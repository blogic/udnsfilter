/*
 * tcp.c - TCP DNS transport (RFC 7766)
 *
 * This file implements the TCP listeners and per-connection framing for
 * DNS over TCP. Messages are two-byte length prefixed. Queries feed the
 * same ucode callback path as UDP; responses are matched back to their
 * connection by id so a connection closed mid-flight is simply dropped.
 */

/* accept4() */
#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal.h"

#define TCP_MAX_CONNS 64
#define TCP_IDLE_TIMEOUT_MS 10000
#define TCP_LISTEN_BACKLOG 16

struct tcp_conn {
	struct uloop_fd ufd;
	struct uloop_timeout idle;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	uint32_t id;
	size_t have;
	uint8_t buf[DNS_MAX_QUERY_SIZE + 2];
	uint8_t *wbuf;
	size_t wlen;
	size_t woff;
	struct tcp_conn *next;
};

static struct uloop_fd tcp4_ufd = { .fd = -1 };
static struct uloop_fd tcp6_ufd = { .fd = -1 };
static struct tcp_conn *conns;
static int conn_count;
static uint32_t conn_id_next = 1;

static struct tcp_conn *conn_find(uint32_t id)
{
	struct tcp_conn *conn;

	for (conn = conns; conn; conn = conn->next) {
		if (conn->id == id)
			return conn;
	}

	return NULL;
}

static bool addr_same_host(const struct sockaddr_storage *a,
                           const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	if (a->ss_family == AF_INET)
		return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
		       ((const struct sockaddr_in *)b)->sin_addr.s_addr;

	return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
	              &((const struct sockaddr_in6 *)b)->sin6_addr,
	              sizeof(struct in6_addr)) == 0;
}

static int conn_host_count(const struct sockaddr_storage *addr)
{
	struct tcp_conn *conn;
	int count = 0;

	for (conn = conns; conn; conn = conn->next) {
		if (addr_same_host(&conn->addr, addr))
			count++;
	}

	return count;
}

static void conn_close(struct tcp_conn *conn)
{
	struct tcp_conn **prev;

	uloop_timeout_cancel(&conn->idle);
	uloop_fd_delete(&conn->ufd);
	close(conn->ufd.fd);

	for (prev = &conns; *prev; prev = &(*prev)->next) {
		if (*prev == conn) {
			*prev = conn->next;
			break;
		}
	}

	conn_count--;
	free(conn->wbuf);
	free(conn);
}

static void conn_idle_cb(struct uloop_timeout *timeout)
{
	conn_close(container_of(timeout, struct tcp_conn, idle));
}

static void conn_events_update(struct tcp_conn *conn)
{
	unsigned int events = ULOOP_READ;

	if (conn->woff < conn->wlen)
		events |= ULOOP_WRITE;

	if (conn->ufd.registered)
		uloop_fd_delete(&conn->ufd);
	uloop_fd_add(&conn->ufd, events);
}

/**
 * conn_flush() - Write out pending response data
 * @conn: Connection
 *
 * Return: false if the connection was closed, true otherwise
 */
static bool conn_flush(struct tcp_conn *conn)
{
	while (conn->woff < conn->wlen) {
		ssize_t n = write(conn->ufd.fd, conn->wbuf + conn->woff,
		                  conn->wlen - conn->woff);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			conn_close(conn);
			return false;
		}

		conn->woff += n;
	}

	if (conn->woff == conn->wlen) {
		free(conn->wbuf);
		conn->wbuf = NULL;
		conn->wlen = 0;
		conn->woff = 0;
	}

	conn_events_update(conn);

	return true;
}

static int conn_write_queue(struct tcp_conn *conn, const uint8_t *data, size_t len)
{
	uint8_t *nbuf = realloc(conn->wbuf, conn->wlen + len);

	if (!nbuf)
		return -1;

	memcpy(nbuf + conn->wlen, data, len);
	conn->wbuf = nbuf;
	conn->wlen += len;

	return 0;
}

/**
 * udns_tcp_send() - Send a length-prefixed DNS message on a connection
 * @conn_id: Connection id captured when the query arrived
 * @data: DNS message
 * @len: Message length
 *
 * The connection is never closed from here; a query callback may still
 * be iterating over it. Hard write errors close it from uloop context.
 *
 * Return: 0 on success, -1 if the connection is gone or queueing failed
 */
int udns_tcp_send(uint32_t conn_id, const uint8_t *data, size_t len)
{
	struct tcp_conn *conn = conn_find(conn_id);
	uint8_t prefix[2];

	if (!conn || len > 65535)
		return -1;

	prefix[0] = len >> 8;
	prefix[1] = len & 0xff;

	if (conn_write_queue(conn, prefix, sizeof(prefix)) < 0 ||
	    conn_write_queue(conn, data, len) < 0)
		return -1;

	conn_events_update(conn);

	return 0;
}

static void conn_rcode_send(struct tcp_conn *conn, const uint8_t *msg, int rcode)
{
	uint16_t query_id = (msg[0] << 8) | msg[1];
	struct dns_packet response;

	if (packet_build_rcode(&response, query_id, rcode) < 0)
		return;

	udns_tcp_send(conn->id, response.data, response.len);
	free(response.data);
}

static void conn_query_dispatch(struct tcp_conn *conn, size_t msg_len)
{
	struct dns_packet pkt;

	if (packet_parse(&pkt, conn->buf + 2, msg_len) < 0) {
		global_ctx.stats.malformed_queries++;
		conn_rcode_send(conn, conn->buf + 2, DNS_RCODE_FORMERR);
		return;
	}

	udns_callback_query(&pkt, &conn->addr, conn->addrlen,
	                    conn->buf + 2, msg_len, conn->id);
	free(pkt.data);
}

/**
 * conn_messages_process() - Parse and dispatch buffered messages
 * @conn: Connection
 *
 * Return: false if the connection was closed, true otherwise
 */
static bool conn_messages_process(struct tcp_conn *conn)
{
	while (conn->have >= 2) {
		size_t msg_len = (conn->buf[0] << 8) | conn->buf[1];

		if (msg_len < sizeof(struct dns_header) || msg_len > DNS_MAX_QUERY_SIZE) {
			conn_close(conn);
			return false;
		}

		if (conn->have < msg_len + 2)
			return true;

		global_ctx.stats.total_queries++;

		if (!ratelimit_allow(&conn->addr)) {
			global_ctx.stats.rate_limited++;
			conn_close(conn);
			return false;
		}

		switch (packet_precheck(conn->buf + 2, msg_len)) {
		case QUERY_VERDICT_DROP:
			global_ctx.stats.malformed_queries++;
			conn_close(conn);
			return false;
		case QUERY_VERDICT_FORMERR:
			global_ctx.stats.malformed_queries++;
			conn_rcode_send(conn, conn->buf + 2, DNS_RCODE_FORMERR);
			break;
		case QUERY_VERDICT_NOTIMP:
			global_ctx.stats.refused_queries++;
			conn_rcode_send(conn, conn->buf + 2, DNS_RCODE_NOTIMP);
			break;
		case QUERY_VERDICT_OK:
			conn_query_dispatch(conn, msg_len);
			break;
		}

		memmove(conn->buf, conn->buf + 2 + msg_len, conn->have - 2 - msg_len);
		conn->have -= 2 + msg_len;
	}

	return true;
}

static void conn_fd_cb(struct uloop_fd *ufd, unsigned int events)
{
	struct tcp_conn *conn = container_of(ufd, struct tcp_conn, ufd);
	ssize_t len;

	if (ufd->eof || ufd->error) {
		conn_close(conn);
		return;
	}

	if ((events & ULOOP_WRITE) && !conn_flush(conn))
		return;

	if (!(events & ULOOP_READ))
		return;

	len = read(conn->ufd.fd, conn->buf + conn->have, sizeof(conn->buf) - conn->have);
	if (len == 0) {
		conn_close(conn);
		return;
	}
	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			conn_close(conn);
		return;
	}

	conn->have += len;
	uloop_timeout_set(&conn->idle, TCP_IDLE_TIMEOUT_MS);

	if (conn_messages_process(conn))
		conn_flush(conn);
}

static void listen_cb(struct uloop_fd *ufd, unsigned int events)
{
	struct tcp_conn *conn;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	int fd;

	fd = accept4(ufd->fd, (struct sockaddr *)&addr, &addrlen,
	             SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0)
		return;

	if (conn_count >= TCP_MAX_CONNS) {
		close(fd);
		return;
	}

	if (udns_security.max_tcp_per_client &&
	    conn_host_count(&addr) >= (int)udns_security.max_tcp_per_client) {
		close(fd);
		return;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		close(fd);
		return;
	}

	memcpy(&conn->addr, &addr, addrlen);
	conn->addrlen = addrlen;
	conn->id = conn_id_next++;
	if (!conn_id_next)
		conn_id_next = 1;
	conn->ufd.fd = fd;
	conn->ufd.cb = conn_fd_cb;
	conn->idle.cb = conn_idle_cb;
	conn->next = conns;
	conns = conn;
	conn_count++;

	uloop_fd_add(&conn->ufd, ULOOP_READ);
	uloop_timeout_set(&conn->idle, TCP_IDLE_TIMEOUT_MS);
}

static int listen_socket_create(const char *addr, int port, int family)
{
	struct sockaddr_storage ss;
	socklen_t addrlen;
	int fd, val;

	fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		udns_set_error("Failed to create TCP socket: %s", strerror(errno));
		return -1;
	}

	val = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	if (family == AF_INET6)
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));

	if (udns_sockaddr_build(addr, port, family, &ss, &addrlen) < 0) {
		udns_set_error("Invalid address: %s", addr);
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&ss, addrlen) < 0 ||
	    listen(fd, TCP_LISTEN_BACKLOG) < 0) {
		udns_set_error("TCP bind/listen failed on %s:%d: %s",
		               addr, port, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

/**
 * udns_tcp_listen() - Create IPv4 and IPv6 TCP DNS listeners
 * @addr: IPv4 address to bind to
 * @addr6: IPv6 address to bind to (NULL for the wildcard address)
 * @port: Port number
 *
 * Return: 0 if at least one listener succeeds, -1 if both fail
 */
int udns_tcp_listen(const char *addr, const char *addr6, int port)
{
	int fd4, fd6;

	if (!addr6)
		addr6 = "::";

	fd4 = listen_socket_create(addr, port, AF_INET);
	fd6 = listen_socket_create(addr6, port, AF_INET6);

	if (fd4 < 0 && fd6 < 0)
		return -1;

	if (fd4 >= 0) {
		tcp4_ufd.fd = fd4;
		tcp4_ufd.cb = listen_cb;
		uloop_fd_add(&tcp4_ufd, ULOOP_READ);
	}

	if (fd6 >= 0) {
		tcp6_ufd.fd = fd6;
		tcp6_ufd.cb = listen_cb;
		uloop_fd_add(&tcp6_ufd, ULOOP_READ);
	}

	return 0;
}

void udns_tcp_close(void)
{
	while (conns)
		conn_close(conns);

	if (tcp4_ufd.fd >= 0) {
		uloop_fd_delete(&tcp4_ufd);
		close(tcp4_ufd.fd);
		tcp4_ufd.fd = -1;
	}

	if (tcp6_ufd.fd >= 0) {
		uloop_fd_delete(&tcp6_ufd);
		close(tcp6_ufd.fd);
		tcp6_ufd.fd = -1;
	}
}
