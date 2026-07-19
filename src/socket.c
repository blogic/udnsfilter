/*
 * socket.c - UDP socket management for udnsfilter
 *
 * This file handles UDP socket creation, binding, and I/O for DNS queries.
 * It manages both IPv4 and IPv6 sockets and integrates with uloop for
 * event-driven packet reception.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"

/**
 * udns_sockaddr_build() - Build a bind address from string form
 * @addr: Address string
 * @port: Port number
 * @family: AF_INET or AF_INET6
 * @ss: Storage to fill
 * @addrlen: Resulting address length
 *
 * Return: 0 on success, -1 on invalid address
 */
int udns_sockaddr_build(const char *addr, int port, int family,
                        struct sockaddr_storage *ss, socklen_t *addrlen)
{
	memset(ss, 0, sizeof(*ss));

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;

		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		if (inet_pton(AF_INET, addr, &sin->sin_addr) <= 0)
			return -1;
		*addrlen = sizeof(*sin);
		return 0;
	}

	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(port);
	if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) <= 0)
		return -1;
	*addrlen = sizeof(*sin6);
	return 0;
}

/**
 * udns_socket_for_client() - Get appropriate socket for client address family
 * @client_addr: Client address
 *
 * Return: Pointer to IPv4 or IPv6 socket based on client address family
 */
struct udns_socket *udns_socket_for_client(struct sockaddr_storage *client_addr)
{
	if (((struct sockaddr *)client_addr)->sa_family == AF_INET)
		return &global_ctx.sock4;
	else
		return &global_ctx.sock6;
}

static void rcode_reply_send(struct udns_socket *sock, const uint8_t *query,
                             struct sockaddr_storage *from, socklen_t from_len,
                             int rcode)
{
	uint16_t query_id = (query[0] << 8) | query[1];
	struct dns_packet response;

	if (packet_build_rcode(&response, query_id, rcode) < 0)
		return;

	udns_socket_send(sock, response.data, response.len,
	                 (struct sockaddr *)from, from_len);
	free(response.data);
}

/**
 * socket_recv_cb() - Handle incoming DNS queries
 * @ufd: uloop file descriptor
 * @events: Event mask
 *
 * Receives DNS queries from clients, validates them, and invokes the
 * query callback. Invalid traffic is dropped or answered with an error
 * rcode according to the packet_precheck() verdict.
 */
static void socket_recv_cb(struct uloop_fd *ufd, unsigned int events)
{
	struct udns_socket *sock = container_of(ufd, struct udns_socket, ufd);
	uint8_t buffer[DNS_MAX_QUERY_SIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	ssize_t len;
	struct dns_packet pkt;

	if (!(events & ULOOP_READ))
		return;

	len = recvfrom(sock->fd, buffer, sizeof(buffer), MSG_TRUNC,
	               (struct sockaddr *)&from, &from_len);
	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			udns_set_error("recvfrom failed: %s", strerror(errno));
		return;
	}

	if (len == 0)
		return;

	global_ctx.stats.total_queries++;

	/* MSG_TRUNC reports the real datagram size for oversized packets */
	if ((size_t)len > sizeof(buffer)) {
		global_ctx.stats.malformed_queries++;
		return;
	}

	if (!ratelimit_allow(&from)) {
		global_ctx.stats.rate_limited++;
		return;
	}

	switch (packet_precheck(buffer, len)) {
	case QUERY_VERDICT_DROP:
		global_ctx.stats.malformed_queries++;
		return;
	case QUERY_VERDICT_FORMERR:
		global_ctx.stats.malformed_queries++;
		rcode_reply_send(sock, buffer, &from, from_len, DNS_RCODE_FORMERR);
		return;
	case QUERY_VERDICT_NOTIMP:
		global_ctx.stats.refused_queries++;
		rcode_reply_send(sock, buffer, &from, from_len, DNS_RCODE_NOTIMP);
		return;
	case QUERY_VERDICT_OK:
		break;
	}

	if (packet_parse(&pkt, buffer, len) < 0) {
		global_ctx.stats.malformed_queries++;
		rcode_reply_send(sock, buffer, &from, from_len, DNS_RCODE_FORMERR);
		return;
	}

	/* Invoke ucode callback with query */
	udns_callback_query(&pkt, &from, from_len, buffer, len, 0);

	free(pkt.data);
}

/**
 * create_socket() - Create and bind a UDP socket
 * @sock: Socket structure to initialise
 * @addr: Address to bind to
 * @port: Port number
 * @family: Address family (AF_INET or AF_INET6)
 *
 * Creates a UDP socket, sets socket options, binds to the specified
 * address and port, and registers with uloop for event notification.
 *
 * Return: 0 on success, -1 on error
 */
static int create_socket(struct udns_socket *sock, const char *addr, int port, int family)
{
	int fd, val;
	socklen_t addrlen;

	if (sock->fd >= 0) {
		udns_set_error("Socket already created");
		return -1;
	}

	fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd < 0) {
		udns_set_error("Failed to create socket: %s", strerror(errno));
		return -1;
	}

	val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		udns_set_error("SO_REUSEADDR failed: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (family == AF_INET6) {
		val = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0) {
			udns_set_error("IPV6_V6ONLY failed: %s", strerror(errno));
			close(fd);
			return -1;
		}
	}

	if (udns_sockaddr_build(addr, port, family, &sock->bind_addr.ss, &addrlen) < 0) {
		udns_set_error("Invalid address: %s", addr);
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&sock->bind_addr, addrlen) < 0) {
		udns_set_error("bind failed on %s:%d: %s", addr, port, strerror(errno));
		close(fd);
		return -1;
	}

	sock->fd = fd;
	sock->family = family;
	sock->ufd.fd = fd;
	sock->ufd.cb = socket_recv_cb;

	uloop_fd_add(&sock->ufd, ULOOP_READ);

	return 0;
}

/**
 * udns_socket_create() - Create IPv4 and IPv6 DNS sockets
 * @addr: IPv4 address to bind to
 * @addr6: IPv6 address to bind to (NULL for the wildcard address)
 * @port: Port number
 *
 * Creates both IPv4 and IPv6 UDP sockets for receiving DNS queries.
 *
 * Return: 0 if at least one socket succeeds, -1 if both fail
 */
int udns_socket_create(const char *addr, const char *addr6, int port)
{
	int ret4 = -1, ret6 = -1;

	if (!addr6)
		addr6 = "::";

	ret4 = create_socket(&global_ctx.sock4, addr, port, AF_INET);
	ret6 = create_socket(&global_ctx.sock6, addr6, port, AF_INET6);

	if (ret4 < 0 && ret6 < 0) {
		udns_set_error("Failed to create any sockets");
		return -1;
	}

	return 0;
}

/**
 * udns_socket_close() - Close a DNS socket
 * @sock: Socket to close
 *
 * Closes the socket and removes it from uloop.
 */
void udns_socket_close(struct udns_socket *sock)
{
	if (!sock || sock->fd < 0)
		return;

	uloop_fd_delete(&sock->ufd);
	close(sock->fd);
	sock->fd = -1;
}

/**
 * udns_socket_send() - Send DNS packet to client
 * @sock: Socket to send from
 * @data: Packet data
 * @len: Data length
 * @dest: Destination address
 * @dest_len: Address length
 *
 * Return: 0 on success, -1 on error
 */
int udns_socket_send(struct udns_socket *sock, const uint8_t *data, size_t len,
                     struct sockaddr *dest, socklen_t dest_len)
{
	ssize_t ret;

	if (!sock || sock->fd < 0) {
		udns_set_error("Invalid socket");
		return -1;
	}

	ret = sendto(sock->fd, data, len, 0, dest, dest_len);
	if (ret < 0) {
		udns_set_error("sendto failed: %s", strerror(errno));
		return -1;
	}

	if ((size_t)ret != len) {
		udns_set_error("Partial send: %zd of %zu bytes", ret, len);
		return -1;
	}

	return 0;
}
