/*
 * resolver.c - c-ares integration for upstream DNS resolution
 *
 * This file integrates the c-ares asynchronous DNS resolver library,
 * providing upstream DNS forwarding with server health tracking, query
 * caching, and DNS rebinding protection (blocking private IP addresses
 * in responses).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "internal.h"

struct query_callback_data {
	struct udns_socket *sock;
	struct sockaddr_storage client_addr;
	socklen_t client_addrlen;
	uint16_t original_id;
	uint16_t max_udp_size;
	uint32_t tcp_conn_id;
	char *domain;
	uint8_t *query_data;
	size_t query_len;
};

struct resolver_fd {
	struct uloop_fd ufd;
	struct resolver_fd *next;
};

static struct server_state *server_states = NULL;
static unsigned int pending_count;

struct rebind_domain {
	char *domain;
	struct rebind_domain *next;
};

static bool rebind_protection_enabled = true;
static struct rebind_domain *rebind_domains;

void rebind_config_set(bool enable)
{
	rebind_protection_enabled = enable;
}

int rebind_domain_add(const char *domain)
{
	struct rebind_domain *entry;

	if (!domain || !*domain)
		return -1;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return -1;

	entry->domain = strdup(domain);
	if (!entry->domain) {
		free(entry);
		return -1;
	}

	entry->next = rebind_domains;
	rebind_domains = entry;

	return 0;
}

void rebind_domains_clear(void)
{
	struct rebind_domain *entry, *tmp;

	for (entry = rebind_domains; entry; entry = tmp) {
		tmp = entry->next;
		free(entry->domain);
		free(entry);
	}

	rebind_domains = NULL;
}

static bool rebind_domain_allowed(const char *domain)
{
	struct rebind_domain *entry;

	if (!domain)
		return false;

	for (entry = rebind_domains; entry; entry = entry->next) {
		if (domain_match_subdomain(domain, entry->domain))
			return true;
	}

	return false;
}

/**
 * server_state_find_or_create() - Find or create server state entry
 * @addr: Server address string
 *
 * Return: Pointer to server_state, or NULL on allocation failure
 */
static struct server_state *server_state_find_or_create(const char *addr)
{
	struct server_state *state;

	for (state = server_states; state; state = state->next) {
		if (strcmp(state->address, addr) == 0)
			return state;
	}

	state = calloc(1, sizeof(*state));
	if (!state)
		return NULL;

	snprintf(state->address, sizeof(state->address), "%s", addr);
	state->healthy = true;
	state->consecutive_failures = 0;
	state->next = server_states;
	server_states = state;

	return state;
}

/**
 * server_state_cb() - Track upstream server health
 * @server_string: Server address
 * @server_success: Whether query succeeded
 * @flags: c-ares flags (unused)
 * @data: User data (unused)
 *
 * Callback from c-ares to track server health. Marks servers as degraded
 * after 3 consecutive failures.
 */
static void server_state_cb(const char *server_string, ares_bool_t server_success,
                            int flags __attribute__((unused)),
                            void *data __attribute__((unused)))
{
	struct server_state *state;

	state = server_state_find_or_create(server_string);
	if (!state)
		return;

	if (server_success) {
		state->consecutive_failures = 0;
		state->healthy = true;
	} else {
		state->consecutive_failures++;
		if (state->consecutive_failures >= 3)
			state->healthy = false;
	}
}

static void ares_fd_cb(struct uloop_fd *ufd, unsigned int events);

/**
 * resolver_timeout_schedule() - Arm the uloop timer for c-ares timeouts
 * @ctx: Resolver context
 *
 * c-ares only enforces retries and query timeouts inside
 * ares_process_fd(), so a timer must fire when the earliest pending
 * timeout is due; fd events alone stall when an upstream stays silent.
 */
static void resolver_timeout_schedule(struct resolver_ctx *ctx)
{
	struct timeval tv;

	if (!ares_timeout(ctx->channel, NULL, &tv)) {
		uloop_timeout_cancel(&ctx->timeout);
		return;
	}

	uloop_timeout_set(&ctx->timeout, tv.tv_sec * 1000 + tv.tv_usec / 1000 + 1);
}

static void resolver_timeout_cb(struct uloop_timeout *timeout)
{
	struct resolver_ctx *ctx = container_of(timeout, struct resolver_ctx, timeout);

	ares_process_fd(ctx->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
	resolver_timeout_schedule(ctx);
}

/**
 * sock_state_cb() - Manage c-ares socket events in uloop
 * @data: Resolver context
 * @socket_fd: Socket file descriptor
 * @readable: Whether socket should be monitored for read
 * @writable: Whether socket should be monitored for write
 *
 * Callback from c-ares to register/unregister sockets with uloop.
 */
static void sock_state_cb(void *data, ares_socket_t socket_fd, int readable, int writable)
{
	struct resolver_ctx *ctx = data;
	struct resolver_fd *rfd, **prev;

	for (prev = &ctx->fds; (rfd = *prev) != NULL; prev = &rfd->next) {
		if (rfd->ufd.fd == socket_fd)
			break;
	}

	if (!readable && !writable) {
		if (!rfd)
			return;
		uloop_fd_delete(&rfd->ufd);
		*prev = rfd->next;
		free(rfd);
		return;
	}

	if (!rfd) {
		rfd = calloc(1, sizeof(*rfd));
		if (!rfd)
			return;
		rfd->ufd.fd = socket_fd;
		rfd->ufd.cb = ares_fd_cb;
		rfd->next = ctx->fds;
		ctx->fds = rfd;
	}

	unsigned int events = 0;
	if (readable)
		events |= ULOOP_READ;
	if (writable)
		events |= ULOOP_WRITE;

	if (rfd->ufd.registered)
		uloop_fd_delete(&rfd->ufd);
	uloop_fd_add(&rfd->ufd, events);
}

/**
 * resolver_init() - Initialise the c-ares resolver
 * @ctx: Resolver context
 * @rotation: Enable server rotation
 * @cache_ttl: Query cache TTL in seconds
 *
 * Return: 0 on success, -1 on error
 */
int resolver_init(struct resolver_ctx *ctx, bool rotation, unsigned int cache_ttl)
{
	struct ares_options opts;
	int optmask = 0;
	int status;

	if (!ctx)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	pending_count = 0;

	memset(&opts, 0, sizeof(opts));
	opts.flags = ARES_FLAG_NOCHECKRESP;
	if (udns_security.dns0x20)
		opts.flags |= ARES_FLAG_DNS0x20;
	opts.timeout = 2000;
	opts.tries = 2;
	opts.sock_state_cb = sock_state_cb;
	opts.sock_state_cb_data = ctx;
	opts.qcache_max_ttl = cache_ttl;
	/* Rotate the UDP source socket, and thus the source port, so a blind
	 * off-path spoofer cannot pin one port for the channel's lifetime. */
	opts.udp_max_queries = 128;
	optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES |
	          ARES_OPT_SOCK_STATE_CB | ARES_OPT_QUERY_CACHE |
	          ARES_OPT_UDP_MAX_QUERIES;

	if (rotation)
		optmask |= ARES_OPT_ROTATE;
	else
		optmask |= ARES_OPT_NOROTATE;

	status = ares_init_options(&ctx->channel, &opts, optmask);
	if (status != ARES_SUCCESS) {
		udns_set_error("ares_init failed: %s", ares_strerror(status));
		return -1;
	}

	ares_set_server_state_callback(ctx->channel, server_state_cb, ctx);

	ctx->rotation_enabled = rotation;
	ctx->cache_ttl = cache_ttl;
	ctx->timeout.cb = resolver_timeout_cb;

	return 0;
}

/**
 * resolver_cleanup() - Clean up resolver resources
 * @ctx: Resolver context
 */
void resolver_cleanup(struct resolver_ctx *ctx)
{
	struct server_state *state, *state_tmp;
	struct resolver_fd *rfd, *rfd_tmp;

	if (!ctx)
		return;

	uloop_timeout_cancel(&ctx->timeout);

	/* ares_destroy() closes sockets, which unregisters and frees their
	 * resolver_fd entries through sock_state_cb; only leftovers remain. */
	if (ctx->channel)
		ares_destroy(ctx->channel);

	for (rfd = ctx->fds; rfd; rfd = rfd_tmp) {
		rfd_tmp = rfd->next;
		uloop_fd_delete(&rfd->ufd);
		free(rfd);
	}

	for (state = server_states; state; state = state_tmp) {
		state_tmp = state->next;
		free(state);
	}
	server_states = NULL;

	rebind_domains_clear();

	memset(ctx, 0, sizeof(*ctx));
}

/**
 * resolver_set_servers() - Configure upstream DNS servers
 * @ctx: Resolver context
 * @servers: Array of server URI strings
 * @count: Number of servers
 */
void resolver_set_servers(struct resolver_ctx *ctx, const char **servers, int count)
{
	char csv[4096] = {0};
	size_t len = 0;
	int i;

	if (!ctx || !servers || count == 0)
		return;

	for (i = 0; i < count; i++) {
		if (i > 0) {
			if (len >= sizeof(csv) - 1)
				break;
			csv[len++] = ',';
		}

		int ret = snprintf(csv + len, sizeof(csv) - len, "%s", servers[i]);
		if (ret < 0 || (size_t)ret >= sizeof(csv) - len) {
			csv[sizeof(csv) - 1] = '\0';
			break;
		}
		len += ret;
	}

	ares_set_servers_ports_csv(ctx->channel, csv);
}

int resolver_reinit(struct resolver_ctx *ctx)
{
	if (!ctx || !ctx->channel)
		return -1;

	return ares_reinit(ctx->channel);
}

int resolver_get_server_states(struct server_state **states)
{
	int count = 0;
	struct server_state *state;

	*states = server_states;

	for (state = server_states; state; state = state->next)
		count++;

	return count;
}

void resolver_get_config(struct resolver_ctx *ctx, bool *rotation, unsigned int *cache_ttl)
{
	if (!ctx)
		return;

	if (rotation)
		*rotation = ctx->rotation_enabled;
	if (cache_ttl)
		*cache_ttl = ctx->cache_ttl;
}

static void ares_fd_cb(struct uloop_fd *ufd, unsigned int events)
{
	ares_socket_t read_fd = ARES_SOCKET_BAD;
	ares_socket_t write_fd = ARES_SOCKET_BAD;

	if (events & ULOOP_READ)
		read_fd = ufd->fd;
	if (events & ULOOP_WRITE)
		write_fd = ufd->fd;

	ares_process_fd(global_ctx.resolver.channel, read_fd, write_fd);
	resolver_timeout_schedule(&global_ctx.resolver);
}

static void client_response_send(struct query_callback_data *data,
                                 const uint8_t *buf, size_t len)
{
	if (data->tcp_conn_id) {
		udns_tcp_send(data->tcp_conn_id, buf, len);
		return;
	}

	udns_socket_send(data->sock, buf, len,
	                 (struct sockaddr *)&data->client_addr, data->client_addrlen);
}

/**
 * rebind_response_send() - Answer a rebind-blocked query with NXDOMAIN
 * @data: Query callback data holding the original client query
 */
static void rebind_response_send(struct query_callback_data *data)
{
	struct dns_packet query, response;

	fprintf(stderr, "Blocked DNS rebinding attempt for domain %s\n",
	        data->domain ? data->domain : "unknown");
	global_ctx.stats.rebind_blocked++;

	if (packet_parse(&query, data->query_data, data->query_len) < 0)
		return;

	memset(&response, 0, sizeof(response));

	if (packet_build_nxdomain(&response, &query) > 0)
		client_response_send(data, response.data, response.len);

	free(query.data);
	free(response.data);
}

/**
 * truncated_response_send() - Tell a UDP client to retry over TCP
 * @data: Query callback data holding the original client query
 */
static void truncated_response_send(struct query_callback_data *data)
{
	struct dns_packet response;

	if (packet_build_truncated(&response, data->query_data, data->query_len) < 0)
		return;

	client_response_send(data, response.data, response.len);
	free(response.data);
}

/**
 * ares_dnsrec_callback() - Handle DNS response from upstream
 * @arg: Query callback data
 * @status: c-ares status code
 * @timeouts: Number of timeouts
 * @dnsrec: Parsed DNS record
 *
 * Processes upstream DNS responses, applies DNS rebinding protection,
 * and forwards valid responses to clients. The client always receives
 * an answer: SERVFAIL on upstream failure, NXDOMAIN on a rebind block.
 */
static void ares_dnsrec_callback(void *arg, ares_status_t status, size_t timeouts,
                                 const ares_dns_record_t *dnsrec)
{
	struct query_callback_data *data = arg;
	uint8_t *response_buf = NULL;
	size_t response_len = 0;

	if (status == ARES_SUCCESS && dnsrec)
		ares_dns_write(dnsrec, &response_buf, &response_len);

	if (!response_buf || response_len < 2) {
		struct dns_packet response;

		global_ctx.stats.upstream_errors++;

		if (packet_build_rcode(&response, data->original_id, DNS_RCODE_SERVFAIL) == 0) {
			client_response_send(data, response.data, response.len);
			free(response.data);
		}
	} else if (rebind_protection_enabled &&
	           !rebind_domain_allowed(data->domain) &&
	           dns_response_contains_private_ip(response_buf, response_len)) {
		rebind_response_send(data);
	} else if (!data->tcp_conn_id && response_len > data->max_udp_size) {
		truncated_response_send(data);
		global_ctx.stats.forwarded_queries++;
	} else {
		/* Restore original query ID */
		uint16_t id_net = htons(data->original_id);
		memcpy(response_buf, &id_net, 2);

		client_response_send(data, response_buf, response_len);

		global_ctx.stats.forwarded_queries++;
	}

	if (response_buf)
		ares_free_string(response_buf);

	if (pending_count > 0)
		pending_count--;

	free(data->query_data);
	free(data->domain);
	free(data);
}

/**
 * overload_servfail_send() - Answer a query dropped at the pending cap
 * @sock: Socket for a UDP client
 * @client_addr: Client address
 * @client_addrlen: Client address length
 * @tcp_conn_id: TCP connection id, 0 for UDP
 * @query_id: Original query id
 *
 * Sends SERVFAIL directly so an overloaded resolver still answers rather
 * than leaving the client to time out.
 */
static void overload_servfail_send(struct udns_socket *sock,
                                   struct sockaddr_storage *client_addr,
                                   socklen_t client_addrlen,
                                   uint32_t tcp_conn_id, uint16_t query_id)
{
	struct dns_packet response;

	if (packet_build_rcode(&response, query_id, DNS_RCODE_SERVFAIL) < 0)
		return;

	if (tcp_conn_id)
		udns_tcp_send(tcp_conn_id, response.data, response.len);
	else
		udns_socket_send(sock, response.data, response.len,
		                 (struct sockaddr *)client_addr, client_addrlen);

	free(response.data);
}

/**
 * query_udp_size() - Advertised EDNS0 UDP payload size of a query
 * @dnsrec: Parsed query record
 *
 * Return: OPT record UDP size clamped to at least 512, or 512 if the
 *         query carries no OPT record
 */
static unsigned short query_udp_size(const ares_dns_record_t *dnsrec)
{
	size_t cnt = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL);

	for (size_t i = 0; i < cnt; i++) {
		const ares_dns_rr_t *rr =
			ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ADDITIONAL, i);
		unsigned short size;

		if (!rr || ares_dns_rr_get_type(rr) != ARES_REC_TYPE_OPT)
			continue;

		size = ares_dns_rr_get_u16(rr, ARES_RR_OPT_UDP_SIZE);
		return size < DNS_MAX_PACKET_SIZE ? DNS_MAX_PACKET_SIZE : size;
	}

	return DNS_MAX_PACKET_SIZE;
}

/**
 * resolver_forward_query() - Forward DNS query to upstream servers
 * @ctx: Resolver context
 * @sock: Socket for sending response
 * @query_data: Query packet data
 * @query_len: Query length
 * @client_addr: Client address for response
 * @client_addrlen: Client address length
 * @domain: Domain name being queried
 * @tcp_conn_id: TCP connection id, 0 for UDP clients
 *
 * Return: 0 on success, -1 on error
 */
int resolver_forward_query(struct resolver_ctx *ctx, struct udns_socket *sock,
                           const uint8_t *query_data, size_t query_len,
                           struct sockaddr_storage *client_addr, socklen_t client_addrlen,
                           const char *domain, uint32_t tcp_conn_id)
{
	struct query_callback_data *data;
	struct dns_packet pkt;
	ares_dns_record_t *dnsrec = NULL;
	ares_status_t status;
	unsigned short qid;

	if (packet_parse(&pkt, query_data, query_len) < 0)
		return -1;

	if (udns_security.max_pending && pending_count >= udns_security.max_pending) {
		overload_servfail_send(sock, client_addr, client_addrlen,
		                       tcp_conn_id, pkt.id);
		global_ctx.stats.overload_dropped++;
		free(pkt.data);
		return -1;
	}

	status = ares_dns_parse(query_data, query_len, 0, &dnsrec);
	if (status != ARES_SUCCESS) {
		udns_set_error("ares_dns_parse failed: %s", ares_strerror(status));
		free(pkt.data);
		return -1;
	}

	data = calloc(1, sizeof(*data));
	if (!data) {
		ares_dns_record_destroy(dnsrec);
		free(pkt.data);
		return -1;
	}

	data->sock = sock;
	memcpy(&data->client_addr, client_addr, client_addrlen);
	data->client_addrlen = client_addrlen;
	data->original_id = pkt.id;
	data->max_udp_size = query_udp_size(dnsrec);
	data->tcp_conn_id = tcp_conn_id;
	data->domain = strdup(domain);
	if (!data->domain) {
		ares_dns_record_destroy(dnsrec);
		free(pkt.data);
		free(data);
		return -1;
	}

	/* Keep the original query so a rebind block can answer with NXDOMAIN */
	data->query_data = malloc(query_len);
	if (!data->query_data) {
		ares_dns_record_destroy(dnsrec);
		free(pkt.data);
		free(data->domain);
		free(data);
		return -1;
	}
	memcpy(data->query_data, query_data, query_len);
	data->query_len = query_len;

	status = ares_send_dnsrec(ctx->channel, dnsrec, ares_dnsrec_callback, data, &qid);

	ares_dns_record_destroy(dnsrec);
	free(pkt.data);

	if (status != ARES_SUCCESS) {
		udns_set_error("ares_send_dnsrec failed: %s", ares_strerror(status));
		free(data->query_data);
		free(data->domain);
		free(data);
		return -1;
	}

	pending_count++;
	resolver_timeout_schedule(ctx);

	return 0;
}
