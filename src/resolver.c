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
	char *domain;
};

struct resolver_fd {
	struct uloop_fd ufd;
	struct resolver_fd *next;
};

static struct server_state *server_states = NULL;

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

	memset(&opts, 0, sizeof(opts));
	opts.flags = ARES_FLAG_NOCHECKRESP;
	opts.timeout = 2000;
	opts.tries = 2;
	opts.sock_state_cb = sock_state_cb;
	opts.sock_state_cb_data = ctx;
	opts.qcache_max_ttl = cache_ttl;
	optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES |
	          ARES_OPT_SOCK_STATE_CB | ARES_OPT_QUERY_CACHE;

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

/**
 * ares_dnsrec_callback() - Handle DNS response from upstream
 * @arg: Query callback data
 * @status: c-ares status code
 * @timeouts: Number of timeouts
 * @dnsrec: Parsed DNS record
 *
 * Processes upstream DNS responses, applies DNS rebinding protection,
 * and forwards valid responses to clients.
 */
static void ares_dnsrec_callback(void *arg, ares_status_t status, size_t timeouts,
                                 const ares_dns_record_t *dnsrec)
{
	struct query_callback_data *data = arg;
	uint8_t *response_buf = NULL;
	size_t response_len = 0;

	if (status == ARES_SUCCESS && dnsrec) {
		/* Convert c-ares DNS record to wire format */
		ares_dns_write(dnsrec, &response_buf, &response_len);

		if (response_buf && response_len >= 2) {
			/* DNS rebinding protection: block private IPs */
			if (dns_response_contains_private_ip(response_buf, response_len)) {
				fprintf(stderr, "Blocked DNS rebinding attempt for domain %s\n",
				        data->domain ? data->domain : "unknown");
				global_ctx.stats.blocked_queries++;
			} else {
				/* Restore original query ID */
				uint16_t id_net = htons(data->original_id);
				memcpy(response_buf, &id_net, 2);

				/* Send response to client */
				udns_socket_send(data->sock, response_buf, response_len,
				                (struct sockaddr *)&data->client_addr, data->client_addrlen);

				global_ctx.stats.forwarded_queries++;
			}
		}

		ares_free_string(response_buf);
	} else {
		global_ctx.stats.upstream_errors++;
	}

	free(data->domain);
	free(data);
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
 *
 * Return: 0 on success, -1 on error
 */
int resolver_forward_query(struct resolver_ctx *ctx, struct udns_socket *sock,
                           const uint8_t *query_data, size_t query_len,
                           struct sockaddr_storage *client_addr, socklen_t client_addrlen,
                           const char *domain)
{
	struct query_callback_data *data;
	struct dns_packet pkt;
	ares_dns_record_t *dnsrec = NULL;
	ares_status_t status;
	unsigned short qid;

	if (packet_parse(&pkt, query_data, query_len) < 0)
		return -1;

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
	data->domain = strdup(domain);
	if (!data->domain) {
		ares_dns_record_destroy(dnsrec);
		free(pkt.data);
		free(data);
		return -1;
	}

	status = ares_send_dnsrec(ctx->channel, dnsrec, ares_dnsrec_callback, data, &qid);

	ares_dns_record_destroy(dnsrec);
	free(pkt.data);

	if (status != ARES_SUCCESS) {
		udns_set_error("ares_send_dnsrec failed: %s", ares_strerror(status));
		free(data->domain);
		free(data);
		return -1;
	}

	resolver_timeout_schedule(ctx);

	return 0;
}
