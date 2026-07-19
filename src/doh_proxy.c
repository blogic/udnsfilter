/*
 * doh_proxy.c - DNS-to-DoH proxy using libcurl
 *
 * This file implements a standalone DNS-to-DoH (DNS-over-HTTPS) proxy.
 * It listens on a local UDP port for standard DNS queries and forwards
 * them as HTTPS requests to a DoH endpoint using libcurl's multi
 * interface integrated with uloop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <libubox/uloop.h>

#include "doh_proxy.h"

#define DOH_MAX_PACKET_SIZE 4096
#define DOH_MAX_RESPONSE_SIZE 65535
#define DOH_MAX_PENDING_REQUESTS 1024
#define DNS_HEADER_SIZE 12

struct pending_request {
	struct doh_proxy_ctx *ctx;
	CURL *easy_handle;
	struct curl_slist *headers;
	struct sockaddr_storage client_addr;
	socklen_t client_addrlen;
	uint8_t query_data[DOH_MAX_PACKET_SIZE];
	size_t query_len;
	uint8_t *response_data;
	size_t response_len;
	size_t response_capacity;
	struct pending_request *next;
};

/**
 * doh_write_callback() - libcurl write callback for DoH responses
 * @ptr: Response data
 * @size: Size of each element
 * @nmemb: Number of elements
 * @userdata: Pending request structure
 *
 * Accumulates HTTP response data (DNS packet) from DoH endpoint.
 *
 * Return: Number of bytes processed
 */
static size_t doh_write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct pending_request *req = userdata;

	if (nmemb > 0 && size > SIZE_MAX / nmemb)
		return 0;

	size_t total_size = size * nmemb;
	size_t new_size = req->response_len + total_size;

	/* Returning a short count aborts the transfer with a write error */
	if (new_size > DOH_MAX_RESPONSE_SIZE)
		return 0;

	if (new_size > req->response_capacity) {
		size_t new_capacity;

		if (req->response_capacity > SIZE_MAX / 2) {
			new_capacity = new_size;
		} else {
			new_capacity = req->response_capacity * 2;
			if (new_capacity < new_size)
				new_capacity = new_size;
		}

		uint8_t *new_buf = realloc(req->response_data, new_capacity);
		if (!new_buf)
			return 0;

		req->response_data = new_buf;
		req->response_capacity = new_capacity;
	}

	memcpy(req->response_data + req->response_len, ptr, total_size);
	req->response_len += total_size;

	return total_size;
}

/**
 * pending_request_free() - Free pending request and resources
 * @req: Request to free
 */
static void pending_request_free(struct pending_request *req)
{
	if (!req)
		return;

	if (req->easy_handle) {
		curl_multi_remove_handle(req->ctx->multi_handle, req->easy_handle);
		curl_easy_cleanup(req->easy_handle);
	}

	if (req->headers)
		curl_slist_free_all(req->headers);

	free(req->response_data);
	free(req);
}

/**
 * pending_request_remove() - Remove request from pending list
 * @ctx: Proxy context
 * @req: Request to remove
 */
static void pending_request_remove(struct doh_proxy_ctx *ctx, struct pending_request *req)
{
	struct pending_request **ptr = &ctx->pending_requests;

	while (*ptr) {
		if (*ptr == req) {
			*ptr = req->next;
			break;
		}
		ptr = &(*ptr)->next;
	}
}

/**
 * doh_response_valid() - Validate a completed DoH exchange
 * @easy: Completed curl easy handle
 * @req: Pending request holding the accumulated body
 *
 * A transport-level success may still carry an HTTP error page; only a
 * 200 response with the DoH media type and a plausible DNS message
 * length may be forwarded to the client.
 *
 * Return: true if the body is a DNS response, false otherwise
 */
static bool doh_response_valid(CURL *easy, struct pending_request *req)
{
	long http_status = 0;
	char *content_type = NULL;

	if (req->response_len < DNS_HEADER_SIZE)
		return false;

	curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_status);
	if (http_status != 200)
		return false;

	curl_easy_getinfo(easy, CURLINFO_CONTENT_TYPE, &content_type);
	if (!content_type ||
	    strncasecmp(content_type, "application/dns-message", 23) != 0)
		return false;

	return true;
}

/**
 * check_multi_info() - Process completed curl transfers
 * @ctx: Proxy context
 *
 * Checks for completed HTTP requests and sends DNS responses to clients.
 */
static void check_multi_info(struct doh_proxy_ctx *ctx)
{
	CURLMsg *msg;
	int msgs_left;
	struct pending_request *req;

	/* Process all completed transfers */
	while ((msg = curl_multi_info_read(ctx->multi_handle, &msgs_left))) {
		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Get request context from curl handle */
		curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (char **)&req);
		if (!req)
			continue;

		if (msg->data.result == CURLE_OK &&
		    doh_response_valid(msg->easy_handle, req)) {
			sendto(ctx->listen_fd, req->response_data, req->response_len, 0,
			       (struct sockaddr *)&req->client_addr, req->client_addrlen);
		}

		pending_request_remove(ctx, req);
		pending_request_free(req);
		ctx->pending_request_count--;
	}
}

static struct doh_proxy_ctx *global_proxy_ctx = NULL;

static void curl_timer_cb(struct uloop_timeout *timeout)
{
	int running_handles;

	if (!global_proxy_ctx)
		return;

	curl_multi_socket_action(global_proxy_ctx->multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
	check_multi_info(global_proxy_ctx);
}

static struct uloop_timeout curl_timeout = {
	.cb = curl_timer_cb
};

static void curl_socket_cb(struct uloop_fd *ufd, unsigned int events)
{
	int running_handles;
	int ev_bitmask = 0;

	if (!global_proxy_ctx)
		return;

	if (events & ULOOP_READ)
		ev_bitmask |= CURL_CSELECT_IN;
	if (events & ULOOP_WRITE)
		ev_bitmask |= CURL_CSELECT_OUT;

	curl_multi_socket_action(global_proxy_ctx->multi_handle, ufd->fd, ev_bitmask, &running_handles);
	check_multi_info(global_proxy_ctx);
}

static int curl_socket_function(CURL *easy, curl_socket_t s, int what, void *userp, void *socketp)
{
	struct doh_proxy_ctx *ctx = userp;
	struct uloop_fd *ufd = socketp;

	if (what == CURL_POLL_REMOVE) {
		if (ufd) {
			uloop_fd_delete(ufd);
			free(ufd);
		}
		curl_multi_assign(ctx->multi_handle, s, NULL);
		return 0;
	}

	if (!ufd) {
		ufd = calloc(1, sizeof(*ufd));
		if (!ufd)
			return -1;

		ufd->fd = s;
		ufd->cb = curl_socket_cb;
		curl_multi_assign(ctx->multi_handle, s, ufd);
	}

	unsigned int events = 0;
	if (what & CURL_POLL_IN)
		events |= ULOOP_READ;
	if (what & CURL_POLL_OUT)
		events |= ULOOP_WRITE;

	if (ufd->registered)
		uloop_fd_delete(ufd);

	if (events)
		uloop_fd_add(ufd, events);

	return 0;
}

static int curl_timer_function(CURLM *multi, long timeout_ms, void *userp)
{
	if (timeout_ms < 0) {
		uloop_timeout_cancel(&curl_timeout);
	} else {
		if (timeout_ms == 0)
			timeout_ms = 1;
		uloop_timeout_set(&curl_timeout, timeout_ms);
	}

	return 0;
}

/**
 * doh_forward_query() - Forward DNS query as DoH request
 * @ctx: Proxy context
 * @query_data: DNS query packet
 * @query_len: Query length
 * @client_addr: Client address for response
 * @client_addrlen: Address length
 *
 * Creates an HTTP POST request to the DoH endpoint with the DNS query.
 *
 * Return: 0 on success, -1 on error
 */
static int doh_forward_query(struct doh_proxy_ctx *ctx, const uint8_t *query_data,
                             size_t query_len, struct sockaddr_storage *client_addr,
                             socklen_t client_addrlen)
{
	struct pending_request *req;
	CURL *easy;

	if (ctx->pending_request_count >= DOH_MAX_PENDING_REQUESTS)
		return -1;

	if (query_len > DOH_MAX_PACKET_SIZE)
		return -1;

	req = calloc(1, sizeof(*req));
	if (!req)
		return -1;

	req->ctx = ctx;
	memcpy(&req->client_addr, client_addr, client_addrlen);
	req->client_addrlen = client_addrlen;
	memcpy(req->query_data, query_data, query_len);
	req->query_len = query_len;
	req->response_capacity = DOH_MAX_PACKET_SIZE;
	req->response_data = malloc(req->response_capacity);
	if (!req->response_data) {
		free(req);
		return -1;
	}

	easy = curl_easy_init();
	if (!easy) {
		free(req->response_data);
		free(req);
		return -1;
	}

	req->easy_handle = easy;

	curl_easy_setopt(easy, CURLOPT_URL, ctx->doh_url);
	curl_easy_setopt(easy, CURLOPT_POST, 1L);
	curl_easy_setopt(easy, CURLOPT_POSTFIELDS, req->query_data);
	curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)req->query_len);
	curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, doh_write_callback);
	curl_easy_setopt(easy, CURLOPT_WRITEDATA, req);
	curl_easy_setopt(easy, CURLOPT_PRIVATE, req);
	curl_easy_setopt(easy, CURLOPT_TIMEOUT, 5L);
	curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(easy, CURLOPT_CAPATH, "/etc/ssl/certs");

	if (ctx->resolve_list)
		curl_easy_setopt(easy, CURLOPT_RESOLVE, ctx->resolve_list);

	req->headers = curl_slist_append(NULL, "Content-Type: application/dns-message");
	req->headers = curl_slist_append(req->headers, "Accept: application/dns-message");
	curl_easy_setopt(easy, CURLOPT_HTTPHEADER, req->headers);

	CURLMcode mres = curl_multi_add_handle(ctx->multi_handle, easy);
	if (mres != CURLM_OK) {
		pending_request_free(req);
		return -1;
	}

	req->next = ctx->pending_requests;
	ctx->pending_requests = req;
	ctx->pending_request_count++;

	return 0;
}

static void udp_socket_cb(struct uloop_fd *ufd, unsigned int events)
{
	struct doh_proxy_ctx *ctx = container_of(ufd, struct doh_proxy_ctx, ufd);
	uint8_t buf[DOH_MAX_PACKET_SIZE];
	struct sockaddr_storage client_addr;
	socklen_t client_addrlen = sizeof(client_addr);
	ssize_t len;

	len = recvfrom(ctx->listen_fd, buf, sizeof(buf), 0,
	               (struct sockaddr *)&client_addr, &client_addrlen);
	if (len < 0)
		return;

	doh_forward_query(ctx, buf, len, &client_addr, client_addrlen);
}

/**
 * resolve_list_build() - Build a CURLOPT_RESOLVE entry for the DoH host
 * @doh_url: DoH endpoint URL
 * @bootstrap: IP address to pin the URL host to
 *
 * Pins the DoH hostname to the given bootstrap address so curl never
 * consults the system resolver, which may loop back into this filter
 * or block the event loop.
 *
 * Return: slist with one host:port:address entry, or NULL on error
 */
static struct curl_slist *resolve_list_build(const char *doh_url, const char *bootstrap)
{
	struct curl_slist *list = NULL;
	CURLU *url = curl_url();
	char *host = NULL, *port = NULL;
	char entry[512];
	int ret;

	if (!url)
		return NULL;

	if (curl_url_set(url, CURLUPART_URL, doh_url, 0) != CURLUE_OK ||
	    curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
	    curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) != CURLUE_OK)
		goto out;

	ret = snprintf(entry, sizeof(entry), "%s:%s:%s", host, port, bootstrap);
	if (ret > 0 && (size_t)ret < sizeof(entry))
		list = curl_slist_append(NULL, entry);

out:
	curl_free(host);
	curl_free(port);
	curl_url_cleanup(url);

	return list;
}

/**
 * doh_proxy_init() - Initialise DoH proxy
 * @ctx: Proxy context to initialise
 * @listen_addr: Local address to listen on
 * @port: Local port number
 * @doh_url: DoH endpoint URL
 * @bootstrap: Optional IP address the URL hostname resolves to
 *
 * Creates UDP socket, initialises libcurl multi interface, and integrates
 * with uloop.
 *
 * Return: 0 on success, -1 on error
 */
int doh_proxy_init(struct doh_proxy_ctx *ctx, const char *listen_addr, int port,
                   const char *doh_url, const char *bootstrap)
{
	int ret;
	int opt = 1;

	if (!ctx || !listen_addr || !doh_url)
		return -1;

	memset(ctx, 0, sizeof(*ctx));

	ctx->doh_url = strdup(doh_url);
	if (!ctx->doh_url)
		return -1;

	if (bootstrap) {
		ctx->resolve_list = resolve_list_build(doh_url, bootstrap);
		if (!ctx->resolve_list) {
			fprintf(stderr, "Invalid bootstrap setup for %s\n", doh_url);
			goto err;
		}
	}

	ctx->port = port;

	ctx->listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctx->listen_fd < 0)
		goto err;

	setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&ctx->bind_addr, 0, sizeof(ctx->bind_addr));
	ctx->bind_addr.sin_family = AF_INET;
	ctx->bind_addr.sin_port = htons(port);

	ret = inet_pton(AF_INET, listen_addr, &ctx->bind_addr.sin_addr);
	if (ret <= 0)
		goto err_close;

	ret = bind(ctx->listen_fd, (struct sockaddr *)&ctx->bind_addr, sizeof(ctx->bind_addr));
	if (ret < 0)
		goto err_close;

	ctx->multi_handle = curl_multi_init();
	if (!ctx->multi_handle)
		goto err_close;

	curl_multi_setopt(ctx->multi_handle, CURLMOPT_SOCKETFUNCTION, curl_socket_function);
	curl_multi_setopt(ctx->multi_handle, CURLMOPT_SOCKETDATA, ctx);
	curl_multi_setopt(ctx->multi_handle, CURLMOPT_TIMERFUNCTION, curl_timer_function);
	curl_multi_setopt(ctx->multi_handle, CURLMOPT_TIMERDATA, ctx);

	ctx->ufd.fd = ctx->listen_fd;
	ctx->ufd.cb = udp_socket_cb;
	uloop_fd_add(&ctx->ufd, ULOOP_READ);

	global_proxy_ctx = ctx;

	if (privilege_drop(NULL, NULL) < 0)
		fprintf(stderr, "Warning: Failed to drop privileges\n");

	return 0;

err_close:
	close(ctx->listen_fd);
err:
	curl_slist_free_all(ctx->resolve_list);
	free(ctx->doh_url);
	return -1;
}

/**
 * doh_proxy_cleanup() - Clean up DoH proxy resources
 * @ctx: Proxy context
 */
void doh_proxy_cleanup(struct doh_proxy_ctx *ctx)
{
	struct pending_request *req, *tmp;

	if (!ctx)
		return;

	global_proxy_ctx = NULL;

	for (req = ctx->pending_requests; req; req = tmp) {
		tmp = req->next;
		pending_request_free(req);
	}
	ctx->pending_requests = NULL;
	ctx->pending_request_count = 0;

	if (ctx->multi_handle)
		curl_multi_cleanup(ctx->multi_handle);

	if (ctx->listen_fd >= 0) {
		uloop_fd_delete(&ctx->ufd);
		close(ctx->listen_fd);
	}

	curl_slist_free_all(ctx->resolve_list);
	free(ctx->doh_url);
	memset(ctx, 0, sizeof(*ctx));
}

static struct doh_proxy_ctx proxy_ctx;

static void print_usage(const char *prog)
{
	printf("Usage: %s <listen_addr> <port> <doh_url> [bootstrap_ip]\n", prog);
	printf("\n");
	printf("Example:\n");
	printf("  %s 127.0.0.1 5301 https://1.1.1.1/dns-query\n", prog);
	printf("  %s 127.0.0.1 5301 https://dns.google/dns-query 8.8.8.8\n", prog);
}

int main(int argc, char **argv)
{
	const char *listen_addr;
	int port;
	const char *doh_url;
	const char *bootstrap = NULL;

	if (argc < 4 || argc > 5) {
		print_usage(argv[0]);
		return 1;
	}

	listen_addr = argv[1];
	doh_url = argv[3];
	if (argc == 5)
		bootstrap = argv[4];

	char *endptr;
	long port_long = strtol(argv[2], &endptr, 10);
	if (*endptr != '\0' || port_long <= 0 || port_long > 65535) {
		fprintf(stderr, "Invalid port: %s\n", argv[2]);
		return 1;
	}
	port = (int)port_long;

	curl_global_init(CURL_GLOBAL_ALL);

	/* uloop_init() installs SIGINT/SIGTERM handlers that cancel the loop */
	uloop_init();

	printf("Starting DNS-to-DoH proxy...\n");
	printf("Listening on %s:%d\n", listen_addr, port);
	printf("DoH endpoint: %s\n", doh_url);
	if (bootstrap)
		printf("Bootstrap: %s\n", bootstrap);

	if (doh_proxy_init(&proxy_ctx, listen_addr, port, doh_url, bootstrap) < 0) {
		fprintf(stderr, "Failed to initialise proxy\n");
		uloop_done();
		curl_global_cleanup();
		return 1;
	}

	printf("Proxy ready\n");

	uloop_run();

	printf("\nShutting down...\n");
	doh_proxy_cleanup(&proxy_ctx);
	uloop_done();
	curl_global_cleanup();

	return 0;
}
