/*
 * doh_proxy.h - DNS-to-DoH proxy header
 */

#ifndef __DOH_PROXY_H
#define __DOH_PROXY_H

#include <netinet/in.h>
#include <curl/curl.h>
#include <libubox/uloop.h>

#include "privilege.h"

struct pending_request;

struct doh_proxy_ctx {
	int listen_fd;
	struct uloop_fd ufd;
	struct sockaddr_in bind_addr;
	CURLM *multi_handle;
	char *doh_url;
	int port;
	struct pending_request *pending_requests;
	int pending_request_count;
};

int doh_proxy_init(struct doh_proxy_ctx *ctx, const char *listen_addr, int port, const char *doh_url);
void doh_proxy_cleanup(struct doh_proxy_ctx *ctx);

#endif /* __DOH_PROXY_H */
