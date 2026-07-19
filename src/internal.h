/*
 * internal.h - Internal definitions for udnsfilter implementation
 */

#ifndef __UDNSFILTER_INTERNAL_H
#define __UDNSFILTER_INTERNAL_H

#include <time.h>
#include <ucode/types.h>
#include <ucode/vm.h>
#include "udnsfilter.h"

struct doh_proxy_process {
	struct uloop_process proc;
	struct uloop_timeout restart_timer;
	int restart_delay;
	time_t started;
	int port;
	char *doh_url;
	char *original_uri;
	char *rewritten_uri;
	struct doh_proxy_process *next;
};

struct udns_ctx {
	struct udns_socket sock4;
	struct udns_socket sock6;
	struct resolver_ctx resolver;
	struct filter_ctx filter;
	struct stats stats;

	uc_value_t *on_query;
	uc_vm_t *vm;

	struct doh_proxy_process *proxies;
	int next_proxy_port;

	char error[256];
	bool initialized;
};

#endif /* __UDNSFILTER_INTERNAL_H */
