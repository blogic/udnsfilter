/*
 * module.c - Ucode module entry point for udnsfilter
 *
 * This file implements the ucode module interface for udnsfilter, providing
 * DNS filtering and forwarding capabilities to ucode scripts. It manages the
 * global context including sockets, resolver, filter engine, and DoH proxy
 * processes.
 */

#include <ucode/module.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include "internal.h"
#include "privilege.h"

#ifndef DOH_PROXY_PATH
#define DOH_PROXY_PATH "/src/projects/udnsfilter/doh_proxy"
#endif
#define DOH_PROXY_START_PORT 5301

/**
 * doh_proxy_path() - Get the path to the doh_proxy executable
 *
 * Returns the path from the DOH_PROXY_PATH environment variable if set,
 * otherwise returns the compiled default path.
 *
 * Return: Path to doh_proxy executable
 */
static const char *doh_proxy_path(void)
{
	const char *env_path = getenv("DOH_PROXY_PATH");
	return env_path ? env_path : DOH_PROXY_PATH;
}

struct udns_ctx global_ctx = {
	.sock4 = { .fd = -1 },
	.sock6 = { .fd = -1 },
	.initialized = false,
	.proxies = NULL,
	.next_proxy_port = DOH_PROXY_START_PORT
};

/**
 * proxy_process_cb() - Handle DoH proxy process exit
 * @proc: uloop process structure
 * @exitcode: Exit code from the process
 *
 * Automatically restarts a DoH proxy process when it exits.
 */
static void proxy_process_cb(struct uloop_process *proc, int exitcode)
{
	struct doh_proxy_process *proxy = container_of(proc, struct doh_proxy_process, proc);

	fprintf(stderr, "DoH proxy on port %d exited with code %d, restarting...\n",
	        proxy->port, exitcode);

	pid_t pid = fork();
	if (pid == 0) {
		char port_str[16];
		snprintf(port_str, sizeof(port_str), "%d", proxy->port);
		execlp(doh_proxy_path(), "doh_proxy", "127.0.0.1", port_str, proxy->doh_url, NULL);
		_exit(1);
	} else if (pid > 0) {
		proxy->proc.pid = pid;
		uloop_process_add(&proxy->proc);
	}
}

/**
 * spawn_doh_proxy() - Spawn a DoH proxy process
 * @original_uri: Original DNS-over-HTTPS URI (e.g., "dns+https://1.1.1.1/dns-query")
 * @doh_url: HTTPS URL for DoH endpoint (e.g., "https://1.1.1.1/dns-query")
 *
 * Spawns a doh_proxy subprocess listening on a local port, which converts
 * standard DNS queries to DoH requests. The process is automatically
 * restarted if it exits.
 *
 * Return: Pointer to doh_proxy_process structure, or NULL on failure
 */
static struct doh_proxy_process *spawn_doh_proxy(const char *original_uri, const char *doh_url)
{
	struct doh_proxy_process *proxy;
	char port_str[16];
	pid_t pid;
	int ret;

	proxy = calloc(1, sizeof(*proxy));
	if (!proxy)
		return NULL;

	if (global_ctx.next_proxy_port > 65535) {
		free(proxy);
		return NULL;
	}

	proxy->port = global_ctx.next_proxy_port++;

	proxy->original_uri = strdup(original_uri);
	if (!proxy->original_uri) {
		free(proxy);
		return NULL;
	}

	proxy->doh_url = strdup(doh_url);
	if (!proxy->doh_url) {
		free(proxy->original_uri);
		free(proxy);
		return NULL;
	}

	ret = snprintf(port_str, sizeof(port_str), "%d", proxy->port);
	if (ret < 0 || (size_t)ret >= sizeof(port_str)) {
		free(proxy->doh_url);
		free(proxy->original_uri);
		free(proxy);
		return NULL;
	}

	char rewritten[256];
	ret = snprintf(rewritten, sizeof(rewritten), "dns://127.0.0.1:%d", proxy->port);
	if (ret < 0 || (size_t)ret >= sizeof(rewritten)) {
		free(proxy->doh_url);
		free(proxy->original_uri);
		free(proxy);
		return NULL;
	}

	proxy->rewritten_uri = strdup(rewritten);
	if (!proxy->rewritten_uri) {
		free(proxy->doh_url);
		free(proxy->original_uri);
		free(proxy);
		return NULL;
	}

	pid = fork();
	if (pid == 0) {
		execlp(doh_proxy_path(), "doh_proxy", "127.0.0.1", port_str, doh_url, NULL);
		_exit(1);
	} else if (pid < 0) {
		free(proxy->rewritten_uri);
		free(proxy->doh_url);
		free(proxy->original_uri);
		free(proxy);
		return NULL;
	}

	proxy->proc.pid = pid;
	proxy->proc.cb = proxy_process_cb;
	uloop_process_add(&proxy->proc);

	return proxy;
}

/**
 * cleanup_proxies() - Terminate all DoH proxy processes
 *
 * Terminates all spawned DoH proxy processes and frees their resources.
 */
static void cleanup_proxies(void)
{
	struct doh_proxy_process *proxy, *tmp;

	for (proxy = global_ctx.proxies; proxy; proxy = tmp) {
		tmp = proxy->next;
		uloop_process_delete(&proxy->proc);
		kill(proxy->proc.pid, SIGTERM);
		free(proxy->doh_url);
		free(proxy->original_uri);
		free(proxy->rewritten_uri);
		free(proxy);
	}

	global_ctx.proxies = NULL;
}

/**
 * uc_udnsfilter_socket_create() - Create and bind DNS sockets
 * @vm: ucode VM instance
 * @nargs: Number of arguments (4)
 *
 * Arguments: address, port, rotation (optional), cache_ttl (optional)
 *
 * Creates IPv4 and IPv6 UDP sockets for receiving DNS queries and initialises
 * the resolver and filter subsystems.
 *
 * Return: true on success, NULL on failure
 */
static uc_value_t *
uc_udnsfilter_socket_create(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *addr_val = uc_fn_arg(0);
	uc_value_t *port_val = uc_fn_arg(1);
	uc_value_t *rotation_val = uc_fn_arg(2);
	uc_value_t *cache_ttl_val = uc_fn_arg(3);
	const char *addr;
	int port;
	bool rotation = true;
	unsigned int cache_ttl = 3600;

	if (ucv_type(addr_val) != UC_STRING || ucv_type(port_val) != UC_INTEGER)
		return NULL;

	addr = ucv_string_get(addr_val);
	port = ucv_int64_get(port_val);

	if (rotation_val && ucv_type(rotation_val) == UC_BOOLEAN)
		rotation = ucv_boolean_get(rotation_val);

	if (cache_ttl_val && ucv_type(cache_ttl_val) == UC_INTEGER)
		cache_ttl = ucv_uint64_get(cache_ttl_val);

	if (udns_socket_create(addr, port) < 0)
		return NULL;

	if (!global_ctx.initialized) {
		if (resolver_init(&global_ctx.resolver, rotation, cache_ttl) < 0) {
			udns_socket_close(&global_ctx.sock4);
			udns_socket_close(&global_ctx.sock6);
			return NULL;
		}

		if (filter_init(&global_ctx.filter) < 0) {
			resolver_cleanup(&global_ctx.resolver);
			udns_socket_close(&global_ctx.sock4);
			udns_socket_close(&global_ctx.sock6);
			return NULL;
		}

		global_ctx.vm = vm;
		global_ctx.initialized = true;
	}

	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_set_callback() - Register a query callback function
 * @vm: ucode VM instance
 * @nargs: Number of arguments (2)
 *
 * Arguments: event_type ("query"), callback (function)
 *
 * Registers a ucode callback function to be invoked for DNS queries.
 *
 * Return: true on success, NULL on failure
 */
static uc_value_t *
uc_udnsfilter_set_callback(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *event_type = uc_fn_arg(0);
	uc_value_t *callback = uc_fn_arg(1);
	const char *type_str;

	if (ucv_type(event_type) != UC_STRING)
		return NULL;

	if (!ucv_is_callable(callback))
		return NULL;

	type_str = ucv_string_get(event_type);

	if (strcmp(type_str, "query") == 0) {
		ucv_put(global_ctx.on_query);
		global_ctx.on_query = ucv_get(callback);
	} else {
		return NULL;
	}

	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_shutdown() - Shutdown DNS filter and clean up resources
 * @vm: ucode VM instance
 * @nargs: Number of arguments (0)
 *
 * Cleans up all resources including sockets, resolver, filter, and DoH proxies.
 *
 * Return: true
 */
static uc_value_t *
uc_udnsfilter_shutdown(uc_vm_t *vm, size_t nargs)
{
	if (!global_ctx.initialized)
		return ucv_boolean_new(true);

	cleanup_proxies();

	udns_socket_close(&global_ctx.sock4);
	udns_socket_close(&global_ctx.sock6);
	resolver_cleanup(&global_ctx.resolver);
	filter_cleanup(&global_ctx.filter);

	ucv_put(global_ctx.on_query);
	global_ctx.on_query = NULL;
	global_ctx.vm = NULL;

	global_ctx.initialized = false;

	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_filter_load() - Load filter list from file
 * @vm: ucode VM instance
 * @nargs: Number of arguments (1)
 *
 * Arguments: path (string)
 *
 * Loads domain filter rules from a file. Supports multiple formats including
 * adblock-style rules (||domain^), hosts file format, and plain domains.
 *
 * Return: Number of rules loaded on success, NULL on failure
 */
static uc_value_t *
uc_udnsfilter_filter_load(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path_val = uc_fn_arg(0);
	const char *path;
	int count;

	if (ucv_type(path_val) != UC_STRING)
		return NULL;

	path = ucv_string_get(path_val);

	count = filter_load_file(&global_ctx.filter, path);
	if (count < 0)
		return NULL;

	return ucv_int64_new(count);
}

/**
 * uc_udnsfilter_filter_match() - Check if domain matches any filter rule
 * @vm: ucode VM instance
 * @nargs: Number of arguments (1)
 *
 * Arguments: domain (string)
 *
 * Tests whether a domain name matches any loaded filter rule.
 *
 * Return: { blocked: true, rule: "pattern" } on match, NULL on no match
 */
static uc_value_t *
uc_udnsfilter_filter_match(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *domain_val = uc_fn_arg(0);
	uc_value_t *result;
	const char *domain;
	struct filter_rule *rule = NULL;

	if (ucv_type(domain_val) != UC_STRING)
		return NULL;

	domain = ucv_string_get(domain_val);

	if (!filter_match(&global_ctx.filter, domain, &rule))
		return NULL;

	result = ucv_object_new(vm);
	ucv_object_add(result, "blocked", ucv_boolean_new(true));
	ucv_object_add(result, "rule", ucv_string_new(rule->pattern));

	return result;
}

/**
 * uc_udnsfilter_stats_get() - Get current statistics
 * @vm: ucode VM instance
 * @nargs: Number of arguments (0)
 *
 * Retrieves current query statistics.
 *
 * Return: Object with total_queries, blocked_queries, allowed_queries,
 *         forwarded_queries, and upstream_errors counters
 */
static uc_value_t *
uc_udnsfilter_stats_get(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *stats = ucv_object_new(vm);

	ucv_object_add(stats, "total_queries",
	               ucv_uint64_new(global_ctx.stats.total_queries));
	ucv_object_add(stats, "blocked_queries",
	               ucv_uint64_new(global_ctx.stats.blocked_queries));
	ucv_object_add(stats, "allowed_queries",
	               ucv_uint64_new(global_ctx.stats.allowed_queries));
	ucv_object_add(stats, "forwarded_queries",
	               ucv_uint64_new(global_ctx.stats.forwarded_queries));
	ucv_object_add(stats, "upstream_errors",
	               ucv_uint64_new(global_ctx.stats.upstream_errors));

	return stats;
}

/**
 * uc_udnsfilter_stats_reset() - Reset all statistics counters
 * @vm: ucode VM instance
 * @nargs: Number of arguments (0)
 *
 * Return: true
 */
static uc_value_t *
uc_udnsfilter_stats_reset(uc_vm_t *vm, size_t nargs)
{
	memset(&global_ctx.stats, 0, sizeof(global_ctx.stats));
	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_set_upstream() - Configure upstream DNS servers
 * @vm: ucode VM instance
 * @nargs: Number of arguments (1)
 *
 * Arguments: servers (array of strings)
 *
 * Sets the upstream DNS servers. Supports standard DNS URIs (dns://host:port)
 * and DoH URIs (dns+https://host/path). DoH URIs spawn a local proxy process.
 *
 * Return: true on success, NULL on failure
 */
static uc_value_t *
uc_udnsfilter_set_upstream(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *servers_val = uc_fn_arg(0);
	const char **servers;
	size_t count, i, server_idx = 0;

	if (ucv_type(servers_val) != UC_ARRAY)
		return NULL;

	count = ucv_array_length(servers_val);
	if (count == 0 || count > 64)
		return NULL;

	cleanup_proxies();

	servers = calloc(count, sizeof(char *));
	if (!servers)
		return NULL;

	for (i = 0; i < count; i++) {
		uc_value_t *server = ucv_array_get(servers_val, i);
		if (ucv_type(server) != UC_STRING)
			continue;

		const char *uri = ucv_string_get(server);

		if (strncmp(uri, "dns+https://", 12) == 0) {
			const char *doh_url_start = uri + 4;
			struct doh_proxy_process *proxy = spawn_doh_proxy(uri, doh_url_start);
			if (proxy) {
				proxy->next = global_ctx.proxies;
				global_ctx.proxies = proxy;
				servers[server_idx++] = proxy->rewritten_uri;
				fprintf(stderr, "Spawned DoH proxy: %s -> %s\n",
				        uri, proxy->rewritten_uri);
			}
		} else {
			servers[server_idx++] = uri;
		}
	}

	if (server_idx > 0)
		resolver_set_servers(&global_ctx.resolver, servers, server_idx);

	free(servers);

	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_reinit() - Reinitialise the resolver
 * @vm: ucode VM instance
 * @nargs: Number of arguments (0)
 *
 * Reinitialises the c-ares resolver, useful after network changes.
 *
 * Return: true on success, NULL on failure
 */
static uc_value_t *
uc_udnsfilter_reinit(uc_vm_t *vm, size_t nargs)
{
	if (resolver_reinit(&global_ctx.resolver) < 0)
		return NULL;

	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_get_server_states() - Get upstream server health states
 * @vm: ucode VM instance
 * @nargs: Number of arguments (0)
 *
 * Retrieves the health state of all configured upstream DNS servers,
 * including consecutive failure counts and health status.
 *
 * Return: Object with servers array, rotation flag, and cache_ttl
 */
static uc_value_t *
uc_udnsfilter_get_server_states(uc_vm_t *vm, size_t nargs)
{
	struct server_state *states = NULL;
	struct server_state *state;
	struct doh_proxy_process *proxy;
	uc_value_t *result, *servers, *server_obj;
	bool rotation;
	unsigned int cache_ttl;

	resolver_get_server_states(&states);
	resolver_get_config(&global_ctx.resolver, &rotation, &cache_ttl);

	result = ucv_object_new(vm);
	servers = ucv_array_new(vm);

	for (state = states; state; state = state->next) {
		const char *display_address = state->address;

		for (proxy = global_ctx.proxies; proxy; proxy = proxy->next) {
			char proxy_addr[64];
			snprintf(proxy_addr, sizeof(proxy_addr), "127.0.0.1:%d", proxy->port);
			if (strstr(state->address, proxy_addr)) {
				display_address = proxy->original_uri;
				break;
			}
		}

		server_obj = ucv_object_new(vm);
		ucv_object_add(server_obj, "address", ucv_string_new(display_address));
		ucv_object_add(server_obj, "consecutive_failures",
		               ucv_int64_new(state->consecutive_failures));
		ucv_object_add(server_obj, "state",
		               ucv_string_new(state->healthy ? "healthy" : "degraded"));
		ucv_array_push(servers, server_obj);
	}

	ucv_object_add(result, "servers", servers);
	ucv_object_add(result, "rotation", ucv_boolean_new(rotation));
	ucv_object_add(result, "cache_ttl", ucv_uint64_new(cache_ttl));

	return result;
}

/**
 * uc_udnsfilter_send_blocked_response() - Send a null response to client
 * @vm: ucode VM instance
 * @nargs: Number of arguments (2)
 *
 * Arguments: client (object), packet (object)
 *
 * Sends a DNS response with a null IP address (0.0.0.0) to block the domain.
 * Increments the blocked_queries counter.
 *
 * Return: true on success, NULL on failure
 */
static uc_value_t *
uc_udnsfilter_send_blocked_response(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *client_val = uc_fn_arg(0);
	uc_value_t *packet_val = uc_fn_arg(1);
	uc_value_t *addr_val, *port_val, *family_val, *raw_data_val;
	struct sockaddr_storage client_addr;
	socklen_t client_addrlen;
	struct dns_packet query, response;
	const char *addr_str, *family_str, *raw_data_str;
	size_t raw_len;
	int port;

	if (ucv_type(client_val) != UC_OBJECT || ucv_type(packet_val) != UC_OBJECT)
		return NULL;

	addr_val = ucv_object_get(client_val, "address", NULL);
	port_val = ucv_object_get(client_val, "port", NULL);
	family_val = ucv_object_get(client_val, "family", NULL);
	raw_data_val = ucv_object_get(packet_val, "raw_data", NULL);

	if (ucv_type(addr_val) != UC_STRING || ucv_type(port_val) != UC_INTEGER ||
	    ucv_type(family_val) != UC_STRING || ucv_type(raw_data_val) != UC_STRING)
		return NULL;

	addr_str = ucv_string_get(addr_val);
	port = ucv_int64_get(port_val);
	family_str = ucv_string_get(family_val);
	raw_data_str = ucv_string_get(raw_data_val);
	raw_len = ucv_string_length(raw_data_val);

	memset(&client_addr, 0, sizeof(client_addr));

	if (strcmp(family_str, "inet") == 0) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		inet_pton(AF_INET, addr_str, &sin->sin_addr);
		client_addrlen = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client_addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		inet_pton(AF_INET6, addr_str, &sin6->sin6_addr);
		client_addrlen = sizeof(*sin6);
	}

	memset(&query, 0, sizeof(query));
	memset(&response, 0, sizeof(response));

	if (packet_parse(&query, (const uint8_t *)raw_data_str, raw_len) < 0)
		return NULL;

	if (packet_build_null_response(&response, &query) < 0) {
		free(query.data);
		free(response.data);
		return NULL;
	}

	udns_socket_send(udns_socket_for_client(&client_addr), response.data, response.len,
	                (struct sockaddr *)&client_addr, client_addrlen);

	global_ctx.stats.blocked_queries++;

	free(query.data);
	free(response.data);

	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_forward_query() - Forward DNS query to upstream server
 * @vm: ucode VM instance
 * @nargs: Number of arguments (2)
 *
 * Arguments: client (object), packet (object)
 *
 * Forwards a DNS query to the configured upstream servers using c-ares.
 * The response will be sent back to the client when received.
 *
 * Return: true on success, NULL on failure
 */
static uc_value_t *
uc_udnsfilter_forward_query(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *client_val = uc_fn_arg(0);
	uc_value_t *packet_val = uc_fn_arg(1);
	uc_value_t *addr_val, *port_val, *family_val, *questions_val, *question_val;
	uc_value_t *name_val;
	struct sockaddr_storage client_addr;
	socklen_t client_addrlen;
	const char *addr_str, *family_str, *domain;
	int port;
	uint8_t query_data[DNS_MAX_PACKET_SIZE];
	size_t query_len;

	if (ucv_type(client_val) != UC_OBJECT || ucv_type(packet_val) != UC_OBJECT)
		return NULL;

	addr_val = ucv_object_get(client_val, "address", NULL);
	port_val = ucv_object_get(client_val, "port", NULL);
	family_val = ucv_object_get(client_val, "family", NULL);

	if (ucv_type(addr_val) != UC_STRING || ucv_type(port_val) != UC_INTEGER ||
	    ucv_type(family_val) != UC_STRING)
		return NULL;

	addr_str = ucv_string_get(addr_val);
	port = ucv_int64_get(port_val);
	family_str = ucv_string_get(family_val);

	memset(&client_addr, 0, sizeof(client_addr));

	if (strcmp(family_str, "inet") == 0) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		inet_pton(AF_INET, addr_str, &sin->sin_addr);
		client_addrlen = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client_addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		inet_pton(AF_INET6, addr_str, &sin6->sin6_addr);
		client_addrlen = sizeof(*sin6);
	}

	uc_value_t *raw_data_val = ucv_object_get(packet_val, "raw_data", NULL);
	if (ucv_type(raw_data_val) != UC_STRING)
		return NULL;

	const char *raw_data_str = ucv_string_get(raw_data_val);
	query_len = ucv_string_length(raw_data_val);

	if (query_len > sizeof(query_data))
		return NULL;

	memcpy(query_data, raw_data_str, query_len);

	questions_val = ucv_object_get(packet_val, "questions", NULL);
	if (ucv_type(questions_val) != UC_ARRAY || ucv_array_length(questions_val) == 0)
		return NULL;

	question_val = ucv_array_get(questions_val, 0);
	name_val = ucv_object_get(question_val, "name", NULL);
	if (ucv_type(name_val) != UC_STRING)
		return NULL;

	domain = ucv_string_get(name_val);

	resolver_forward_query(&global_ctx.resolver, udns_socket_for_client(&client_addr),
	                      query_data, query_len,
	                      &client_addr, client_addrlen, domain);

	return ucv_boolean_new(true);
}

/**
 * uc_udnsfilter_drop_privileges() - Drop root privileges
 * @vm: ucode VM instance
 * @nargs: Number of arguments (2)
 *
 * Arguments: user (string, optional), group (string, optional)
 *
 * Drops root privileges to the specified user and group. Defaults to
 * "nobody:nogroup" if not specified.
 *
 * Return: true on success, false on failure
 */
static uc_value_t *
uc_udnsfilter_drop_privileges(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *user_val = uc_fn_arg(0);
	uc_value_t *group_val = uc_fn_arg(1);
	const char *user = NULL;
	const char *group = NULL;

	if (user_val && ucv_type(user_val) == UC_STRING)
		user = ucv_string_get(user_val);

	if (group_val && ucv_type(group_val) == UC_STRING)
		group = ucv_string_get(group_val);

	if (privilege_drop(user, group) < 0)
		return ucv_boolean_new(false);

	return ucv_boolean_new(true);
}

static const uc_function_list_t module_fns[] = {
	{ "socket_create",           uc_udnsfilter_socket_create },
	{ "set_callback",            uc_udnsfilter_set_callback },
	{ "shutdown",                uc_udnsfilter_shutdown },
	{ "filter_load",             uc_udnsfilter_filter_load },
	{ "filter_match",            uc_udnsfilter_filter_match },
	{ "stats_get",               uc_udnsfilter_stats_get },
	{ "stats_reset",             uc_udnsfilter_stats_reset },
	{ "set_upstream",            uc_udnsfilter_set_upstream },
	{ "reinit",                  uc_udnsfilter_reinit },
	{ "get_server_states",       uc_udnsfilter_get_server_states },
	{ "send_blocked_response",   uc_udnsfilter_send_blocked_response },
	{ "forward_query",           uc_udnsfilter_forward_query },
	{ "drop_privileges",         uc_udnsfilter_drop_privileges },
};

/**
 * uc_module_init() - Initialise the udnsfilter ucode module
 * @vm: ucode VM instance
 * @scope: Module scope object
 *
 * Registers all udnsfilter functions with the ucode VM.
 */
void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, module_fns);
}
