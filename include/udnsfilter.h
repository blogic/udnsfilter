/*
 * udnsfilter.h - Main header for uDNS Filter
 */

#ifndef __UDNSFILTER_H
#define __UDNSFILTER_H

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <ares.h>
#include <libubox/uloop.h>

/* DNS Constants */
#define DNS_PORT 53
#define DNS_MAX_PACKET_SIZE 512   /* Classic UDP payload limit (RFC 1035) */
#define DNS_MAX_QUERY_SIZE 4096   /* Receive limit; EDNS0 queries exceed 512 */
#define DNS_MAX_NAME_LENGTH 253
#define DNS_MAX_NAME_WIRE_LENGTH 255
#define DNS_MAX_LABEL_LENGTH 63

/* DNS Header Structure */
struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} __attribute__((packed));

/* DNS Query Types */
#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_PTR    12
#define DNS_TYPE_MX     15
#define DNS_TYPE_TXT    16
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_SRV    33
#define DNS_TYPE_ANY    255

/* DNS Classes */
#define DNS_CLASS_IN    1

/* DNS Response Codes */
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5

/* DNS Flags */
#define DNS_FLAG_QR      (1 << 15)  /* Query/Response */
#define DNS_FLAG_AA      (1 << 10)  /* Authoritative Answer */
#define DNS_FLAG_TC      (1 << 9)   /* Truncated */
#define DNS_FLAG_RD      (1 << 8)   /* Recursion Desired */
#define DNS_FLAG_RA      (1 << 7)   /* Recursion Available */

#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE(flags) (((flags) >> 11) & 0xf)

/* Filter Rule Types */
enum filter_rule_type {
	FILTER_EXACT,      /* domain.com */
	FILTER_SUBDOMAIN,  /* ||domain.com^ - domain and all subdomains */
	FILTER_WILDCARD,   /* *.domain.com */
};

/* Filter Rule */
struct filter_rule {
	char *pattern;
	uint32_t hash;
	enum filter_rule_type type;
	struct filter_rule *next;  /* For hash table chaining */
};

/* Hash Table for exact matches */
struct filter_hashtable {
	struct filter_rule **buckets;
	size_t size;
	size_t count;
};

/* Filter Context */
struct filter_ctx {
	struct filter_hashtable *exact_ht;   /* Full-domain rules */
	struct filter_hashtable *suffix_ht;  /* ||domain^ and *.domain rules keyed by base domain */
	size_t total_count;
};

/* Server health tracking */
struct server_state {
	char address[INET6_ADDRSTRLEN + 8];
	int consecutive_failures;
	bool healthy;
	struct server_state *next;
};

/* Resolver Context (c-ares wrapper) */
struct resolver_ctx {
	ares_channel channel;
	struct resolver_fd *fds;
	struct uloop_timeout timeout;
	bool rotation_enabled;
	unsigned int cache_ttl;
};

/* DNS Packet */
struct dns_packet {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	uint8_t *data;
	size_t len;
	size_t capacity;
};

/* DNS Question */
struct dns_question {
	char name[DNS_MAX_NAME_LENGTH + 1];
	uint16_t qtype;
	uint16_t qclass;
};

/* Client Info */
struct client_info {
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char ip[INET6_ADDRSTRLEN];
};

/* Statistics */
struct stats {
	uint64_t total_queries;
	uint64_t blocked_queries;
	uint64_t allowed_queries;
	uint64_t forwarded_queries;
	uint64_t upstream_errors;
	uint64_t malformed_queries;
	uint64_t refused_queries;
	uint64_t rate_limited;
	uint64_t overload_dropped;
};

/* Security configuration, adjustable from ucode; zero disables a limit */
struct udns_security {
	bool block_any;
	unsigned int ratelimit;
	unsigned int ratelimit_burst;
	unsigned int ratelimit_global;
	unsigned int ratelimit_global_burst;
	unsigned int max_pending;
	unsigned int max_filter_rules;
	unsigned int max_tcp_per_client;
};
extern struct udns_security udns_security;

/* Verdict for a query before parsing and callback dispatch */
enum query_verdict {
	QUERY_VERDICT_OK,
	QUERY_VERDICT_DROP,
	QUERY_VERDICT_FORMERR,
	QUERY_VERDICT_NOTIMP,
};

/* UDP socket context */
struct udns_socket {
	int fd;
	struct uloop_fd ufd;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_storage ss;
	} bind_addr;
	int family;
};

/* Global context - opaque, defined in module.c */
struct udns_ctx;
extern struct udns_ctx global_ctx;

/* packet.c - DNS packet handling */
int packet_parse(struct dns_packet *pkt, const uint8_t *data, size_t len);
int packet_build(struct dns_packet *pkt, uint8_t *buf, size_t buflen);
int packet_parse_question(struct dns_packet *pkt, struct dns_question *q);
enum query_verdict packet_precheck(const uint8_t *data, size_t len);
int packet_build_nxdomain(struct dns_packet *response, const struct dns_packet *query);
int packet_build_rcode(struct dns_packet *response, uint16_t query_id, int rcode);
int packet_build_null_response(struct dns_packet *response, const struct dns_packet *query);
int packet_build_truncated(struct dns_packet *response, const uint8_t *query, size_t query_len);

/* socket.c - Socket handling */
int udns_sockaddr_build(const char *addr, int port, int family,
                        struct sockaddr_storage *ss, socklen_t *addrlen);
int udns_socket_create(const char *addr, const char *addr6, int port);
void udns_socket_close(struct udns_socket *sock);
int udns_socket_send(struct udns_socket *sock, const uint8_t *data, size_t len,
                     struct sockaddr *dest, socklen_t dest_len);
struct udns_socket *udns_socket_for_client(struct sockaddr_storage *client_addr);

/* tcp.c - TCP DNS transport (RFC 7766) */
int udns_tcp_listen(const char *addr, const char *addr6, int port);
void udns_tcp_close(void);
int udns_tcp_send(uint32_t conn_id, const uint8_t *data, size_t len);

/* resolver.c - c-ares integration */
int resolver_init(struct resolver_ctx *ctx, bool rotation, unsigned int cache_ttl);
void resolver_cleanup(struct resolver_ctx *ctx);
int resolver_forward_query(struct resolver_ctx *ctx, struct udns_socket *sock,
                           const uint8_t *query_data, size_t query_len,
                           struct sockaddr_storage *client_addr, socklen_t client_addrlen,
                           const char *domain, uint32_t tcp_conn_id);
void resolver_set_servers(struct resolver_ctx *ctx, const char **servers, int count);
int resolver_reinit(struct resolver_ctx *ctx);
int resolver_get_server_states(struct server_state **states);
void resolver_get_config(struct resolver_ctx *ctx, bool *rotation, unsigned int *cache_ttl);
void rebind_config_set(bool enable);
int rebind_domain_add(const char *domain);
void rebind_domains_clear(void);

/* filter.c - Filter engine */
int filter_init(struct filter_ctx *ctx);
void filter_cleanup(struct filter_ctx *ctx);
void filter_clear(struct filter_ctx *ctx);
int filter_load_file(struct filter_ctx *ctx, const char *path);
int filter_add_rule(struct filter_ctx *ctx, const char *pattern);
bool filter_match(struct filter_ctx *ctx, const char *domain,
                  struct filter_rule **matched);
void filter_stats(struct filter_ctx *ctx, size_t *count);

/* ratelimit.c - query rate limiting */
bool ratelimit_allow(const struct sockaddr_storage *ss);

/* util.c - Utilities */
uint32_t hash_string(const char *str);
bool domain_match_exact(const char *domain, const char *pattern);
bool domain_match_subdomain(const char *domain, const char *pattern);
const char *qtype_to_string(uint16_t qtype);
bool is_private_ipv4(uint32_t ip);
bool is_private_ipv6(const uint8_t *ip);
bool dns_response_contains_private_ip(const uint8_t *response, size_t len);

/* callback.c - ucode callback invocation */
void udns_callback_query(struct dns_packet *pkt, struct sockaddr_storage *client_addr,
                         socklen_t client_addrlen, const uint8_t *raw_data, size_t raw_len,
                         uint32_t tcp_conn_id);

/* Error handling */
void udns_set_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
const char *udns_get_error(void);

#endif /* __UDNSFILTER_H */
