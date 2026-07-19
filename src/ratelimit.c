/*
 * ratelimit.c - query rate limiting
 *
 * Token-bucket rate limiting with one global bucket and a bounded
 * per-client table keyed by source address. The table is organised as
 * small sets probed linearly; under a spoofed-source flood entries are
 * recycled by age, and the global bucket remains the backstop.
 */

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "udnsfilter.h"

#define RATELIMIT_SETS 256
#define RATELIMIT_WAYS 4

struct rate_client {
	uint8_t addr[16];
	uint8_t addr_len;
	bool in_use;
	bool limited;
	double tokens;
	struct timespec last;
};

static struct rate_client clients[RATELIMIT_SETS][RATELIMIT_WAYS];
static double global_tokens;
static struct timespec global_last;
static bool global_limited;
static bool global_primed;

static size_t addr_key(const struct sockaddr_storage *ss, const uint8_t **key)
{
	if (ss->ss_family == AF_INET) {
		*key = (const uint8_t *)&((const struct sockaddr_in *)ss)->sin_addr;
		return 4;
	}

	*key = (const uint8_t *)&((const struct sockaddr_in6 *)ss)->sin6_addr;
	return 16;
}

static uint32_t addr_hash(const uint8_t *key, size_t len)
{
	uint32_t hash = 2166136261u;

	for (size_t i = 0; i < len; i++) {
		hash ^= key[i];
		hash *= 16777619u;
	}

	return hash;
}

static double elapsed_since(const struct timespec *last, const struct timespec *now)
{
	return (double)(now->tv_sec - last->tv_sec) +
	       (double)(now->tv_nsec - last->tv_nsec) / 1e9;
}

static bool bucket_take(double *tokens, struct timespec *last, const struct timespec *now,
                        unsigned int rate, unsigned int burst)
{
	*tokens += elapsed_since(last, now) * rate;
	if (*tokens > burst)
		*tokens = burst;
	*last = *now;

	if (*tokens < 1.0)
		return false;

	*tokens -= 1.0;
	return true;
}

static void limited_log(const struct sockaddr_storage *ss)
{
	char ip[INET6_ADDRSTRLEN] = "?";

	if (ss->ss_family == AF_INET)
		inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, ip, sizeof(ip));
	else
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr, ip, sizeof(ip));

	fprintf(stderr, "Rate limiting queries from %s\n", ip);
}

static bool global_allow(const struct timespec *now)
{
	unsigned int rate = udns_security.ratelimit_global;
	unsigned int burst = udns_security.ratelimit_global_burst;

	if (!rate)
		return true;

	if (!global_primed) {
		global_tokens = burst;
		global_last = *now;
		global_primed = true;
	}

	if (bucket_take(&global_tokens, &global_last, now, rate, burst)) {
		/* Re-arm the log only once the flood has genuinely eased */
		if (global_limited && global_tokens >= burst / 2)
			global_limited = false;
		return true;
	}

	if (!global_limited) {
		global_limited = true;
		fprintf(stderr, "Global query rate limit exceeded\n");
	}

	return false;
}

static struct rate_client *client_slot(const uint8_t *key, size_t len,
                                       const struct timespec *now)
{
	struct rate_client *set = clients[addr_hash(key, len) % RATELIMIT_SETS];
	struct rate_client *victim = &set[0];

	for (int i = 0; i < RATELIMIT_WAYS; i++) {
		struct rate_client *entry = &set[i];

		if (entry->in_use && entry->addr_len == len &&
		    memcmp(entry->addr, key, len) == 0)
			return entry;

		if (!entry->in_use)
			victim = entry;
		else if (victim->in_use && elapsed_since(&entry->last, now) >
		                           elapsed_since(&victim->last, now))
			victim = entry;
	}

	memset(victim, 0, sizeof(*victim));
	memcpy(victim->addr, key, len);
	victim->addr_len = len;
	victim->in_use = true;
	victim->tokens = udns_security.ratelimit_burst;
	victim->last = *now;

	return victim;
}

/**
 * ratelimit_allow() - Account one query against the rate limits
 * @ss: Client source address
 *
 * Return: true if the query may be processed, false if it must be dropped
 */
bool ratelimit_allow(const struct sockaddr_storage *ss)
{
	struct timespec now;
	struct rate_client *client;
	const uint8_t *key;
	size_t len;

	if (!udns_security.ratelimit && !udns_security.ratelimit_global)
		return true;

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (!global_allow(&now))
		return false;

	if (!udns_security.ratelimit)
		return true;

	len = addr_key(ss, &key);
	client = client_slot(key, len, &now);

	if (bucket_take(&client->tokens, &client->last, &now,
	                udns_security.ratelimit, udns_security.ratelimit_burst)) {
		if (client->limited &&
		    client->tokens >= udns_security.ratelimit_burst / 2)
			client->limited = false;
		return true;
	}

	if (!client->limited) {
		client->limited = true;
		limited_log(ss);
	}

	return false;
}
