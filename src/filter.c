/*
 * filter.c - DNS filter matching engine with hash table optimisation
 *
 * This file implements a high-performance domain filtering engine using
 * a hash table for exact matches and linked lists for wildcard and
 * subdomain patterns. Supports multiple filter formats including
 * adblock-style rules, hosts files, and plain domain lists.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "udnsfilter.h"

#define HASHTABLE_INITIAL_SIZE 4096

static struct filter_hashtable *hashtable_create(size_t size)
{
	struct filter_hashtable *ht;

	ht = calloc(1, sizeof(*ht));
	if (!ht)
		return NULL;

	ht->buckets = calloc(size, sizeof(struct filter_rule *));
	if (!ht->buckets) {
		free(ht);
		return NULL;
	}

	ht->size = size;
	ht->count = 0;

	return ht;
}

static void rule_list_free(struct filter_rule *rule)
{
	struct filter_rule *next;

	while (rule) {
		next = rule->next;
		free(rule->pattern);
		free(rule);
		rule = next;
	}
}

static void hashtable_destroy(struct filter_hashtable *ht)
{
	size_t i;

	if (!ht)
		return;

	for (i = 0; i < ht->size; i++)
		rule_list_free(ht->buckets[i]);

	free(ht->buckets);
	free(ht);
}

static void hashtable_grow(struct filter_hashtable *ht)
{
	struct filter_rule **buckets;
	size_t new_size = ht->size * 2;
	size_t i;

	/* Growth failure is not fatal: chains lengthen but lookups stay correct */
	buckets = calloc(new_size, sizeof(*buckets));
	if (!buckets)
		return;

	for (i = 0; i < ht->size; i++) {
		struct filter_rule *rule = ht->buckets[i];

		while (rule) {
			struct filter_rule *next = rule->next;
			size_t bucket = rule->hash % new_size;

			rule->next = buckets[bucket];
			buckets[bucket] = rule;
			rule = next;
		}
	}

	free(ht->buckets);
	ht->buckets = buckets;
	ht->size = new_size;
}

static void hashtable_insert(struct filter_hashtable *ht, struct filter_rule *rule)
{
	size_t bucket;

	if (ht->count >= ht->size - ht->size / 4)
		hashtable_grow(ht);

	bucket = rule->hash % ht->size;
	rule->next = ht->buckets[bucket];
	ht->buckets[bucket] = rule;
	ht->count++;
}

static struct filter_rule *hashtable_lookup(struct filter_hashtable *ht,
                                            const char *domain)
{
	if (!ht)
		return NULL;

	uint32_t hash = hash_string(domain);
	size_t bucket = hash % ht->size;
	struct filter_rule *rule;

	for (rule = ht->buckets[bucket]; rule; rule = rule->next) {
		if (rule->hash == hash && domain_match_exact(domain, rule->pattern))
			return rule;
	}

	return NULL;
}

int filter_init(struct filter_ctx *ctx)
{
	if (!ctx)
		return -1;

	memset(ctx, 0, sizeof(*ctx));

	ctx->exact_ht = hashtable_create(HASHTABLE_INITIAL_SIZE);
	ctx->suffix_ht = hashtable_create(HASHTABLE_INITIAL_SIZE);
	if (!ctx->exact_ht || !ctx->suffix_ht) {
		hashtable_destroy(ctx->exact_ht);
		hashtable_destroy(ctx->suffix_ht);
		memset(ctx, 0, sizeof(*ctx));
		udns_set_error("Out of memory");
		return -1;
	}

	return 0;
}

static void hashtable_clear(struct filter_hashtable *ht)
{
	size_t i;

	if (!ht)
		return;

	for (i = 0; i < ht->size; i++) {
		rule_list_free(ht->buckets[i]);
		ht->buckets[i] = NULL;
	}
	ht->count = 0;
}

void filter_cleanup(struct filter_ctx *ctx)
{
	if (!ctx)
		return;

	hashtable_destroy(ctx->exact_ht);
	hashtable_destroy(ctx->suffix_ht);

	memset(ctx, 0, sizeof(*ctx));
}

void filter_clear(struct filter_ctx *ctx)
{
	if (!ctx)
		return;

	hashtable_clear(ctx->exact_ht);
	hashtable_clear(ctx->suffix_ht);
	ctx->total_count = 0;
}

int filter_add_rule(struct filter_ctx *ctx, const char *pattern)
{
	struct filter_rule *rule;
	enum filter_rule_type type;
	char *clean_pattern;

	if (!ctx || !pattern || !*pattern)
		return -1;

	/* The exported module ABI can reach this before socket_create() has run
	 * filter_init(); refuse rather than dereference a NULL hashtable. */
	if (!ctx->exact_ht || !ctx->suffix_ht) {
		udns_set_error("Filter not initialised");
		return -1;
	}

	size_t pattern_len = strlen(pattern);

	/* Both ||domain^ and *.domain block the base domain and everything
	 * below it, so they share the suffix table keyed by base domain. */
	if (strncmp(pattern, "||", 2) == 0 && pattern_len > 3 && pattern[pattern_len - 1] == '^') {
		clean_pattern = strndup(pattern + 2, pattern_len - 3);
		type = FILTER_SUBDOMAIN;
	} else if (pattern[0] == '*') {
		const char *base = pattern + 1;

		if (*base == '.')
			base++;
		if (!*base) {
			udns_set_error("Invalid wildcard pattern");
			return -1;
		}
		clean_pattern = strdup(base);
		type = FILTER_WILDCARD;
	} else {
		clean_pattern = strdup(pattern);
		type = FILTER_EXACT;
	}

	if (!clean_pattern) {
		udns_set_error("Out of memory");
		return -1;
	}

	struct filter_hashtable *ht = (type == FILTER_EXACT) ? ctx->exact_ht : ctx->suffix_ht;

	if (hashtable_lookup(ht, clean_pattern)) {
		free(clean_pattern);
		return 1;
	}

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		free(clean_pattern);
		udns_set_error("Out of memory");
		return -1;
	}

	rule->pattern = clean_pattern;
	rule->hash = hash_string(clean_pattern);
	rule->type = type;

	hashtable_insert(ht, rule);
	ctx->total_count++;

	return 0;
}

int filter_load_file(struct filter_ctx *ctx, const char *path)
{
	FILE *f;
	char line[512];
	int count = 0;

	if (!ctx || !path)
		return -1;

	f = fopen(path, "r");
	if (!f) {
		udns_set_error("Failed to open %s", path);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		size_t line_len = strlen(line);

		if (udns_security.max_filter_rules &&
		    ctx->total_count >= udns_security.max_filter_rules) {
			udns_set_error("Filter rule limit reached");
			fprintf(stderr, "Filter rule limit (%u) reached loading %s\n",
			        udns_security.max_filter_rules, path);
			break;
		}

		/* Skip overly long lines */
		if (line_len > 0 && line[line_len - 1] != '\n' && !feof(f)) {
			int c;
			while ((c = fgetc(f)) != EOF && c != '\n')
				;
			continue;
		}

		/* Skip leading whitespace */
		while (*p && isspace(*p))
			p++;

		/* Skip empty lines and comments */
		if (*p == '\0' || *p == '#' || *p == '!')
			continue;

		/* Strip hosts file IP addresses */
		if (strncmp(p, "0.0.0.0 ", 8) == 0)
			p += 8;
		else if (strncmp(p, "127.0.0.1 ", 10) == 0)
			p += 10;
		else if (strncmp(p, ":: ", 3) == 0)
			p += 3;

		/* Strip trailing whitespace */
		size_t len = strlen(p);
		while (len > 0 && isspace(p[len - 1]))
			p[--len] = '\0';

		if (*p && filter_add_rule(ctx, p) == 0)
			count++;
	}

	fclose(f);

	return count;
}

bool filter_match(struct filter_ctx *ctx, const char *domain, struct filter_rule **matched)
{
	struct filter_rule *rule;
	const char *suffix;

	if (!ctx || !domain)
		return false;

	rule = hashtable_lookup(ctx->exact_ht, domain);

	/* Suffix rules match the base domain and every label boundary above it */
	for (suffix = domain; !rule && suffix; ) {
		rule = hashtable_lookup(ctx->suffix_ht, suffix);
		suffix = strchr(suffix, '.');
		if (suffix)
			suffix++;
	}

	if (!rule)
		return false;

	if (matched)
		*matched = rule;

	return true;
}

void filter_stats(struct filter_ctx *ctx, size_t *count)
{
	if (!ctx || !count)
		return;

	*count = ctx->total_count;
}
