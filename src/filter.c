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

static void hashtable_destroy(struct filter_hashtable *ht)
{
	size_t i;

	if (!ht)
		return;

	for (i = 0; i < ht->size; i++) {
		struct filter_rule *rule = ht->buckets[i];
		while (rule) {
			struct filter_rule *next = rule->next;
			free(rule->pattern);
			free(rule);
			rule = next;
		}
	}

	free(ht->buckets);
	free(ht);
}

static void hashtable_insert(struct filter_hashtable *ht, struct filter_rule *rule)
{
	size_t bucket = rule->hash % ht->size;

	rule->next = ht->buckets[bucket];
	ht->buckets[bucket] = rule;
	ht->count++;
}

static struct filter_rule *hashtable_lookup(struct filter_hashtable *ht,
                                            const char *domain)
{
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
	if (!ctx->exact_ht) {
		udns_set_error("Out of memory");
		return -1;
	}

	return 0;
}

void filter_cleanup(struct filter_ctx *ctx)
{
	struct filter_rule *rule, *next;

	if (!ctx)
		return;

	hashtable_destroy(ctx->exact_ht);

	for (rule = ctx->subdomain_rules; rule; rule = next) {
		next = rule->next;
		free(rule->pattern);
		free(rule);
	}

	for (rule = ctx->wildcard_rules; rule; rule = next) {
		next = rule->next;
		free(rule->pattern);
		free(rule);
	}

	memset(ctx, 0, sizeof(*ctx));
}

int filter_add_rule(struct filter_ctx *ctx, const char *pattern)
{
	struct filter_rule *rule;
	enum filter_rule_type type;
	char *clean_pattern = NULL;

	if (!ctx || !pattern || !*pattern)
		return -1;

	size_t pattern_len = strlen(pattern);

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		udns_set_error("Out of memory");
		return -1;
	}

	if (strncmp(pattern, "||", 2) == 0 && pattern_len > 2 && pattern[pattern_len - 1] == '^') {
		if (pattern_len < 3) {
			udns_set_error("Invalid subdomain pattern");
			free(rule);
			return -1;
		}
		clean_pattern = strndup(pattern + 2, pattern_len - 3);
		if (!clean_pattern) {
			udns_set_error("Out of memory");
			free(rule);
			return -1;
		}
		type = FILTER_SUBDOMAIN;
	} else if (pattern[0] == '*') {
		clean_pattern = strdup(pattern);
		if (!clean_pattern) {
			udns_set_error("Out of memory");
			free(rule);
			return -1;
		}
		type = FILTER_WILDCARD;
	} else {
		clean_pattern = strdup(pattern);
		if (!clean_pattern) {
			udns_set_error("Out of memory");
			free(rule);
			return -1;
		}
		type = FILTER_EXACT;
	}

	rule->pattern = clean_pattern;
	rule->hash = hash_string(clean_pattern);
	rule->type = type;
	rule->next = NULL;

	switch (type) {
	case FILTER_EXACT:
		hashtable_insert(ctx->exact_ht, rule);
		break;
	case FILTER_SUBDOMAIN:
		rule->next = ctx->subdomain_rules;
		ctx->subdomain_rules = rule;
		ctx->subdomain_count++;
		break;
	case FILTER_WILDCARD:
		rule->next = ctx->wildcard_rules;
		ctx->wildcard_rules = rule;
		ctx->wildcard_count++;
		break;
	}

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

		if (line_len > 0 && line[line_len - 1] != '\n' && !feof(f)) {
			int c;
			while ((c = fgetc(f)) != EOF && c != '\n')
				;
			continue;
		}

		while (*p && isspace(*p))
			p++;

		if (*p == '\0' || *p == '#' || *p == '!')
			continue;

		if (strncmp(p, "0.0.0.0 ", 8) == 0)
			p += 8;
		else if (strncmp(p, "127.0.0.1 ", 10) == 0)
			p += 10;
		else if (strncmp(p, ":: ", 3) == 0)
			p += 3;

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

	if (!ctx || !domain)
		return false;

	rule = hashtable_lookup(ctx->exact_ht, domain);
	if (rule) {
		if (matched)
			*matched = rule;
		return true;
	}

	for (rule = ctx->subdomain_rules; rule; rule = rule->next) {
		if (domain_match_subdomain(domain, rule->pattern)) {
			if (matched)
				*matched = rule;
			return true;
		}
	}

	for (rule = ctx->wildcard_rules; rule; rule = rule->next) {
		if (domain_match_wildcard(domain, rule->pattern)) {
			if (matched)
				*matched = rule;
			return true;
		}
	}

	return false;
}

void filter_stats(struct filter_ctx *ctx, size_t *count)
{
	if (!ctx || !count)
		return;

	*count = ctx->total_count;
}
