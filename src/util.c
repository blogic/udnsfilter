/*
 * util.c - Utility functions
 *
 * This file provides utility functions for string hashing, domain name
 * matching, and private IP address detection for DNS rebinding protection.
 */

#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "udnsfilter.h"

/**
 * hash_string() - Compute djb2 hash of string
 * @str: String to hash
 *
 * Case-insensitive hash function for domain names.
 *
 * Return: 32-bit hash value
 */
uint32_t hash_string(const char *str)
{
	uint32_t hash = 5381;
	int c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + tolower(c);  /* Case-insensitive */

	return hash;
}

/**
 * domain_match_exact() - Test for exact domain match
 * @domain: Domain to test
 * @pattern: Pattern to match against
 *
 * Case-insensitive exact match.
 *
 * Return: true if match, false otherwise
 */
bool domain_match_exact(const char *domain, const char *pattern)
{
	return strcasecmp(domain, pattern) == 0;
}

/**
 * domain_match_subdomain() - Test for domain or subdomain match
 * @domain: Domain to test
 * @pattern: Base domain pattern
 *
 * Matches both exact domain and all subdomains (e.g., pattern "example.com"
 * matches "example.com" and "www.example.com").
 *
 * Return: true if match, false otherwise
 */
bool domain_match_subdomain(const char *domain, const char *pattern)
{
	size_t domain_len = strlen(domain);
	size_t pattern_len = strlen(pattern);

	/* Exact match: example.com matches example.com */
	if (strcasecmp(domain, pattern) == 0)
		return true;

	/* Subdomain match: www.example.com matches example.com */
	if (domain_len > pattern_len) {
		const char *suffix = domain + (domain_len - pattern_len);
		/* Check for leading dot and matching suffix */
		if (suffix[-1] == '.' && strcasecmp(suffix, pattern) == 0)
			return true;
	}

	return false;
}

/**
 * domain_match_wildcard() - Match wildcard pattern
 * @domain: Domain to test
 * @pattern: Wildcard pattern (e.g., "*.example.com")
 *
 * Return: true if match, false otherwise
 */
bool domain_match_wildcard(const char *domain, const char *pattern)
{
	/* Simple wildcard matching */
	if (pattern[0] != '*')
		return domain_match_exact(domain, pattern);

	/* Skip the * and optional . */
	pattern++;
	if (*pattern == '.')
		pattern++;

	/* Match as subdomain */
	return domain_match_subdomain(domain, pattern);
}

/**
 * is_private_ipv4() - Check if IPv4 address is private
 * @ip: IPv4 address in host byte order
 *
 * Tests for RFC1918 private addresses, loopback, link-local, and multicast.
 *
 * Return: true if private, false otherwise
 */
bool is_private_ipv4(uint32_t ip)
{
	uint8_t a = (ip >> 24) & 0xff;
	uint8_t b = (ip >> 16) & 0xff;

	if (a == 10)
		return true;
	if (a == 172 && b >= 16 && b <= 31)
		return true;
	if (a == 192 && b == 168)
		return true;
	if (a == 127)
		return true;
	if (a == 0)
		return true;
	if (a == 169 && b == 254)
		return true;
	if (a >= 224)
		return true;

	return false;
}

/**
 * is_private_ipv6() - Check if IPv6 address is private
 * @ip: IPv6 address bytes
 *
 * Tests for link-local, site-local, ULA, loopback, and multicast addresses.
 *
 * Return: true if private, false otherwise
 */
bool is_private_ipv6(const uint8_t *ip)
{
	if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80)
		return true;
	if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0xc0)
		return true;
	if (ip[0] == 0xfc || ip[0] == 0xfd)
		return true;

	bool all_zero = true;
	for (int i = 0; i < 15; i++) {
		if (ip[i] != 0) {
			all_zero = false;
			break;
		}
	}
	if (all_zero && (ip[15] == 0 || ip[15] == 1))
		return true;

	if (ip[0] == 0xff)
		return true;

	return false;
}

/**
 * dns_response_contains_private_ip() - Check DNS response for private IPs
 * @response: DNS response packet
 * @len: Packet length
 *
 * Scans DNS answer section for A and AAAA records containing private
 * IP addresses. Used for DNS rebinding attack protection.
 *
 * Return: true if private IP found, false otherwise
 */
bool dns_response_contains_private_ip(const uint8_t *response, size_t len)
{
	const struct dns_header *hdr;
	const uint8_t *ptr;
	uint16_t ancount;
	size_t remaining;

	if (!response || len < sizeof(struct dns_header))
		return false;

	hdr = (const struct dns_header *)response;
	ancount = ntohs(hdr->answers);

	if (ancount == 0)
		return false;

	ptr = response + sizeof(struct dns_header);
	remaining = len - sizeof(struct dns_header);

	/* Skip question section name */
	while (remaining > 0 && *ptr != 0) {
		uint8_t label_len = *ptr;
		if ((label_len & 0xc0) == 0xc0) {
			if (remaining < 2)
				return false;
			ptr += 2;
			remaining -= 2;
			break;
		}
		if (label_len > DNS_MAX_LABEL_LENGTH || remaining < (size_t)(label_len + 1))
			return false;
		ptr += label_len + 1;
		remaining -= label_len + 1;
	}

	/* Skip null terminator */
	if (remaining > 0 && *ptr == 0) {
		ptr++;
		remaining--;
	}

	/* Skip qtype and qclass */
	if (remaining < 4)
		return false;
	ptr += 4;
	remaining -= 4;

	/* Scan answer section for private IPs */
	for (uint16_t i = 0; i < ancount && remaining >= 12; i++) {
		/* Skip answer name */
		while (remaining > 0 && *ptr != 0) {
			uint8_t label_len = *ptr;
			if ((label_len & 0xc0) == 0xc0) {
				if (remaining < 2)
					return false;
				ptr += 2;
				remaining -= 2;
				break;
			}
			if (label_len > DNS_MAX_LABEL_LENGTH || remaining < (size_t)(label_len + 1))
				return false;
			ptr += label_len + 1;
			remaining -= label_len + 1;
		}

		if (remaining > 0 && *ptr == 0) {
			ptr++;
			remaining--;
		}

		if (remaining < 10)
			return false;

		/* Extract rtype and rdlength */
		uint16_t rtype = (ptr[0] << 8) | ptr[1];
		uint16_t rdlength = (ptr[8] << 8) | ptr[9];

		ptr += 10;
		remaining -= 10;

		if (remaining < rdlength)
			return false;

		/* Check A records for private IPv4 */
		if (rtype == DNS_TYPE_A && rdlength == 4) {
			uint32_t ip = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
			if (is_private_ipv4(ip))
				return true;
		}
		/* Check AAAA records for private IPv6 */
		else if (rtype == DNS_TYPE_AAAA && rdlength == 16) {
			if (is_private_ipv6(ptr))
				return true;
		}

		ptr += rdlength;
		remaining -= rdlength;
	}

	return false;
}
