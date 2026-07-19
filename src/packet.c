/*
 * packet.c - DNS packet parsing and building for udnsfilter
 *
 * Adapted from umdnsd packet.c by John Crispin
 * Copyright (C) 2024 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This file provides DNS packet parsing and building functionality using
 * c-ares library APIs. It handles DNS name compression, packet validation,
 * and construction of various DNS responses.
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <stdio.h>
#include <ares.h>

#include "udnsfilter.h"

static char error_buf[256] = {0};

/**
 * udns_set_error() - Set error message
 * @fmt: printf-style format string
 *
 * Sets the global error message for retrieval by udns_get_error().
 */
void udns_set_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(error_buf, sizeof(error_buf), fmt, ap);
	va_end(ap);
}

/**
 * udns_get_error() - Get last error message
 *
 * Return: Pointer to error message string
 */
const char *udns_get_error(void)
{
	return error_buf;
}

/**
 * scan_name_length() - Calculate wire-format length of DNS name
 * @data: Packet data
 * @len: Packet length
 * @offset: Starting offset of name
 *
 * Calculates the number of bytes occupied by a DNS name in wire format.
 * A compression pointer terminates the name, so no pointer chasing is
 * needed; dn_expand() performs the actual decompression with its own
 * loop protection.
 *
 * Return: Length in bytes, or -1 on error
 */
static int scan_name_length(const uint8_t *data, size_t len, size_t offset)
{
	size_t pos = offset;

	while (pos < len) {
		uint8_t label_len = data[pos];

		if (label_len == 0)
			return pos - offset + 1;

		if ((label_len & 0xc0) == 0xc0) {
			if (pos + 1 >= len)
				return -1;
			return pos - offset + 2;
		}

		if (label_len > DNS_MAX_LABEL_LENGTH)
			return -1;

		pos += label_len + 1;
	}

	return -1;
}

/**
 * parse_name() - Parse DNS name from wire format
 * @base: Start of packet data
 * @base_len: Total packet length
 * @ptr: Pointer to current position (updated)
 * @remaining: Bytes remaining (updated)
 *
 * Parses a DNS name from wire format, handling compression pointers.
 * Uses dn_expand() for decompression.
 *
 * Return: Allocated string containing the name, or NULL on error
 */
static char *parse_name(const uint8_t *base, size_t base_len, const uint8_t **ptr, size_t *remaining)
{
	char name_buf[DNS_MAX_NAME_LENGTH + 1];
	int name_len;
	int wire_len;
	size_t offset;

	if (*ptr < base || *ptr >= base + base_len) {
		udns_set_error("Pointer outside packet bounds");
		return NULL;
	}

	offset = *ptr - base;
	wire_len = scan_name_length(base, base_len, offset);
	if (wire_len < 0) {
		udns_set_error("Invalid DNS name");
		return NULL;
	}

	if ((size_t)wire_len > *remaining) {
		udns_set_error("Name exceeds packet bounds");
		return NULL;
	}

	if (*ptr + wire_len > base + base_len) {
		udns_set_error("Name extends beyond packet");
		return NULL;
	}

	name_len = dn_expand(base, base + base_len, *ptr, name_buf, sizeof(name_buf));
	if (name_len < 0) {
		udns_set_error("Failed to expand DNS name");
		return NULL;
	}

	*ptr += wire_len;
	*remaining -= wire_len;

	char *result = strdup(name_buf);
	if (!result) {
		udns_set_error("Out of memory");
		return NULL;
	}

	return result;
}

/**
 * packet_parse_question() - Parse DNS question from packet
 * @pkt: Parsed packet structure
 * @q: Question structure to fill
 *
 * Extracts the first DNS question from a parsed packet, including
 * name, qtype, and qclass.
 *
 * Return: 0 on success, -1 on error
 */
int packet_parse_question(struct dns_packet *pkt, struct dns_question *q)
{
	const uint8_t *ptr;
	size_t remaining;
	char *name;
	uint16_t qtype, qclass;

	if (!pkt || !q || !pkt->data)
		return -1;

	ptr = pkt->data + sizeof(struct dns_header);
	remaining = pkt->len - sizeof(struct dns_header);

	/* Parse name */
	name = parse_name(pkt->data, pkt->len, &ptr, &remaining);
	if (!name)
		return -1;

	snprintf(q->name, sizeof(q->name), "%s", name);
	free(name);

	/* Parse qtype and qclass */
	if (remaining < 4) {
		udns_set_error("Truncated question");
		return -1;
	}

	memcpy(&qtype, ptr, 2);
	ptr += 2;
	memcpy(&qclass, ptr, 2);
	ptr += 2;
	remaining -= 4;

	q->qtype = ntohs(qtype);
	q->qclass = ntohs(qclass);

	return 0;
}

/**
 * packet_parse() - Parse DNS packet from wire format
 * @pkt: Packet structure to initialise
 * @data: Wire-format packet data
 * @len: Data length
 *
 * Parses a DNS packet header and stores the complete packet data for
 * later processing. The packet data is copied internally.
 *
 * Return: 0 on success, -1 on error
 */
int packet_parse(struct dns_packet *pkt, const uint8_t *data, size_t len)
{
	const struct dns_header *hdr;

	if (!pkt || !data || len < sizeof(struct dns_header)) {
		udns_set_error("Invalid packet");
		return -1;
	}

	if (len > DNS_MAX_QUERY_SIZE) {
		udns_set_error("Packet too large");
		return -1;
	}

	memset(pkt, 0, sizeof(*pkt));

	/* Parse header */
	hdr = (const struct dns_header *)data;
	pkt->id = ntohs(hdr->id);
	pkt->flags = ntohs(hdr->flags);
	pkt->qdcount = ntohs(hdr->questions);
	pkt->ancount = ntohs(hdr->answers);
	pkt->nscount = ntohs(hdr->authority);
	pkt->arcount = ntohs(hdr->additional);

	/* Store packet data for name decompression */
	pkt->data = malloc(len);
	if (!pkt->data) {
		udns_set_error("Out of memory");
		return -1;
	}

	memcpy(pkt->data, data, len);
	pkt->len = len;
	pkt->capacity = len;

	return 0;
}

/**
 * packet_build_nxdomain() - Build NXDOMAIN response
 * @response: Response packet structure to fill
 * @query: Original query packet
 *
 * Constructs a DNS NXDOMAIN (domain not found) response using c-ares APIs.
 *
 * Return: Response length on success, -1 on error
 */
int packet_build_nxdomain(struct dns_packet *response, const struct dns_packet *query)
{
	ares_dns_record_t *dnsrec = NULL;
	ares_status_t status;
	struct dns_question question;
	uint8_t *response_buf = NULL;
	size_t response_len = 0;

	if (!response || !query || !query->data || query->len < sizeof(struct dns_header))
		return -1;

	if (packet_parse_question((struct dns_packet *)query, &question) < 0) {
		udns_set_error("Failed to parse question");
		return -1;
	}

	status = ares_dns_record_create(&dnsrec, query->id,
	                                 ARES_FLAG_QR | ARES_FLAG_RD | ARES_FLAG_RA,
	                                 ARES_OPCODE_QUERY, ARES_RCODE_NXDOMAIN);
	if (status != ARES_SUCCESS) {
		udns_set_error("Failed to create DNS record: %s", ares_strerror(status));
		return -1;
	}

	status = ares_dns_record_query_add(dnsrec, question.name,
	                                    (ares_dns_rec_type_t)question.qtype,
	                                    (ares_dns_class_t)question.qclass);
	if (status != ARES_SUCCESS) {
		udns_set_error("Failed to add query: %s", ares_strerror(status));
		ares_dns_record_destroy(dnsrec);
		return -1;
	}

	status = ares_dns_write(dnsrec, &response_buf, &response_len);
	ares_dns_record_destroy(dnsrec);

	if (status != ARES_SUCCESS) {
		udns_set_error("Failed to write DNS record: %s", ares_strerror(status));
		return -1;
	}

	if (response->capacity < response_len) {
		response->data = realloc(response->data, response_len);
		if (!response->data) {
			ares_free_string(response_buf);
			udns_set_error("Out of memory");
			return -1;
		}
		response->capacity = response_len;
	}

	memcpy(response->data, response_buf, response_len);
	response->len = response_len;
	ares_free_string(response_buf);

	return response->len;
}

/**
 * packet_build_servfail() - Build SERVFAIL response
 * @response: Response packet structure to fill
 * @query_id: Query ID to use in response
 *
 * Constructs a DNS SERVFAIL (server failure) response with minimal header.
 *
 * Return: 0 on success, -1 on error
 */
int packet_build_servfail(struct dns_packet *response, uint16_t query_id)
{
	uint8_t *buf;
	struct dns_header *hdr;

	if (!response)
		return -1;

	buf = malloc(sizeof(struct dns_header));
	if (!buf) {
		udns_set_error("Out of memory");
		return -1;
	}

	memset(response, 0, sizeof(*response));

	hdr = (struct dns_header *)buf;
	hdr->id = htons(query_id);
	hdr->flags = htons(DNS_FLAGS_RESPONSE_SERVFAIL);
	hdr->questions = htons(0);
	hdr->answers = htons(0);
	hdr->authority = htons(0);
	hdr->additional = htons(0);

	response->data = buf;
	response->len = sizeof(struct dns_header);
	response->capacity = sizeof(struct dns_header);

	return 0;
}

/**
 * packet_build_null_response() - Build response with null IP address
 * @response: Response packet structure to fill
 * @query: Original query packet
 *
 * Constructs a DNS response with a null IP address (0.0.0.0) for A queries.
 * Used to block domains whilst providing a response.
 *
 * Return: Response length on success, -1 on error
 */
int packet_build_null_response(struct dns_packet *response, const struct dns_packet *query)
{
	ares_dns_record_t *dnsrec = NULL;
	ares_dns_rr_t *rr = NULL;
	ares_status_t status;
	struct dns_question question;
	uint8_t *response_buf = NULL;
	size_t response_len = 0;
	struct in_addr null_addr;

	if (!response || !query || !query->data || query->len < sizeof(struct dns_header))
		return -1;

	if (packet_parse_question((struct dns_packet *)query, &question) < 0) {
		udns_set_error("Failed to parse question");
		return -1;
	}

	status = ares_dns_record_create(&dnsrec, query->id,
	                                 ARES_FLAG_QR | ARES_FLAG_RD | ARES_FLAG_RA,
	                                 ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
	if (status != ARES_SUCCESS) {
		udns_set_error("Failed to create DNS record: %s", ares_strerror(status));
		return -1;
	}

	status = ares_dns_record_query_add(dnsrec, question.name,
	                                    (ares_dns_rec_type_t)question.qtype,
	                                    (ares_dns_class_t)question.qclass);
	if (status != ARES_SUCCESS) {
		udns_set_error("Failed to add query: %s", ares_strerror(status));
		ares_dns_record_destroy(dnsrec);
		return -1;
	}

	if (question.qtype == DNS_TYPE_A) {
		null_addr.s_addr = 0;

		status = ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
		                                 question.name, ARES_REC_TYPE_A,
		                                 ARES_CLASS_IN, 10);
		if (status != ARES_SUCCESS) {
			udns_set_error("Failed to add RR: %s", ares_strerror(status));
			ares_dns_record_destroy(dnsrec);
			return -1;
		}

		status = ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &null_addr);
		if (status != ARES_SUCCESS) {
			udns_set_error("Failed to set address: %s", ares_strerror(status));
			ares_dns_record_destroy(dnsrec);
			return -1;
		}
	}

	status = ares_dns_write(dnsrec, &response_buf, &response_len);
	ares_dns_record_destroy(dnsrec);

	if (status != ARES_SUCCESS) {
		udns_set_error("Failed to write DNS record: %s", ares_strerror(status));
		return -1;
	}

	if (response->capacity < response_len) {
		response->data = realloc(response->data, response_len);
		if (!response->data) {
			ares_free_string(response_buf);
			udns_set_error("Out of memory");
			return -1;
		}
		response->capacity = response_len;
	}

	memcpy(response->data, response_buf, response_len);
	response->len = response_len;
	ares_free_string(response_buf);

	return response->len;
}

/**
 * packet_build_truncated() - Build a TC response from the original query
 * @response: Response packet structure to fill
 * @query: Wire-format client query
 * @query_len: Query length
 *
 * Builds a header-plus-question response with the TC bit set, telling
 * the client to retry over TCP because the full answer exceeds its
 * advertised UDP payload size.
 *
 * Return: 0 on success, -1 on error
 */
int packet_build_truncated(struct dns_packet *response, const uint8_t *query, size_t query_len)
{
	struct dns_header *hdr;
	uint16_t qdcount;
	size_t len;

	if (!response || !query || query_len < sizeof(struct dns_header))
		return -1;

	qdcount = ntohs(((const struct dns_header *)query)->questions);
	len = sizeof(struct dns_header);

	for (uint16_t i = 0; i < qdcount; i++) {
		int qname_len = scan_name_length(query, query_len, len);

		if (qname_len < 0 || len + qname_len + 4 > query_len)
			return -1;
		len += qname_len + 4;
	}

	memset(response, 0, sizeof(*response));

	response->data = malloc(len);
	if (!response->data) {
		udns_set_error("Out of memory");
		return -1;
	}

	memcpy(response->data, query, len);
	response->len = len;
	response->capacity = len;

	hdr = (struct dns_header *)response->data;
	hdr->flags = htons(DNS_FLAG_QR | DNS_FLAG_TC | DNS_FLAG_RD | DNS_FLAG_RA);
	hdr->answers = 0;
	hdr->authority = 0;
	hdr->additional = 0;

	return 0;
}

/**
 * packet_build() - Build DNS packet into wire format
 * @pkt: Packet structure with data
 * @buf: Output buffer
 * @buflen: Buffer size
 *
 * Copies the packet data into the provided buffer for transmission.
 *
 * Return: Packet length on success, -1 on error
 */
int packet_build(struct dns_packet *pkt, uint8_t *buf, size_t buflen)
{
	if (!pkt || !pkt->data || !buf || buflen < pkt->len)
		return -1;

	memcpy(buf, pkt->data, pkt->len);
	return pkt->len;
}

/**
 * qtype_to_string() - Convert DNS query type to string
 * @qtype: DNS query type constant
 *
 * Return: String representation of query type
 */
const char *qtype_to_string(uint16_t qtype)
{
	switch (qtype) {
	case DNS_TYPE_A:     return "A";
	case DNS_TYPE_NS:    return "NS";
	case DNS_TYPE_CNAME: return "CNAME";
	case DNS_TYPE_SOA:   return "SOA";
	case DNS_TYPE_PTR:   return "PTR";
	case DNS_TYPE_MX:    return "MX";
	case DNS_TYPE_TXT:   return "TXT";
	case DNS_TYPE_AAAA:  return "AAAA";
	case DNS_TYPE_SRV:   return "SRV";
	default:             return "UNKNOWN";
	}
}
