/*
 * callback.c - ucode callback invocation for udnsfilter
 *
 * This file handles invocation of ucode callback functions when DNS
 * queries are received. It converts C structures to ucode values and
 * safely calls the registered callback function.
 */

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "internal.h"

/**
 * udns_callback_query() - Invoke ucode query callback
 * @pkt: Parsed DNS packet
 * @client_addr: Client address
 * @client_addrlen: Address length
 * @raw_data: Raw packet data
 * @raw_len: Raw data length
 *
 * Constructs ucode objects for the packet and client information,
 * then invokes the registered query callback function.
 */
void udns_callback_query(struct dns_packet *pkt, struct sockaddr_storage *client_addr,
                         socklen_t client_addrlen, const uint8_t *raw_data, size_t raw_len,
                         uint32_t tcp_conn_id)
{
	uc_value_t *pkt_obj, *client_obj, *questions_array, *raw_data_val;
	struct dns_question question;
	char addr_str[INET6_ADDRSTRLEN];

	if (!global_ctx.on_query || !global_ctx.vm || !pkt)
		return;

	pkt_obj = ucv_object_new(global_ctx.vm);
	if (!pkt_obj)
		return;

	ucv_object_add(pkt_obj, "id", ucv_int64_new(pkt->id));
	ucv_object_add(pkt_obj, "flags", ucv_int64_new(pkt->flags));

	raw_data_val = ucv_string_new_length((const char *)raw_data, raw_len);
	ucv_object_add(pkt_obj, "raw_data", raw_data_val);

	questions_array = ucv_array_new(global_ctx.vm);
	if (pkt->qdcount > 0) {
		if (packet_parse_question(pkt, &question) == 0) {
			uc_value_t *q_obj = ucv_object_new(global_ctx.vm);
			ucv_object_add(q_obj, "name", ucv_string_new(question.name));
			ucv_object_add(q_obj, "type", ucv_int64_new(question.qtype));
			ucv_object_add(q_obj, "class", ucv_int64_new(question.qclass));
			ucv_array_push(questions_array, q_obj);
		} else {
			ucv_object_add(pkt_obj, "parse_error", ucv_string_new(udns_get_error()));
		}
	}
	ucv_object_add(pkt_obj, "questions", questions_array);

	client_obj = ucv_object_new(global_ctx.vm);
	if (!client_obj) {
		ucv_put(pkt_obj);
		return;
	}

	if (client_addr->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)client_addr;
		inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
		ucv_object_add(client_obj, "address", ucv_string_new(addr_str));
		ucv_object_add(client_obj, "port", ucv_int64_new(ntohs(sin->sin_port)));
		ucv_object_add(client_obj, "family", ucv_string_new("inet"));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)client_addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
		ucv_object_add(client_obj, "address", ucv_string_new(addr_str));
		ucv_object_add(client_obj, "port", ucv_int64_new(ntohs(sin6->sin6_port)));
		ucv_object_add(client_obj, "family", ucv_string_new("inet6"));
	}

	ucv_object_add(client_obj, "transport", ucv_string_new(tcp_conn_id ? "tcp" : "udp"));
	if (tcp_conn_id)
		ucv_object_add(client_obj, "conn", ucv_uint64_new(tcp_conn_id));

	uc_vm_stack_push(global_ctx.vm, ucv_get(global_ctx.on_query));
	uc_vm_stack_push(global_ctx.vm, ucv_get(pkt_obj));
	uc_vm_stack_push(global_ctx.vm, ucv_get(client_obj));

	if (uc_vm_call(global_ctx.vm, false, 2) == EXCEPTION_NONE) {
		uc_value_t *rv = uc_vm_stack_pop(global_ctx.vm);
		ucv_put(rv);
	}

	ucv_put(pkt_obj);
	ucv_put(client_obj);
}
