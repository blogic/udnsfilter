'use strict';

import * as udnsfilter from 'udnsfilter';
import * as tracking from 'udnsfilter.tracking';

let config;

export function init(cfg) {
	config = cfg;
};

export function handle(packet, client) {
	if (!packet.questions || length(packet.questions) == 0)
		return;

	let domain = packet.questions[0].name;
	let client_ip = client.address;

	if (config.verbose)
		printf("Query from %s:%d: %s\n", client_ip, client.port, domain);

	if (config.filter_enabled && domain) {
		let result = udnsfilter.filter_match(domain);
		if (result && result.blocked) {
			if (config.verbose)
				printf("BLOCKED: %s (rule: %s)\n", domain, result.rule);

			tracking.domain_hit('blocked', client_ip, domain);
			udnsfilter.send_blocked_response(client, packet);
			return;
		}
	}

	tracking.domain_hit('replied', client_ip, domain);
	udnsfilter.forward_query(client, packet);
};
