'use strict';

const DOMAIN_MAP_MAX = 4096;
const TRACKED_IPS_MAX = 32;

let tracked_ips = {};
let global_domains = { replied: {}, blocked: {} };

function domain_count(owner, key, domain) {
	let map = owner[key];

	/* Reset a full map instead of evicting: these are diagnostic
	 * counters and a per-query scan under a random-subdomain flood
	 * would cost more than the history is worth. */
	if (map[domain] == null && length(map) >= DOMAIN_MAP_MAX)
		map = owner[key] = {};

	if (!map[domain])
		map[domain] = 0;
	map[domain]++;
}

export function domain_hit(kind, client_ip, domain) {
	domain_count(global_domains, kind, domain);
	if (tracked_ips[client_ip])
		domain_count(tracked_ips[client_ip], kind, domain);
};

export function track(ip) {
	if (!tracked_ips[ip]) {
		if (length(tracked_ips) >= TRACKED_IPS_MAX)
			return false;
		tracked_ips[ip] = { replied: {}, blocked: {} };
	}

	return true;
};

export function untrack(ip) {
	delete tracked_ips[ip];
};

export function tracked() {
	return tracked_ips;
};

export function domains() {
	return global_domains;
};
