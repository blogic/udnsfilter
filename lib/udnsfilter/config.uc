'use strict';

import * as uci from 'uci';

function config_bool(value, fallback) {
	if (value == null)
		return fallback;

	return value == '1' || value == 'true' || value == 'on' || value == 'yes';
}

function config_list(value, fallback) {
	if (type(value) == 'array')
		return value;
	if (type(value) == 'string')
		return [ value ];

	return fallback;
}

function config_uint(value, fallback) {
	if (value == null)
		return fallback;

	let n = int(value);
	if (type(n) != 'int' || n < 0)
		return fallback;

	return n;
}

export function load(confdir) {
	let config = {
		listen_addr: '0.0.0.0',
		listen_addr6: '::',
		listen_port: 53,
		upstream_servers: [ 'dns://8.8.8.8' ],
		bootstrap: null,
		filter_enabled: true,
		rotation: true,
		cache_ttl: 3600,
		verbose: false,
		rebind_protection: true,
		rebind_domains: [],
		confdir: confdir,
		security: {
			block_any: true,
			dns0x20: false,
			ratelimit: 100,
			ratelimit_burst: 300,
			ratelimit_global: 1000,
			ratelimit_global_burst: 2000,
			max_pending: 2048,
			max_filter_rules: 262144,
			max_tcp_per_client: 8,
		},
	};

	let cursor = uci.cursor(confdir);

	if (!cursor || !cursor.load('dns'))
		return config;

	let main = cursor.get_all('dns', 'main');
	if (!main)
		return config;

	config.listen_addr = main.listen_addr ?? config.listen_addr;
	config.listen_addr6 = main.listen_addr6 ?? config.listen_addr6;
	config.listen_port = int(main.listen_port ?? config.listen_port);
	config.bootstrap = main.bootstrap;
	config.cache_ttl = int(main.cache_ttl ?? config.cache_ttl);
	config.rotation = config_bool(main.rotation, config.rotation);
	config.filter_enabled = config_bool(main.filter, config.filter_enabled);
	config.verbose = config_bool(main.verbose, config.verbose);
	config.rebind_protection = config_bool(main.rebind_protection, config.rebind_protection);
	config.upstream_servers = config_list(main.upstream, config.upstream_servers);
	config.rebind_domains = config_list(main.rebind_domain, config.rebind_domains);

	let sec = config.security;
	sec.block_any = config_bool(main.block_any, sec.block_any);
	sec.dns0x20 = config_bool(main.dns0x20, sec.dns0x20);
	sec.ratelimit = config_uint(main.ratelimit, sec.ratelimit);
	sec.ratelimit_burst = config_uint(main.ratelimit_burst, sec.ratelimit_burst);
	sec.ratelimit_global = config_uint(main.ratelimit_global, sec.ratelimit_global);
	sec.ratelimit_global_burst = config_uint(main.ratelimit_global_burst, sec.ratelimit_global_burst);
	sec.max_pending = config_uint(main.max_pending, sec.max_pending);
	sec.max_filter_rules = config_uint(main.max_filter_rules, sec.max_filter_rules);
	sec.max_tcp_per_client = config_uint(main.max_tcp_per_client, sec.max_tcp_per_client);

	return config;
};
