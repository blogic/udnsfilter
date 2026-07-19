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

	return config;
};
