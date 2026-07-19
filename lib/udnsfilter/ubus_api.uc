'use strict';

import * as ubus from 'ubus';
import * as udnsfilter from 'udnsfilter';
import * as filter from 'udnsfilter.filter';
import * as tracking from 'udnsfilter.tracking';

let conn;
let obj;

export function publish(config) {
	conn = ubus.connect();
	if (!conn)
		return false;

	obj = conn.publish('udnsfilter', {
		stats: {
			call: function(req) {
				let c_stats = udnsfilter.stats_get();
				return {
					total_queries: c_stats.total_queries || 0,
					blocked_queries: c_stats.blocked_queries || 0,
					allowed_queries: c_stats.allowed_queries || 0,
					forwarded_queries: c_stats.forwarded_queries || 0,
					upstream_errors: c_stats.upstream_errors || 0
				};
			},
			args: {}
		},
		reinit: {
			call: function(req) {
				if (!udnsfilter.reinit())
					return { success: false, error: "ares_reinit failed" };

				return { success: true };
			},
			args: {}
		},
		servers: {
			call: function(req) {
				return udnsfilter.get_server_states();
			},
			args: {}
		},
		reload_filter: {
			call: function(req) {
				if (!config.filter_enabled)
					return { success: false, error: "filtering not enabled" };

				let result = filter.load(config.confdir);
				if (!result)
					return { success: false, error: "failed to load filter lists" };

				return {
					success: true,
					rules_loaded: result.total_rules,
					filters: result.loaded_filters
				};
			},
			args: {}
		},
		reset_stats: {
			call: function(req) {
				udnsfilter.stats_reset();
				return { success: true };
			},
			args: {}
		},
		filters: {
			call: function(req) {
				return filter.status() ?? {};
			},
			args: {}
		},
		tracking: {
			call: function(req) {
				let ip = req.args?.ip;
				let enable = req.args?.enable;

				if (!ip)
					return tracking.tracked();

				if (enable) {
					if (!tracking.track(ip))
						return { success: false, error: "too many tracked addresses" };
					return { success: true, tracking: ip };
				}

				tracking.untrack(ip);
				return { success: true, stopped: ip };
			},
			args: {
				ip: "127.0.0.1",
				enable: true
			}
		},
		domains: {
			call: function(req) {
				return tracking.domains();
			},
			args: {}
		}
	});

	return obj != null;
};

export function cleanup() {
	if (obj)
		obj.remove();
	if (conn)
		conn.disconnect();
};
