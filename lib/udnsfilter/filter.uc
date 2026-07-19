'use strict';

import * as uci from 'uci';
import * as udnsfilter from 'udnsfilter';

let last_load;

export function lists(confdir) {
	let cursor = uci.cursor(confdir);
	let result = [];

	if (!cursor || !cursor.load('dns'))
		return null;

	cursor.foreach('dns', 'filter', function(section) {
		push(result, {
			section: section['.name'],
			name: section.name ?? section['.name'],
			url: section.url,
			path: section.path,
			enabled: section.enabled == '1',
		});
	});

	return result;
};

export function load(confdir) {
	let entries = lists(confdir);

	/* An unreadable configuration must not wipe the active rules */
	if (!entries)
		return null;

	udnsfilter.filter_clear();

	let result = { total_rules: 0, loaded_filters: 0, filters: [] };

	for (let entry in entries) {
		if (!entry.enabled || !entry.path)
			continue;

		let count = udnsfilter.filter_load(entry.path);
		if (count == null || count <= 0)
			continue;

		let info = { name: entry.name, path: entry.path, rules: count };
		if (entry.url)
			info.url = entry.url;

		push(result.filters, info);
		result.total_rules += count;
		result.loaded_filters++;
	}

	result.loaded_at = time();
	last_load = result;

	return result;
};

export function status() {
	return last_load;
};
