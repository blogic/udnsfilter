# uDNS Filter

A DNS filtering and forwarding service for OpenWrt routers.

## Overview

uDNS Filter provides DNS-based content filtering and query forwarding for OpenWrt systems. It intercepts DNS queries over UDP and TCP, applies domain-based filtering rules, and forwards allowed queries to upstream DNS servers including DNS-over-HTTPS (DoH) providers.

## Features

- **Domain Filtering**: Block domains using exact match, subdomain, or wildcard patterns
- **Multiple Filter Formats**: Supports adblock-style rules, hosts file format, and plain domain lists
- **UDP and TCP**: Both transports on IPv4 and IPv6 (RFC 7766); oversized UDP answers are truncated with TC set according to the client's advertised EDNS0 payload size
- **DNS-over-HTTPS Support**: Automatically spawns DoH proxy processes for encrypted DNS, with optional bootstrap pinning for hostname endpoints
- **Server Health Monitoring**: Tracks upstream server health with automatic failover, retries, and query timeouts
- **Query Statistics**: Real-time tracking of queries, blocks, and upstream errors over ubus
- **DNS Rebind Protection**: Blocks upstream answers containing private addresses, with a per-domain allowlist for legitimate split-horizon names
- **Event Loop Integration**: Native libubox/uloop integration
- **Privilege Separation**: Drops root privileges after socket binding

## Architecture

### Components

- **udnsfilter.so**: Ucode module providing the core DNS engine (sockets, TCP transport, resolver, filter matching)
- **lib/udnsfilter/** ucode modules (installed to `share/ucode/udnsfilter/`, imported as `udnsfilter.<name>`):
  - `config.uc`: defaults and the `config main` UCI parsing
  - `filter.uc`: filter list configuration and state; drives the C engine through its path-based API
  - `query.uc`: per-query decision (match, counters, block or forward), registered directly as the engine callback
  - `tracking.uc`: bounded global and per-address domain counters
  - `ubus_api.uc`: the published ubus object
- **udnsfilter**: thin launcher wiring the modules together
- **doh_proxy**: Standalone binary that converts standard DNS queries to DoH requests
- **c-ares**: Embedded DNS resolver library for upstream query forwarding

### Filter Engine

Three rule types are supported:

- **Exact**: `example.com` blocks only the exact domain
- **Subdomain**: `||example.com^` blocks the domain and all subdomains
- **Wildcard**: `*.example.com` equivalent to the subdomain form

Exact rules live in one hash table; subdomain and wildcard rules share a second table keyed by base domain, probed once per label boundary of the queried name. Lookups are O(labels) regardless of rule count, tables grow automatically, and duplicate rules across overlapping lists are stored once.

### Blocked Responses

Filtered domains are answered with a null address (0.0.0.0). Rebind-protected answers return NXDOMAIN. Upstream failures return SERVFAIL rather than leaving the client to time out.

## Configuration

All configuration lives in the `dns` UCI package (`/etc/config/dns`). The launcher accepts an alternative UCI configuration directory as its first argument.

### Main Section

```uci
config main 'main'
	option listen_addr '0.0.0.0'
	option listen_addr6 '::'
	option listen_port '53'
	list upstream 'dns://1.1.1.1'
	list upstream 'dns+https://dns.google/dns-query'
	option bootstrap '8.8.8.8'
	option rotation '1'
	option cache_ttl '3600'
	option filter '1'
	option verbose '0'
	option rebind_protection '1'
	list rebind_domain 'plex.direct'
	option block_any '1'
	option dns0x20 '0'
	option ratelimit '100'
	option ratelimit_burst '300'
	option ratelimit_global '1000'
	option ratelimit_global_burst '2000'
	option max_pending '2048'
	option max_filter_rules '262144'
	option max_tcp_per_client '8'
```

- `upstream`: standard DNS URIs (`dns://host[:port]`) or DoH URIs (`dns+https://host/path`)
- `bootstrap`: IP address used to resolve DoH hostnames, avoiding a resolver loop when udnsfilter is the system resolver
- `rebind_protection` / `rebind_domain`: private-address blocking and its allowlist (listed domains and their subdomains are exempt)
- `verbose`: per-query logging

### Security Limits

The options below harden the service against abuse. Each accepts `0` to disable that
limit; the values shown above are the defaults.

- `block_any`: answer NOTIMP to `ANY` queries rather than forwarding them, preventing their use in amplification (RFC 8482). Set `0` to allow `ANY`.
- `dns0x20`: randomise the case of upstream query names for extra spoofing resistance. Off by default because some upstreams and middleboxes do not preserve case.
- `ratelimit` / `ratelimit_burst`: per-client query rate (queries per second) and burst allowance. Over-limit UDP datagrams are dropped without a reply; over-limit TCP connections are closed.
- `ratelimit_global` / `ratelimit_global_burst`: the same limits applied across all clients combined.
- `max_pending`: maximum outstanding upstream queries. Beyond this the client is answered SERVFAIL immediately instead of the query being queued.
- `max_filter_rules`: maximum number of loaded filter rules across all lists. Loading stops once the cap is reached.
- `max_tcp_per_client`: maximum concurrent TCP connections from a single client address.

The queries dropped by these limits are counted in `stats` (see below). After every stats
interval, a `udnsfilter.security` ubus event carries the deltas of the malformed, rate
limited, rebind blocked and overload dropped counters whenever any of them rose, so a
monitor can subscribe to attack activity.

### DNS-over-HTTPS

DoH URIs like `dns+https://1.1.1.1/dns-query` spawn local proxy processes listening on ephemeral ports (starting at 5301). Exited proxies are restarted with an escalating backoff. Responses are validated: only HTTP 200 with the `application/dns-message` media type is forwarded.

### Filter List Management

Filter lists are configured as `filter` sections:

```uci
config filter 'adguard_dns'
	option enabled '1'
	option name 'AdGuard DNS Filter'
	option url 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt'
	option path '/var/lib/udnsfilter/adguard_dns.txt'
```

Filter file formats:
- Adblock-style: `||ads.example.com^`
- Hosts file: `0.0.0.0 ads.example.com`
- Plain domains: `ads.example.com`

Comments (`#` and `!`) and blank lines are ignored.

#### Updating Filter Lists

`udnsfilter-update` downloads all enabled filter lists to their configured paths, creating target directories as needed. Downloads are bounded by a 60 second timeout. Exit codes: 0 success, 1 partial failure, 2 total failure. An alternative UCI configuration directory can be passed as the first argument.

## ubus Interface

The launcher publishes the `udnsfilter` object:

- `stats`: query counters (total, blocked, allowed, forwarded, upstream errors)
- `reset_stats`: reset the counters
- `servers`: upstream server health states, rotation flag, and cache TTL
- `reload_filter`: clear and reload all enabled filter lists from UCI
- `filters`: last filter load result (per-list rule counts, totals, timestamp)
- `reinit`: reinitialise the resolver after network changes
- `tracking`: enable, disable, or dump per-client domain counters (bounded, at most 32 addresses)
- `domains`: global replied and blocked domain counters (bounded)

## Module API

The `udnsfilter` ucode module (C engine) exports:

- `socket_create(addr, port, [rotation], [cache_ttl], [addr6])`
- `set_callback('query', fn)`: fn receives (packet, client); client carries `transport` and, for TCP, a connection id
- `set_upstream(servers, [bootstrap])`
- `filter_load(path)`, `filter_clear()`, `filter_match(domain)`
- `rebind_protection(enable, [domains])`
- `send_blocked_response(client, packet)`, `forward_query(client, packet)`
- `stats_get()`, `stats_reset()`, `get_server_states()`, `reinit()`
- `drop_privileges([user], [group])`, `shutdown()`

The `udnsfilter.filter` ucode module (configuration and state) exports:

- `lists([confdir])`: parsed UCI filter sections as `{section, name, url, path, enabled}` entries
- `load([confdir])`: clear the engine and load all enabled lists; returns `{total_rules, loaded_filters, filters[], loaded_at}` or null if the configuration is unreadable (active rules stay untouched)
- `status()`: result of the last `load()`

Supporting modules: `udnsfilter.config` (`load(confdir)` returning the daemon configuration), `udnsfilter.query` (`init(config)`, `handle(packet, client)`), `udnsfilter.tracking` (`domain_hit()`, `track()`, `untrack()`, `tracked()`, `domains()`) and `udnsfilter.ubus_api` (`publish(config)`, `cleanup()`).

The engine knows nothing about UCI; all configuration parsing happens in ucode.
