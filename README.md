# uDNS Filter

A high-performance DNS filtering and forwarding service for OpenWrt routers.

## Overview

uDNS Filter provides DNS-based content filtering and query forwarding capabilities for OpenWrt systems. It intercepts DNS queries, applies domain-based filtering rules, and forwards allowed queries to upstream DNS servers including DNS-over-HTTPS (DoH) providers.

## Features

- **Domain Filtering**: Block domains using exact match, subdomain, or wildcard patterns
- **Multiple Filter Formats**: Supports adblock-style rules, hosts file format, and plain domain lists
- **DNS-over-HTTPS Support**: Automatically spawns DoH proxy processes for encrypted DNS
- **Dual Stack**: Full IPv4 and IPv6 support
- **Server Health Monitoring**: Tracks upstream server health with automatic failover
- **Query Statistics**: Real-time tracking of queries, blocks, and upstream errors
- **Private IP Detection**: Identifies and handles responses containing private IP addresses
- **Event Loop Integration**: Native libubox/uloop integration for efficient OpenWrt operation
- **Privilege Separation**: Drops root privileges after socket binding

## Architecture

### Components

- **udnsfilter.so**: Ucode module providing the core DNS filtering engine
- **doh_proxy**: Standalone binary that converts standard DNS queries to DoH requests
- **c-ares**: Embedded DNS resolver library for upstream query forwarding

### Filter Engine

Three rule types are supported:

- **Exact**: `example.com` - blocks only exact domain
- **Subdomain**: `||example.com^` - blocks domain and all subdomains
- **Wildcard**: `*.example.com` - blocks matching subdomains

The engine uses a hash table for exact matches (O(1) lookup) and linked lists for pattern-based rules.

### DNS-over-HTTPS

DoH URIs like `dns+https://1.1.1.1/dns-query` automatically spawn local proxy processes that listen on ephemeral ports (starting at 5301) and convert standard DNS queries to HTTPS requests. Proxies are automatically restarted if they exit.

## Configuration

### Upstream Servers

Supports standard DNS and DNS-over-HTTPS URIs:

```
dns://8.8.8.8:53
dns://1.1.1.1
dns+https://1.1.1.1/dns-query
dns+https://dns.google/dns-query
```

### Filter File Format

Supports multiple formats:
- Adblock-style: `||ads.example.com^`
- Hosts file: `0.0.0.0 ads.example.com`
- Plain domains: `ads.example.com`

Comments (`#` and `!`) and blank lines are ignored.

### Filter List Management

uDNS Filter includes a UCI-based filter list management system compatible with popular filter lists like Pi-hole and AdGuard Home.

#### UCI Configuration

Filter lists are configured in `/etc/config/dns`:

```uci
config filter 'adguard_dns'
	option enabled '1'
	option name 'AdGuard DNS Filter'
	option url 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt'
	option path '/var/lib/udnsfilter/adguard_dns.txt'
```

Default filter lists included:
- **AdGuard DNS Filter**: Official DNS-focused filter from AdGuard
- **StevenBlack Unified Hosts**: Popular unified hosts file
- **EasyList**: General adblocking list
- **EasyPrivacy**: Tracking protection
- **OISD Small**: Curated, efficient blocklist
- **AdAway**: Mobile-focused blocking
- **Fanboy Enhanced Tracking**: Advanced tracking protection

#### Updating Filter Lists

Use the `udnsfilter-update` command to download and update enabled filter lists:

```bash
udnsfilter-update
```

This script:
- Downloads all enabled filter lists from their URLs
- Stores them in `/var/lib/udnsfilter/`
- Validates downloads (checks for non-empty files)
- Returns exit codes: 0=success, 1=partial failure, 2=total failure

#### Loading Filters from UCI

The `filter_load_uci()` function loads all enabled filters defined in UCI configuration:

```javascript
import * as udnsfilter from 'udnsfilter';

const result = udnsfilter.filter_load_uci();
// Returns: { total_rules: 100000, loaded_filters: 3, filters: [...] }
```
