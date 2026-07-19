# Security TODO

## Currently Implemented

- DNS Rebinding Protection - private IP detection in responses (RFC1918, loopback, link-local, multicast), with a per-domain allowlist. Rebinding blocks are counted separately (`rebind_blocked`).
- Query pre-validation - responses (QR set) and runt packets are dropped; non-QUERY opcodes and ANY queries answered NOTIMP; malformed or multi-question packets answered FORMERR.
- Per-client and global query rate limiting (token buckets); over-limit UDP is dropped without a reply, over-limit TCP is closed.
- Resource caps - outstanding upstream queries, loaded filter rules, and concurrent TCP connections per client address.
- Upstream anti-spoofing - UDP source-port rotation via `udp_max_queries`, optional DNS 0x20 case randomisation.
- Attack telemetry - per-counter `stats` over ubus and a `udnsfilter.security` event carrying the deltas of the attack counters.

All limits are configurable in `/etc/config/dns`; `0` disables a limit. See README "Security Limits".

## Attack Mitigation TODO

### High Priority (Router DNS Critical)

#### Rate Limiting
- [x] Per-client query rate limiting (`ratelimit` / `ratelimit_burst`, `src/ratelimit.c`)
- [x] Global query rate limiting (`ratelimit_global` / `ratelimit_global_burst`)
- [ ] Per-domain query rate limiting (prevent NXDOMAIN floods) - deferred (heuristic). Random-subdomain floods are bounded by the per-client limiter and the c-ares query cache; targeted per-domain accounting belongs with the NXDOMAIN cluster below.
- [x] Configurable rate limit thresholds (UCI options, applied via `security_set()`)

#### Query/Response Size Limits
- [x] Maximum query size enforcement (`DNS_MAX_QUERY_SIZE`, plus `MSG_TRUNC` drop of oversized UDP datagrams)
- [x] Maximum response size limiting (EDNS0-aware truncation, `query_udp_size()` / `truncated_response_send()`)
- [x] ANY query type restrictions (amplification prevention) - `block_any`, answers NOTIMP per RFC 8482

#### Resource Limits
- [x] Maximum concurrent pending queries (`max_pending`, excess answered SERVFAIL)
- [x] Maximum filter rules limit (`max_filter_rules`)
- [x] Query table memory limits (bounded by `max_pending`; global/per-client tracking maps already bounded)
- [x] Automatic eviction of stale queries (c-ares 2s x2 tries guarantees a callback; rate-limit client table recycles entries by age)

#### Protocol Security
- [x] Maximum domain name depth enforcement (label checks in `scan_name_length()` / `name_skip()`)
- [x] Label compression bomb protection (name scan terminates at the first pointer; `dn_expand()` carries its own loop protection)
- [x] Maximum name length validation (`dn_expand()` into a bounded buffer; pre-check rejects wire names over 255 bytes)
- [x] Malformed packet rejection hardening (`packet_precheck()`: QR/opcode/qdcount, FORMERR on parse failure, `MSG_TRUNC` drop)

#### Response Validation
- [ ] Bailiwick checking (ensure responses match query domain) - not applicable in the classic sense. This is a forwarder that trusts its configured recursive upstreams; classic bailiwick checking is a recursive-resolver concern (validating records against the delegation being followed). The relevant protection, question matching, is covered below.
- [x] Response/query matching (beyond transaction ID) - c-ares matches both the query id and the question set (`same_questions()` in `ares_process.c`) and validates DNS cookies (RFC 7873); replies that do not match are dropped. `ARES_FLAG_NOCHECKRESP` does NOT weaken these; it only governs whether SERVFAIL/NOTIMP/REFUSED are passed through or requeued.

### Medium Priority

#### DNS Cache Poisoning Protection
- [x] Verify c-ares port randomisation behaviour - one UDP socket per upstream, kernel-chosen ephemeral source port, rotated every 128 queries via `ARES_OPT_UDP_MAX_QUERIES`.
- [x] Verify c-ares transaction ID randomisation - OS randomness (getrandom/arc4random); RC4 is only a last-resort fallback (`c-ares/src/lib/util/ares_rand.c`).
- [ ] Consider DNSSEC validation support - deferred. c-ares is a stub resolver and does not validate DNSSEC; validation would need a validating resolver or a separate library.
- [x] Source port entropy analysis - addressed by the `udp_max_queries` rotation above.

#### DNS Tunnelling Detection
- [ ] Excessive subdomain depth detection - deferred (heuristic)
- [ ] Unusual query pattern detection (excessive TXT, NULL queries) - deferred (heuristic)
- [ ] Domain name entropy analysis - deferred (heuristic)
- [ ] Query frequency analysis per domain - deferred (heuristic)

#### NXDOMAIN Attack Protection
- [ ] Random subdomain flood detection - deferred (heuristic); partially mitigated by per-client rate limiting
- [ ] NXDOMAIN response rate limiting per client - deferred (heuristic)
- [ ] Base domain tracking for enumeration detection - deferred (heuristic)

### Lower Priority

#### DNS Exfiltration Detection
- [ ] Large TXT record response monitoring - deferred (heuristic)
- [ ] Unusual encoding detection in domain names - deferred (heuristic)
- [ ] High query volume to single domain alerting - deferred (heuristic)

#### Advanced Monitoring
- [ ] Subdomain enumeration pattern detection - deferred (heuristic)
- [ ] Systematic scanning detection - deferred (heuristic)
- [ ] PTR query rate limiting (local network scanning prevention) - deferred; covered generally by per-client rate limiting

#### DoS Hardening
- [x] CPU usage limiting for filter matching (O(labels) hash lookups regardless of rule count, `filter_match()`)
- [x] Query processing timeout enforcement (c-ares 2s x2 tries; DoH proxy curl 5s)
- [x] Graceful degradation under load (rate limiting, pending cap, and SERVFAIL responses instead of collapse)

## Configuration TODO

- [x] Rate limiting configuration options
- [ ] Security policy configuration (strict/moderate/permissive) - deferred; individual options ship first, a preset layer can be added on top later
- [x] Logging levels for security events (per-episode rate-limit logging; verbose per-query logging)
- [x] Statistics for blocked attack attempts (`stats`: malformed, refused, rate-limited, overload-dropped, rebind-blocked)
- [x] Alert/notification mechanism for attacks (`udnsfilter.security` ubus event on the stats interval)

## Testing TODO

- [ ] Amplification attack test suite
- [ ] Rate limiting test cases
- [ ] Malformed packet fuzzing
- [ ] Load testing under attack scenarios
- [ ] DNSSEC validation testing (if implemented)

## Documentation TODO

- [ ] Security features documentation
- [ ] Attack mitigation strategy guide
- [ ] Configuration best practises for different deployment scenarios
- [ ] Performance tuning guide
