# Configuration and endpoint contracts

[`config.example.json`](../config.example.json) is the complete schema-1 shape.
[`observer/config.py`](../observer/config.py) is its executable validator. Unknown
keys at every configuration level are errors; there are no environment-based
target overrides. This file holds no tokens or recipient addresses. Maximum
configuration size is 32 KiB. Invalid config exits with a fixed error class.

| Field | Type and constraint |
|---|---|
| `schema` | integer, exactly `1` |
| `enabled` | boolean; example `false`, must be explicitly `true` for live execution |
| `observer_id` | 1–64 ASCII letters, digits, `_` or `-`; a non-sensitive identifier |
| `readiness.url` | absolute HTTPS DNS URL with no credentials, query or fragment |
| `readiness.expected` | nonempty exact JSON object, at most 4 KiB serialized; types matter |
| `freshness.url` | absolute HTTPS DNS URL for the required nonce canary |
| `negative` | list of 1–8 checks, each with exactly the fields below |
| `negative[].name` | unique non-sensitive 1–64 character identifier, same alphabet as observer ID |
| `negative[].url` | absolute HTTPS DNS URL |
| `negative[].expected` | `http_denial`, `post_tls_eof` or `post_tls_reset` |
| `negative[].statuses` | for `http_denial`, 1–8 exact integer HTTP 400–499 statuses; otherwise `[]` |
| `private.enabled` | boolean; `false` means no private request or private-health claim |
| `private.url` | HTTPS private DNS URL; resolved only in SOCKS5 when enabled |
| `private.socks_port` | integer 1024–65535; proxy host is fixed at `127.0.0.1` |
| `private.max_pending_seconds` | integer 0–3600; example `60` is provisional |
| `provider.heartbeat_url` | HTTPS endpoint implementing the execution-heartbeat contract |
| `provider.events_url` | HTTPS endpoint implementing the incident-event contract |
| `provider.contract_verified` | boolean; live run requires `true` after independent acceptance |

All HTTPS endpoint paths must be URL-encoded ASCII. Ports default to 443 and can
be explicitly configured from 1–65535. There is no certificate-verification bypass.
Use the guest's root-managed trust store for a required private CA and verify it
on the future guest. Live configuration must be named `config` in the systemd
credential directory, not supplied from a writable checkout.

## Requests and exact responses

All probes are HTTP/1.1 HTTPS GETs with `Connection: close`,
`Accept: application/json` and `Cache-Control: no-cache`. Freshness and private
checks additionally send `X-Observer-Nonce` with a fresh 32-character lowercase
hexadecimal nonce. The private check alone sends `Authorization: Bearer <token>`.
No token is sent to a public readiness/freshness/negative URL.

Readiness passes only with HTTP 200 and the entire JSON object exactly matching
`readiness.expected`, with JSON value types preserved. Select the real object's
shape explicitly; the example's `{"status":"ok"}` is a placeholder contract.

The freshness canary must return HTTP 200, `Cache-Control: no-store`, and exactly:

```json
{"schema":1,"nonce":"<exact request nonce>","generated_at":"<current UTC ISO-8601 timestamp>"}
```

The timestamp must carry UTC (`Z` or zero offset) and be within ±120 seconds of
the observer's trusted receive clock. `no-cache` alone is insufficient. There is
no fallback to readiness, a cached timestamp, or local receipt time.

The private heartbeat must return HTTP 200, `Cache-Control: no-store`, and exactly:

```json
{"schema":1,"nonce":"<exact request nonce>","generated_at":"<current UTC ISO-8601 timestamp>","queue":{"ready":true,"active":0,"oldest_pending_seconds":0},"security_alerts_firing":0}
```

The queue keys are exact. `ready` is a true boolean, `active` is an integer
0–1,000,000, `oldest_pending_seconds` is a finite nonnegative number no greater
than the configured ceiling, and `security_alerts_firing` is an integer
0–1,000,000. Booleans cannot substitute for numbers. The alert count is schema
validated; it is not itself an incident signal in v1. All extra response fields
are refused. Malformed JSON, unauthorized status, TLS failure or stale nonce
is unhealthy. No raw database access or general metrics export is supported.

Negative checks specify **one exact expected class**, not a collection of generic
curl failures. `http_denial` accepts only the listed 4xx status after verified
TLS. `post_tls_eof` requires no HTTP status and an EOF after verified TLS;
`post_tls_reset` requires a reset after verified TLS. A different abort class
fails an eligible check. TLS/DNS/pre-TLS connection failure and timeout are
inconclusive. Fixture results do not prove the real edge's expected behavior;
its exact behavior must be independently measured and configured.

## Generic notification adapter contract

This repository implements a **custom webhook contract**, not a selected
commercial provider's connector. It cannot be pointed blindly at an arbitrary
provider. Host it or select a compatible adapter independently, verify semantics,
and then set `contract_verified: true`. No Telegram adapter is implemented.

Both requests are HTTPS POST JSON with `Authorization: Bearer <provider_token>`
and `Idempotency-Key`. Response must complete verified TLS and HTTP 200, 202 or
204 within the request deadline. Response body is bounded and discarded.
This acknowledgment is transport acceptance only; external delivery verification
is separate. Redirects and every other HTTP status are failures.

An execution heartbeat is sent before home probes with a new idempotency key
every cycle, even when clock trust or home checks fail:

```json
{"schema":1,"observer_id":"offsite-review","type":"heartbeat","at":"<UTC timestamp>","clock_trusted":true}
```

The adapter must use its independent receive clock, require valid authentication
and monitor every expected observer. Three missed nominal 30-second heartbeats
must open `observer_host`/provider-path loss externally. Test timing tolerance,
receipt deduplication and recovery. Never evaluate liveness from the sender's
timestamp alone. Heartbeats are not replayed and do not join the local event spool.

An incident/recovery event has stable ID and idempotency key across retries:

```json
{"schema":1,"observer_id":"offsite-review","type":"event","id":"<32 lowercase hex characters>","key":"wan_edge","event":"incident","at":"<UTC timestamp>"}
```

Keys are `wan_edge`, `edge_exposure`, `private_queue`, `clock` and `provider_path`.
`event` is `incident` or `recovery`. The provider must deduplicate each event ID
for at least 24 hours, preserve ordering, rate-limit the dedicated observer
credential, and deliver incident/recovery to the operator-selected email and
an independently configured fallback SMS/push path. A failed primary provider
needs independent fallback monitoring; the local process cannot notify through
a failed path. No recipient or credential is invented in this repository.

## Secrets and endpoint allowlist

Production token sources are root-owned 0600 files in `/etc/offsite-observer`.
Private credential copies are named `provider_token` and optional `private_token`.
Tokens are ASCII bearer strings 8–4098 characters from the documented validator
alphabet; they are never passed in argv or embedded in target URLs.

| Outbound destination | Purpose | Scope to approve |
|---|---|---|
| Public readiness/freshness/negative DNS names and configured TCP ports | WAN and exposure checks | Exact real names/ports from operator |
| Guest DNS resolver | Public DNS resolution | External resolver; no home wildcard |
| `127.0.0.1:<socks_port>` | Private HTTPS proxy | Loopback only |
| Private heartbeat DNS name and TCP port inside tailnet | Read-only heartbeat | Exactly one approved target/port grant |
| Provider heartbeat/events DNS names and configured TCP ports | Liveness and events | Independently operated compatible adapter |
| Tailscale control/relay/peer endpoints | Optional daemon connectivity | Review current Tailscale requirements separately |
| Host time source, package repositories, encrypted backup destination | Platform maintenance | Hosting operator's separate policy |

Application config limits **intended** targets; it is not an egress firewall.
Require external guest firewall/Tailscale grants to enforce those boundaries.
Do not claim that the systemd unit prevents arbitrary outbound traffic after
runtime compromise.
