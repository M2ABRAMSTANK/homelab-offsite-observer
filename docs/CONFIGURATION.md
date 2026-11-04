# Configuration and endpoint contracts

Use `config.telegram.example.json` for the native Telegram + Healthchecks deployment.
`config.example.json` retains the original generic adapter configuration. Both use
schema 1; unknown keys remain errors.

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
credential directory, not supplied from a writable checkout. The CLI checks that
path and the private credential files' ownership, mode, link count and contents;
it does not verify that systemd created the directory. The supplied unit is the
mechanism that uses `LoadCredential` for protected sources. A manual live
invocation therefore lacks the unit's sandbox, deadline and resource limits and
is not an activation procedure.

## Requests and exact responses

All probes are HTTP/1.1 HTTPS GETs with `Connection: close`,
`Accept: application/json` and `Cache-Control: no-cache`. Freshness and private
checks additionally send `X-Observer-Nonce` with a fresh 32-character lowercase
hexadecimal nonce. The private check alone sends `Authorization: Bearer <token>`.
No token is sent to a public readiness/freshness/negative URL.

Responses carrying health JSON require complete, unambiguous HTTP framing before
their bodies are interpreted. The header block must end with `\r\n\r\n`; malformed
status/header syntax, duplicate headers, conflicting `Content-Length` and
`Transfer-Encoding`, invalid lengths, unsupported transfer encodings, truncated
content-length bodies, and incomplete chunked trailers are invalid responses.
`Content-Length` is decimal and at most 20 digits. For health JSON, `chunked`
accepts only 1–8 ASCII hexadecimal size digits, exact CRLF delimiters and a final
zero chunk; chunk extensions and trailer fields are refused.

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
TLS with a well-formed HTTP/1.0 or HTTP/1.1 status line, valid complete headers,
and unambiguous header framing. Its body is deliberately not read.
`post_tls_eof` requires no HTTP response bytes and an EOF after verified TLS;
`post_tls_reset` requires a reset after verified TLS with no HTTP response bytes.
Status/partial-status followed by an abort is malformed/inconclusive and never passes.
A different abort class
fails an eligible check. TLS/DNS/pre-TLS connection failure and timeout are
inconclusive. Fixture results do not prove the real edge's expected behavior;
its exact behavior must be independently measured and configured.

## Native Telegram + Healthchecks provider

Set `provider` to exactly `{"kind":"telegram_healthchecks","contract_verified":false}`.
There are no configurable provider URLs: the implementation fixes Telegram to
`https://api.telegram.org/bot<TOKEN>/sendMessage` and Healthchecks to
`https://hc-ping.com/<UUID>`, appending `/fail` for pending/dropped notification
work. Tokens/UUID and numeric chat ID are separate protected credentials; neither
API credential is sent to the other service. See [Deployment](DEPLOYMENT.md) for
account setup and [Operations](OPERATIONS.md) for delivery/recovery semantics.

Telegram POST JSON includes only numeric `chat_id`, fixed reduced text and
content protection/preview flags. Accept only verified TLS, HTTP 200, `ok: true`,
a positive integer message ID and the exact numeric returned chat ID. Telegram
has no idempotency key: retry order is retained locally, but duplicate messages
are possible after a lost response. A stable event ID is included in the text.
The local incident state and delivery backlog are separate evidence.

Native Healthchecks pings are empty-body HTTPS POSTs after state persistence,
never replayed or queued. Accept only verified TLS, HTTP 200 and body `OK`.
Pending events/backoff or a nonzero drop counter produce `/fail`; home probe
failures with successfully delivered events still produce a normal execution
heartbeat. Healthchecks failure itself is persisted as `provider_path` and can
notify through Telegram on the next cycle after its three-failure threshold.
Configure independent notification delivery; a local process cannot report its
own death. Default examples are disabled and do not contact either provider.

Native credential names are `provider_token` (dedicated bot token),
`telegram_chat` (signed numeric chat ID) and `heartbeat_token` (check UUID).
They are loaded from `provider.token`, `telegram_chat.token` and `heartbeat.token`
by systemd; optional `private_token` is unchanged. Source files are root-owned
0600 under `/etc/offsite-observer`; runtime copies belong to the service user.
Native secrets use specific grammars, not the generic bearer-token grammar below.

Contracts: [Telegram sendMessage](https://core.telegram.org/bots/api#sendmessage),
[Healthchecks Pinging API](https://healthchecks.io/docs/http_api/),
[Healthchecks schedule](https://healthchecks.io/docs/configuring_checks/).

## Legacy generic notification adapter contract

The legacy configuration implements a **custom webhook contract**. The native
configuration above needs no such adapter. It cannot be pointed blindly at an arbitrary
provider. Host it or select a compatible adapter independently, verify semantics,
and then set `contract_verified: true`. This legacy mode does not invoke the native Telegram connector.

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

The acknowledgment proves only that the observer reached the pre-probe heartbeat
stage and the adapter accepted it; it does not prove that probes, state writes,
or incident delivery completed. The adapter must use its independent receive
clock, require valid authentication and monitor every expected observer. Three
missed nominal 30-second heartbeats must open `observer_host`/provider-path loss
externally. Test timing tolerance, receipt deduplication and recovery. Never
evaluate liveness from the sender's timestamp alone. Heartbeats are not replayed
and do not join the local event spool. The local `provider_path` outcome measures
`heartbeat_url` only: an accepted heartbeat can coexist with a failed
`events_url`. Provider acceptance must inject that isolated event-path failure
while heartbeats continue and prove independent adapter/fallback detection of
undelivered events.

An incident/recovery event has stable ID and idempotency key across retries:

```json
{"schema":1,"observer_id":"offsite-review","type":"event","id":"<32 lowercase hex characters>","key":"wan_edge","event":"incident","at":"<UTC timestamp>"}
```

Keys are `wan_edge`, `edge_exposure`, `private_queue`, `clock` and `provider_path`.
`event` is `incident` or `recovery`. The provider must deduplicate each event ID
for at least 24 hours, preserve the order of received events, rate-limit the
dedicated observer credential, and deliver incident/recovery to the
operator-selected email and
an independently configured fallback SMS/push path. A failed primary provider
needs independent fallback monitoring; the local process cannot notify through
a failed path. Events can expire or be dropped locally before delivery, so no
global incident/recovery ordering or delivery guarantee exists. No recipient or
credential is invented in this repository.

## Legacy secrets and endpoint allowlist

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
