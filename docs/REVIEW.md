# Review evidence and deployment gates

## Source review

This repository is intentionally generic, with a fresh independent Git history.
Review every tracked file and commit before public publication. There must be no
real home DNS name, host/guest inventory, private network address, recipient,
credentials, response body, production log, private design dump or copied
infrastructure Git history. Do not commit real `config.json`, token files,
generated TLS fixture material, `.venv` or state. Inspect newly created files,
not just an ordinary tracked diff. No deployment follows from public publication.

Reproduce `make test` and `make demo`. The suite exercises:

- Freshness nonce mismatch, ±120-second boundaries, stale/naive timestamps,
  missing `no-store`, clock uncertainty, exact JSON/schema/types/count bounds.
- Real verified TLS, untrusted CA/wrong hostname, pre-TLS failure, post-TLS EOF,
  exact denial status, malformed status/header refusal, incomplete
  content-length/chunked-trailer refusal, oversized length refusal, strict chunk
  size/delimiter/final-chunk handling, extension/trailer refusal, redirects,
  oversized headers/body, SOCKS5 domain framing and policy-refusal framing.
- Three failures/two passes, independent incident machines, provider-gated
  recovery, inconclusive exposure streak retention, outage negative suppression.
- Oversized private heartbeat ages are unhealthy without aborting a cycle;
  three repeated malformed responses still persist incident streaks, run eligible
  negative probes and deliver queued events, recoveries and new incidents.
- Child-process timeout/cleanup, default dry-run without request/state calls,
  disabled live execution, fixed error output and evidence without body/token.
- Atomic state, owner/mode, symlink/hardlink rejection, interrupted fixed-slot
  recovery simulation, no overlap, non-finite timestamp/corruption refusal,
  count/size/age spool limits, short backward-clock retention/extreme-future
  rejection, persisted `created`/`notified` future bound of 300 seconds and
  retry `next` bound of 600 seconds before heartbeat, 24-hour dedup and bounded
  retry delay.

A test must fail if its protected check is removed or the acceptance condition is
weakened. The oversized-age validator and cycle regressions were both reproduced
as `OverflowError` failures on revision `84f377071e8ee79f19740e4cf53f24f38fe7845f`
before moving the age bound ahead of float conversion. Local socket-pair TLS is
source evidence; it does not emulate the hosting guest or public-network vantage.

## Required deployment inputs and independent evidence

| Gate | Required evidence | Current source status |
|---|---|---|
| External placement | Approved owner/host, unprivileged Debian template, local storage, resources and backup target | Unknown; no host action |
| Inbound boundary | Actual guest has no public/inbound service; console administration plan; observer has no listener/capabilities/host mount | Unit/source only |
| Guest runtime | Python/systemd support, real unit verification, `LoadCredential` source/copy behavior, resource/timeout limits, no overlap across timer/manual starts, restart behavior | Local tests only |
| Clock | Host synchronized, guest reports `NTPSynchronized=yes`; skew/untrusted behavior verified without widening guest privileges | Local fixtures only |
| Public vantage | External public resolver, real DNS/SNI/certificate/expected exact readiness response and a deployed nonce canary | Targets unknown |
| Freshness | Real 128-bit nonce echo + UTC timestamp + no-store, cache/replay/stale/clock-skew rejection | Local fixtures only |
| Negative canaries | Valid real TLS then exact measured denial/EOF/reset; pre-TLS and outage remain inconclusive | Local fixtures only |
| Private path | Exact hostname/port, minimal token representation, OS trust, loopback userspace daemon, approved observer tag/grant | Disabled by example |
| Denied tailnet paths | Through proxy, forbidden host and port attempts are denied; permitted target succeeds; no routes/SSH/exit-node grant | Not run |
| Notification | Compatible adapter acknowledges/deduplicates/rate-limits; selected recipients receive incident and recovery on email plus independent fallback. Prove an isolated `events_url` failure is detected externally while `heartbeat_url` continues to acknowledge. | Generic contract only |
| External dead-man | Stop observer; three missed nominal heartbeats alert externally. Separately fail adapter/provider path and prove independent fallback. Confirm a received heartbeat proves only pre-probe reachability, not cycle completion. Recovery verified | Not implemented locally or run |
| Provider failure | Does not clear home incident; bounded spool/backoff, expiry/drop behavior, provider deduplication, retained-event order, and isolated event-path failure detection verified end-to-end | Local tests only |
| Backup/restore | Encrypted daily backups with approved retention; isolated restore networking off, protected data recovered, dry-run contacts nothing | Operator-managed; not run |
| Live authorization | Explicit host/network/provider actions approved after review; config enabled and contract_verified set by operator | No deployment authorization here |

Do not mark these complete from mocked responses, generic source review or a
commercial provider name. Real recipient contact, provider purchase and policy
changes are separate actions. Do not send review invitations or messages from
this code repository without explicit operator authorization.

Known v1 limits: no selected provider connector, no cryptographic proof against
a compromised host/endpoint, no guaranteed message retention/delivery, no
platform provisioning or automated restore, no third-party remediation, and no
production-accepted monitoring claim. Private checks can be disabled, so the
activation report must make that coverage gap explicit.
