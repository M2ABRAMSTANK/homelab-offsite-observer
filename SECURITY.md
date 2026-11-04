# Security boundary

The observer is an outbound-only monitoring client with an explicit Ansible
installation and activation workflow. Its threat
model assumes a trusted hosting operator, root-managed code/configuration,
trusted CA store, and independent notification infrastructure. The observer has no inbound listener. The optional home-side canary binds only
loopback behind existing TLS. No real host, credentials or provider acceptance
is included in public source.

Untrusted remote servers may return stale, oversized, malformed, compressed,
misleading or slow responses. The runtime verifies TLS/hostname, nonce, schema,
freshness and exact negative behavior, limits data and subprocess lifetime, and
stores only reduced evidence. DNS compromise plus a compromised trusted CA,
compromised host clock, stolen valid endpoint credential, or compromised observer
host are outside the freshness proof. A nonce proves response freshness, not
that a compromised server is honest.

A stolen observer account can read its narrow provider/private token copies,
forge provider messages and modify its local state. The private bearer token must
authorize only the closed heartbeat representation. The tailnet grant must permit
only that destination and TCP port. No broad LAN, subnet route, SSH, exit-node,
Proxmox API, remediation or database credential belongs here. Keep the provider
credential restricted to this observer and apply external rate limits.

Missing heartbeats must be evaluated externally. A powered-off observer or failed
provider path cannot alert itself. Transport acknowledgment is not proof of
recipient delivery. All real notification paths, denied tailnet targets, clock
trust, guest sandbox behavior and encrypted restore remain deployment gates.

For review findings, describe the affected code and reproduce with synthetic
targets. Do not post real infrastructure names, addresses, tokens, recipient
details, raw response bodies or production logs to public issues. Rotate any
credential inadvertently exposed in source or issue history before reuse.


Native Telegram uses a dedicated bot, not home queue credentials. Healthchecks
uses a single-check UUID, not an account management key, and must notify through
a non-Telegram integration. Bot token and ping UUID necessarily appear in their
provider request URLs; never log requests or exception text. Host root and TLS
providers can see these values, so keep proxy/debug tracing disabled. Telegram
retries can duplicate messages; local observed recovery is not delivery proof.

Ansible validates paths before replacing files, rejects unsupported guest
privilege boundaries, and does not silently enable monitoring. Tests include
secret redaction, wrong-recipient rejection, active-update refusal and path safety.
See [validation evidence](docs/VALIDATION.md) for the limits of local checks.
