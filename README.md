# Homelab off-site observer

Reviewable version 1 of an outbound-only monitor for an independently hosted,
unprivileged Debian LXC. It checks a public HTTPS edge, unexpected public exposure,
and an optional private queue heartbeat through a loopback Tailscale SOCKS5 proxy.
It sends events to an independently operated HTTPS notification adapter.

**Source for review, not a deployed or production-accepted service.** No host,
provider, recipient, credentials, real target, or Tailscale enrollment is included.
Examples use reserved `example.invalid` names. The example is disabled. This
repository has independent history and contains no infrastructure inventory.

## Try it without contacting anything

Requires Python 3.11+ on Linux or macOS; `openssl` is required for the test fixtures.
There are no Python dependencies, install hooks, or import-time network actions.

```sh
make demo
make test
```

`make demo` validates the example and prints `mode: dry-run`,
`network_requests: 0`, and `state_writes: 0`. Tests use mocks, child processes,
temporary files and real TLS over local Unix socket pairs. They need no Internet,
listening ports, production credentials or privileges. Local TLS certificates are
generated in a temporary directory and removed afterward.

## What to review

| Area | Entry point |
|---|---|
| Boundaries, data flow, privileges, failure behavior | [Design](docs/DESIGN.md) |
| Exact endpoint and webhook contracts | [Configuration](docs/CONFIGURATION.md) |
| Guest preparation, disabled install, activation, uninstall | [Operations](docs/OPERATIONS.md) |
| Acceptance evidence still required before deployment | [Review checklist](docs/REVIEW.md) |
| Threats and disclosure boundary | [Security](SECURITY.md) |
| HTTPS and SOCKS5 implementation | [transport.py](observer/transport.py) |
| Freshness, schema and negative checks | [checks.py](observer/checks.py) |
| Bounded execution and provider delivery | [runner.py](observer/runner.py) |
| Independent incident machines and atomic spool | [state.py](observer/state.py) |

The default CLI never activates live monitoring. Live execution requires `--live`,
`enabled: true`, `provider.contract_verified: true`, a non-root runtime account,
and configuration and tokens supplied through systemd `LoadCredential`. The
included timer is installed disabled by the documented procedure. No code opens
a server socket or automatically installs/enrolls anything.

A provider must independently evaluate missing heartbeats and deliver to verified
recipients. A generic webhook 2xx response cannot prove handset delivery or a
working external dead-man. Private monitoring is optional and visibly disabled
until its endpoint, read-only token and exact tailnet grant are ready. This project
does not send Telegram or perform containment/remediation.

No redistribution license has been selected. Public review access does not imply
a license grant; choose a license before promoting this as a reusable release.
