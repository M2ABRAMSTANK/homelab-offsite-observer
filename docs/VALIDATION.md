# Deployment-source validation — 2026-11-04

The package implements installation and activation for a dedicated unprivileged
Debian 12/13 Proxmox LXC, direct Telegram delivery, independent Healthchecks
liveness, and an optional separately installed home-edge freshness canary.
No actual offsite guest, real provider account, recipient or home endpoint was
contacted or configured during this source task.

## Reproduced evidence

| Check | Result | Scope |
|---|---|---|
| `make check` | 68 tests pass; diff whitespace check passes | Local Python, synthetic inputs and TLS socket pairs |
| Debian 12 and Debian 13 Python suites | Pass | Disposable containers, network disabled; public source mounted read-only |
| Both example configurations (`make demo`) | Zero requests, zero state writes | Native and legacy configuration validation |
| All three Ansible playbook syntax checks | Pass | Installed controller Ansible; canary group absent in observer-only example inventory is expected |
| Debian 12 and 13 installer fixtures | Eight checks pass on each | Real Debian Ansible/users/filesystem, **simulated systemd** and fixture-only replacement of guest-platform probe |
| Every generated observer unit | `systemd-analyze verify` passes on Debian 12 and 13 | Unit syntax/dependencies, not sandbox execution |
| Security regressions against base `a8b1fd1` | 43-test run fails with 17 assertions and 3 errors | Red proof for imported framing/state fixes; candidate passes |
| Independent security review | No remaining concrete blocker found after fixes | Read-only source review, 13 independently repeated pure checks, mocked provider failure/recovery reproduction |

The installer fixture verifies production Docker refusal before install, disabled
installation, repeat installation with **zero changed tasks** and preserved
configuration/state, active update refusal, explicit stopped update, refusal of
an activating oneshot, default-off activation refusal, and symlink refusal
without modifying its target. It also validates all generated unit files.
It deliberately does **not** emulate cgroups, credential mounts, systemd service
execution, Proxmox AppArmor, external routing or recipient delivery.

Regression coverage includes exact Telegram recipient/type checks, false/failed
API responses, fixed provider destinations, token parsing and permissions,
Healthchecks success/failure body rules, backoff staying failed, dropped-event
signaling, dead-man-path loss alerting through Telegram, failed recovery remaining
durable, state-write failure suppressing completion heartbeat, reserved dispatch
budgets, strict activation outcomes and preflight before activation. Canary
coverage checks actual HTTP handling over local socket pairs, nonce duplication,
path restrictions, no-store and schema/freshness.

The previous unpublished security changes from `0b3cc0c` were incorporated as
uncommitted source: strict response framing, complete response bodies, bounded
persisted future timestamps, short clock rollback retention and activation tests.

## Repeat locally

```sh
make check
make demo
make syntax-check
```

The following Docker commands create disposable local validation containers.
The image is a test tool, not a deployment image:

```sh
docker build -t offsite-observer-validation:12 -f tests/Dockerfile .
docker run --rm --network none -v "$PWD:/source:ro" offsite-observer-validation:12 python3 -B -m unittest discover -s tests -v
docker run --rm --network none -v "$PWD:/source:ro" offsite-observer-validation:12 python3 -B tests/installer_container.py

docker build --build-arg DEBIAN_VERSION=13 -t offsite-observer-validation:13 -f tests/Dockerfile .
docker run --rm --network none -v "$PWD:/source:ro" offsite-observer-validation:13 python3 -B -m unittest discover -s tests -v
docker run --rm --network none -v "$PWD:/source:ro" offsite-observer-validation:13 python3 -B tests/installer_container.py
```

Never run `tests/installer_container.py` in an existing operational container.
It is a disposable-filesystem harness and substitutes systemctl there.

## Required field acceptance

Use [Deployment](DEPLOYMENT.md), then retain evidence privately:

- Actual unprivileged Proxmox guest, sandbox/credential mounts, clock query,
  outbound policy, local storage, resource limits and no unwanted listeners.
- Exact public readiness/freshness/negative behavior from the offsite vantage.
  The optional canary must be integrated into home Caddy through its own workflow.
- Telegram handset incident/recovery receipt and independent Healthchecks email/
  push delivery, stopped-worker timeout and recovery, provider-path outage drill.
- Optional private heartbeat endpoint, trust, read-only token and restrictive
  Tailscale grants with allowed/denied-path tests. Public-only mode needs none of
  those but makes no private-queue claim.
- Encrypted backup, protected recovery material and isolated restore.

These are installation-specific checks, not completed by source publication or
by the fixture results above. No “production accepted” claim is made.
