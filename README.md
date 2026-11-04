# Homelab off-site observer

An outbound-only monitor for an independently hosted, **unprivileged Debian LXC
on Proxmox**. It checks public HTTPS readiness, response freshness and unintended
public exposure, with an optional private queue check through Tailscale userspace
networking. Incident and recovery messages go directly to a dedicated Telegram
bot; Healthchecks.io independently detects observer loss or undelivered events.
The home notification queue is not part of this delivery path.

**Includes an Ansible installer, explicit activation, provider acceptance tools,
and a separately installable freshness canary.** Start with
[the deployment guide](docs/DEPLOYMENT.md). You supply private targets and
credentials; installing source leaves monitoring disabled. Installation readiness
and successful tests do not mean an actual offsite guest or recipient has been
verified. [Validation evidence and remaining field checks](docs/VALIDATION.md)
state exactly what has been tested.

## Install in the guest

Create a dedicated Debian 12/13 unprivileged LXC (1 vCPU, 512 MiB RAM, 8 GiB local
storage). Keep nesting, host devices, privileged mode and host mounts disabled.
Use its Proxmox console; the observer does not require inbound SSH or public ports.
From a reviewed checkout inside that guest, as root:

```sh
apt-get update
apt-get install --no-install-recommends python3 ansible-core ca-certificates dbus systemd
ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/install.yml
```

This installs the application and hardened systemd units **disabled**. Follow the
[configuration and activation steps](docs/DEPLOYMENT.md) to provide your private
input files, check notification receipt, and start monitoring. No custom webhook
adapter needs to be built. The older generic webhook interface remains available
for existing integrations via `config.example.json`.

## Test locally without external requests

Python 3.11+ and `openssl` are sufficient. No Python runtime dependencies.

```sh
make check
make demo
```

Tests use mocks, temporary files and TLS over local socket pairs. The demo prints
`network_requests: 0` and `state_writes: 0`. Live execution needs explicit activation,
protected credentials and a non-root account. No imports install packages, enroll
Tailscale or contact providers.

| Need | Document |
|---|---|
| Friend/hosting operator installation and acceptance | [Deployment](docs/DEPLOYMENT.md) |
| Schema, probes and native/legacy provider contracts | [Configuration](docs/CONFIGURATION.md) |
| Privileges, data flow and failure handling | [Design](docs/DESIGN.md) |
| Updates, backup, restore and removal | [Operations](docs/OPERATIONS.md) |
| Security review and operational checks | [Review](docs/REVIEW.md), [Validation](docs/VALIDATION.md) |
| Threat model and reporting | [Security](SECURITY.md) |

The private queue check stays off until a compatible authenticated endpoint and
restricted tailnet grant exist. The supplied freshness canary belongs behind the
**home** HTTPS edge, not on the observer. Neither component performs remediation.
Telegram can duplicate a message after an ambiguous send; stable event IDs make
retries identifiable. Healthchecks must use an independent email/push notification
integration so a Telegram outage cannot silence both paths.

## Source workflow

This independent repository is the `services/offsite-observer` submodule in the
parent Homelab repository. GitLab `origin` is primary and mirrors to GitHub.
Commit and push here only when authorized, verify the mirror, then separately
update the parent pointer. Never copy private inventory, tokens, chat IDs, runtime
configuration, state or production logs into public source or Git history.

No redistribution license has been selected. Public review access alone is not
a license grant; select one before offering a general reusable release.
