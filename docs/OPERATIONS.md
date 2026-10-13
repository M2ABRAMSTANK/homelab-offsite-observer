# Manual installation and operation

These are reviewable procedures for a **future, separately authorized guest**.
Nothing here has been executed against a host. The repository does not provision
an LXC, change the hosting Proxmox node, install on import, or auto-enable a timer.
Use the hosting operator's IaC for an unprivileged Debian guest, encrypted backup
and network policy; never hand-patch an existing container to widen privileges.

## Prerequisites

- Independently hosted unprivileged Debian LXC, local filesystem, no host mounts,
  no nesting/Docker privileges, no TUN/raw socket capability, no inbound service.
- Python 3.11+, OS `ca-certificates`, systemd 252+ and a synchronized host clock.
  The guest must report `NTPSynchronized=yes`; prove this before enabling.
- Outbound resolver independent of the monitored home edge, exact HTTPS target
  contracts, a deployed freshness canary and root-managed private trust if needed.
- Independent compatible webhook adapter, recipient/fallback selection, externally
  tested dead-man, and dedicated minimal provider credential.
- Optional private endpoint/read-only token and approved destination/port grant.
- Hosting console access. Inspect template SSH/other listeners and reconcile them
  through guest IaC; the observer requires no inbound guest listener.

Inspect the code and test it locally first (`make test`, `make demo`). Review the
real guest's systemd/LXC sandbox support; namespace/cgroup restrictions vary.
Do not weaken a failed sandbox or make the LXC privileged to make it start.

## Install disabled

Run as the future guest administrator from the reviewed checkout, after the
hosting operator has approved this host action. Provision packages through that
host's IaC or distribution package manager; no curl-piped installer is supplied.

```sh
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin offsite-observer
sudo install -d -o root -g root -m 0755 /opt/offsite-observer/observer
sudo install -o root -g root -m 0644 observer/*.py /opt/offsite-observer/observer/
sudo install -o root -g root -m 0644 config.example.json /opt/offsite-observer/config.example.json
sudo install -d -o root -g root -m 0700 /etc/offsite-observer
sudo install -o root -g root -m 0644 systemd/offsite-observer.service systemd/offsite-observer.timer /etc/systemd/system/
sudo systemctl daemon-reload
python3 -B -m observer --config config.example.json
```

Do not run `useradd` if the account already exists; first verify its UID/group,
shell, home and memberships. Source must remain root-owned and not service-writable.
Install does not create tokens, activate monitoring or enable the timer. Review
the optional guest-wide journal policy before installing
`systemd/journald-retention.conf` under `/etc/systemd/journald.conf.d/`; reconcile
with existing needs and reload/restart journald only under host authorization.
The combined size/retention settings are upper bounds, not guaranteed retention.

## Configure and optional Tailscale

Create a root-owned 0600 `/etc/offsite-observer/config.json` from the example,
replace all placeholders and configure the real exact responses. Create
`provider.token` privately (root-owned 0600), with no token pasted into a terminal
command or repository. Leave `enabled: false` until all acceptance gates pass.
Validate the protected configuration using the dry-run command as root; dry-run
is allowed as root because it performs no live action:

```sh
sudo /usr/bin/python3 -B -m observer --config /etc/offsite-observer/config.json
```

Run that command from `/opt/offsite-observer`. Never run the **live** service as
root. The installed unit loads protected config/token sources into the private
credential directory of `offsite-observer`.

For private monitoring, install Tailscale separately from an approved upstream
package. Configure its daemon for userspace operation and loopback-only proxy:

```text
tailscaled --tun=userspace-networking --socks5-server=127.0.0.1:1055
```

This is a daemon configuration example, not an enrollment command. Authenticate
privately without putting auth keys in argv or public source. Use a dedicated
observer identity/tag approved by the tailnet administrator. Do not advertise
subnet routes, accept broad LAN routes, act as an exit node, enable Tailscale SSH,
Serve/Funnel or expose the proxy publicly. Policy must permit only the approved
heartbeat host and TCP port. Verify both allowed reachability and denied hosts/
ports through this proxy, with no direct-connect fallback. Those real policy
tests cannot be completed using this generic source alone.

Create root-owned 0600 `/etc/offsite-observer/private.token`. Add a root-owned
systemd drop-in (through guest IaC) containing:

```ini
[Service]
LoadCredential=private_token:/etc/offsite-observer/private.token
```

Set `private.enabled: true`, the exact private HTTPS DNS target and the configured
loopback SOCKS port. The optional daemon is outside the observer unit and needs
its own constrained state, resource and backup policy. Do not pass it a host TUN
device. If disabled, this project makes no private-health claim.

## Accept, enable, observe

Complete [REVIEW.md](REVIEW.md), independently verify compatible webhook semantics,
recipient delivery and external dead-man, then set `contract_verified: true` and
`enabled: true` in the protected configuration. Separately authorize first live
requests. Validate the unit with `systemd-analyze verify` on the actual guest.
The review repository's successful unit tests are not guest/notification proof.

```sh
sudo systemctl daemon-reload
sudo systemctl start offsite-observer.service
sudo systemctl status offsite-observer.service
sudo journalctl -u offsite-observer.service --since '-5 minutes'
```

The service logs only reduced evidence. Exit 2 means clock/provider or runtime
failure; home incident state is reported in JSON and does not make every healthy
execution a failed unit. Inspect all outcomes and private-disabled status.
Unexpected sandbox/clock/credential errors are an activation stop. Verify no
new public/inbound listening sockets, service UID/capabilities, writable paths,
resource limits, timer non-overlap, configured latency and actual endpoint classes.

After accepted first-cycle evidence and external notification tests:

```sh
sudo systemctl enable --now offsite-observer.timer
sudo systemctl list-timers offsite-observer.timer
```

Only this explicit enable starts recurring traffic. Monitor `spool_dropped`,
clock/provider failures and independent missing-heartbeat incidents. Deleting
state forgets streaks/incidents; do not treat state as disposable during repairs.
Before updates, disable timer, wait for the unit to stop, preserve state/config,
install the reviewed source and repeat acceptance without broadening privileges.

## Backup and isolated restore

The hosting operator must configure encrypted daily guest/config backups with
7-day / 4-week / 3-month retention and separately secure decryption material.
Include protected config/token sources, local state and representative reduced
journal evidence. Encryption configuration and recovery cannot be proven here.

Quarterly, restore to an isolated clone with networking disabled **before boot**.
Keep the observer timer disabled and run dry-run first. Restore source/config/
state and verify ownership/modes and retained incident evidence. Revoke or replace
tokens for a test clone; never allow production liveness/events from it. Prove
the probe can start in dry-run without production contact. Only a separately
authorized synthetic-network test should enable live execution. Record restore
evidence and securely remove the clone and test credentials afterward.

## Stop and uninstall

Uninstall requires host authorization. Preserve encrypted backup of state and
config first; keep the stopped observer registered in external monitoring until
its maintenance/decommission plan is agreed, or it will correctly dead-man alert.

```sh
sudo systemctl disable --now offsite-observer.timer
sudo systemctl stop offsite-observer.service
sudo systemctl is-active offsite-observer.service
sudo systemctl is-enabled offsite-observer.timer
```

Expected stopped/disabled statuses may exit nonzero. After confirming no running
worker, remove **only** this project's installed unit/drop-in and source paths,
then run `systemctl daemon-reload`. Review and remove the optional journal policy
only if it was installed specifically for this guest. Retain `/var/lib/offsite-observer`
and `/etc/offsite-observer` until the operator approves their archived data deletion.
Revoke dedicated provider/private tokens and the observer tailnet identity.
Do not remove a shared Tailscale daemon, account or backup job blindly. The future
hosting operator's IaC owns guest destruction and data-preservation decisions.
