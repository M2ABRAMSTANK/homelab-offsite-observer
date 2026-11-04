# Operations

Use [DEPLOYMENT.md](DEPLOYMENT.md) for install, configuration, provider tests and
activation. The package runs natively under systemd in an unprivileged Debian
12/13 LXC; the Docker image under `tests/` is only a local validation fixture.

## Observe and stop

```sh
systemctl list-timers offsite-observer.timer
journalctl -u offsite-observer.service --since '-10 minutes' --no-pager
systemctl disable --now offsite-observer.timer
systemctl stop offsite-observer.service
```

Evidence contains fixed probe classes, timestamps, booleans and aggregate counters,
never URLs, tokens or remote response bodies. Inspect `outcomes`, `incidents`,
`spool_events`, `spool_dropped` and `provider_heartbeat` together. Ordinary cycles
exit 2 on clock/heartbeat failure; a home outage is reported as monitoring data,
not necessarily a failed systemd unit. Acceptance uses stricter exit criteria.

For native Telegram, `incidents` describes local detected state, **not confirmed
notification receipt**. A recovery can be detected before its Telegram send fails;
that recovery remains queued and Healthchecks receives `/fail`. The previously
sent incident remains visible on the handset. Telegram has no idempotent-send
contract, so ambiguous delivery can duplicate a message with the same event ID.
Do not use the local incident boolean as proof that a recovery was delivered.

Every native cycle reserves time for an event attempt and its final Healthchecks
request. Pending events, including backoff, and any recorded event drops keep the
Healthchecks check failed. A lost Healthchecks path opens `provider_path` after
three failed cycles and queues Telegram notification; successful requests recover
it after two cycles. New provider-path events are sent on the following cycle.
A home outage alone does not stop successful execution heartbeats.

## Update safely

Arrange a monitoring maintenance window and preserve an encrypted backup first.
Use a reviewed source revision and the same private inputs:

```sh
ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/install.yml -e @/root/offsite-private/inputs.yml -e '{"observer_stop_for_update":true}'
```

Installation stops the timer and active workers before replacing files and leaves
it disabled. Without explicit update consent, active/activating/deactivating/
reloading workers cause refusal. Root-owned code/configuration cannot be symlinks,
service writable or unexpectedly shared. Existing state is not erased or chowned
away from an unexpected owner. Missing private input paths preserve existing
configuration and credential sources; supplied paths deliberately replace them.
Re-run preflight and acceptance/activation afterward.

For rollback, reinstall the prior reviewed source revision with the same process.
The schema remains version 1. Preserve the current state before any restore;
restoring older state can replay notifications or lose recent incident history.
Do not clear state to make acceptance pass. If `spool_dropped` is nonzero, retain
its evidence, investigate loss and reconcile outstanding messages before a
separately approved state repair. There is no automatic reset/repair action.

Changing optional private coverage requires a repeated install to update
credential drop-ins. The observer installer does not own or remove Tailscale,
home Caddy configuration or the separately installed canary. The optional
`systemd/journald-retention.conf` is a guest-wide example: review other guest
journals before applying its 64 MiB / 7-day bounds.

## Backup and isolated restore

Use encrypted daily guest/config backups, with 7-day / 4-week / 3-month retention
and separately protected decryption material. Include `/etc/offsite-observer`,
`/var/lib/offsite-observer`, source revision identity, installed units/drop-ins and
representative reduced journal evidence. State must be on local guest storage.
Ansible does not invent or configure the hosting operator's backup destination.

Quarterly restore to a clone with networking disabled **before boot**. Keep its
timer disabled. Verify restored ownership/modes, configuration and retained
incident state, then run the default dry-run (zero requests). Revoke or replace
provider/private tokens before any connected test. Production and restore clones
must never share active liveness credentials. Prove the restore independently;
a successful source test is not restore evidence.

## Uninstall

Archive state/configuration in encrypted storage and arrange provider maintenance
or retirement before stopping the observer; otherwise the dead-man should alert.
Disable the timer and stop **all** `offsite-observer*.service` workers. After
confirming they are stopped, remove only this project's unit/drop-in/source paths
and reload systemd. Retain `/etc/offsite-observer` and `/var/lib/offsite-observer`
until their deletion is separately approved. Revoke dedicated bot/private tokens
and retire the Healthchecks check and optional tailnet identity. Do not blindly
remove shared Tailscale packages, backup jobs, firewall rules or the guest.
