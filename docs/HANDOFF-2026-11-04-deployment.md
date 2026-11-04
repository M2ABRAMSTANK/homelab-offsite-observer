# Offsite observer deployment implementation — 2026-11-04

The owner requested a deployable unprivileged Proxmox LXC service with a simple
Ansible install and security validation, while another agent owns parent Homelab
hardening. The owner chose **direct Telegram using a dedicated bot plus independent
Healthchecks.io dead-man notifications**. This supersedes the earlier no-Telegram
choice for this component; the home queue/bot remains independent.

All edits are confined to this independent service repository. Per the owner's
explicit task direction, work stayed in its initially clean `main` checkout,
with HEAD unchanged at `a8b1fd11f770650f384ea7b720dcb2e29773e98b`; changes are
uncommitted. No other agent writing track shared these files. Review agents were
read-only. Parent hardening files, `.gitmodules`, staged gitlink and parent index
were not edited. No commit, push, deployment, provider contact or notification
occurred. GitLab remains primary and mirrors to GitHub.

Implemented:

- Ansible disabled installation, protected paths/accounts/credentials, update
  refusal for active/transitional workers, preflight and strict first-cycle
  activation. Existing configuration/state survive repeat installs.
- Direct Telegram connector with exact returned chat-ID validation and durable
  ordered retries. Healthchecks completion/failure pings with reserved execution
  budget, pending/drop reporting and Telegram visibility for dead-man-path loss.
- Separate identifiable provider acceptance test units; no monitoring activation
  needed to test credentials/handset/dead-man behavior.
- Home-side loopback freshness canary, separate Ansible play and Caddy route
  example. Existing home edge and private-queue infrastructure are untouched.
- Previous unpublished HTTP-framing/state security fixes from `0b3cc0c`.
- Updated deployment, contracts, operations, threat model and validation records.

[VALIDATION.md](VALIDATION.md) records the reproduced checks and exact limits.
Source review identified and repaired activation accepting unhealthy cycles,
missing Healthchecks-loss Telegram notification, preflight gate ordering,
transitional-worker update refusal, destination path checks and event-send budget
starvation. Native observed recovery is explicitly separate from confirmed
notification delivery; a failed recovery remains queued and fails Healthchecks.
Telegram retry duplicates are possible and carry the same event ID.

Next steps are tracked in [BACKLOG.md](BACKLOG.md). The owner subsequently authorized committing and pushing this implementation
to GitLab and verifying the GitHub mirror. The uncommitted/no-push statements
above record the earlier review checkpoint. Real guest/provider/canary/private-network and encrypted-restore evidence
remain operational acceptance, not source-completion claims. Coordinate any parent
SEC4/design update with the hardening owner; do not overwrite its working files.
