# Deploy on an offsite Proxmox LXC

This guide supplies a complete install/configure/test/activate workflow. The
hosting operator supplies a guest; the monitoring owner supplies targets,
credentials and notification destinations. No custom notification server is
required. Do not put private input files in this public checkout.

## 1. Hosting operator: create the guest

Use your existing Proxmox guest provisioning workflow to create one dedicated
**unprivileged** Debian 12 or 13 LXC: 1 vCPU, 512 MiB RAM, 8 GiB local storage,
normal outbound network/DNS and console access. Leave nesting, privileged mode,
TUN/device passthrough and host bind mounts off. The observer needs no inbound
port or SSH server; remove unused template listeners through your guest policy.
No Proxmox API token is needed inside it. Host time must be synchronized.

Set the guest firewall to deny inbound connections except established replies;
allow its approved resolver, package mirrors and HTTPS destinations. Native
notifications require `api.telegram.org:443` and `hc-ping.com:443`. Public probe
names/ports are owner supplied. Optional Tailscale has separate control/relay
requirements; [its userspace mode](https://tailscale.com/docs/concepts/userspace-networking)
needs no TUN or extra LXC capabilities. Application target restrictions are not an
egress firewall.

The installer checks Debian/Python, systemd, LXC virtualization and an unmapped
host-root boundary (`/proc/self/uid_map`). It refuses bare hosts, privileged LXC
and Docker. It never modifies the Proxmox host or provisions/destroys guests.

## 2. Install disabled

Obtain the reviewed source revision and run inside the guest console as root:

```sh
apt-get update
apt-get install --no-install-recommends python3 ansible-core ca-certificates dbus systemd
ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/install.yml
```

The play creates a non-login `offsite-observer` account, root-owned application
files, private configuration storage and hardened units. Existing state and
configuration survive reruns. A currently active timer/worker blocks updates
unless `observer_stop_for_update` is explicitly true. Install always ends with
the timer disabled. No token, provider request, Tailscale enrollment or canary
activation occurs during observer installation.

A remote controller can instead use a private inventory with one `observer`
host and an independently verified SSH host key. The supplied local inventory
needs neither inbound SSH nor private inventory. Ansible 2.14+ is supported.

## 3. Monitoring owner: prepare private inputs

Create a private directory outside the checkout, for example
`/root/offsite-private`, mode 0700. Copy `config.telegram.example.json` to
`config.json` there, mode 0600. Replace readiness, freshness and negative-check
URLs and exact expected responses with your measured contracts. Keep `enabled`
and `provider.contract_verified` false during acceptance testing.

Provide these 0600 files using a protected transfer/editor, not shell arguments:

| File | Contents |
|---|---|
| `provider.token` | Dedicated Telegram bot token; never reuse the home bot token |
| `telegram_chat.token` | Exact numeric Telegram chat ID, including `-` for groups |
| `heartbeat.token` | UUID portion of one Healthchecks.io check's ping URL |
| `private.token` | Optional read-only heartbeat token; only if private mode is enabled |

Create the dedicated bot in Telegram's BotFather, start its private chat or add
it to the intended group with only message-sending permissions. Obtain/verify the
numeric chat ID privately. The native connector sends only fixed event classes,
non-sensitive observer ID, UTC time and event ID; it does not poll commands.
Telegram's [sendMessage API](https://core.telegram.org/bots/api#sendmessage) must
return `ok: true`, a positive message ID and the **exact intended chat ID**.
A successful API response still needs handset receipt confirmation.

Create a [Healthchecks.io simple check](https://healthchecks.io/docs/configuring_checks/)
with period **60 seconds**, grace **30 seconds**, POST-only pings, and a direct
email or independent push integration you can receive when Telegram/home are
unavailable. Use the UUID, not an account-management API key. Disable content
filtering for this empty-body ping and verify that the check is not paused.
Nominal missing-heartbeat detection is 90 seconds after the last accepted ping;
provider scheduling/delivery adds latency, which the acceptance drill measures.
Do not configure its only notification destination as Telegram.

Copy `deploy/inputs.example.yml` outside the checkout and adjust file paths.
These refer to the **Ansible controller**, which is the guest for the local flow.
Run the same play with that input file:

```sh
ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/install.yml -e @/root/offsite-private/inputs.yml
cd /opt/offsite-observer
python3 -B -m tools.deployment_check
systemctl start offsite-observer-preflight.service
journalctl -u offsite-observer-preflight.service -n 10 --no-pager
```

The check reads protected sources; preflight exercises the actual service user,
credential copies, state validation and clock in the installed sandbox, with no
network requests or probe-state writes. systemd may create its empty state
directory. `NTPSynchronized=yes` must work from that sandbox. LXC shares the host
clock: fix host time or D-Bus/timedated availability; never grant `CAP_SYS_TIME`,
privileged mode or weaken sandboxing to bypass a failure.

## 4. Home-side freshness endpoint

An existing compatible endpoint can be used directly. Otherwise the supplied
canary is installed on the **home reverse-proxy guest**, separately from offsite
installation. Provide a private inventory with one host in group `canary`:

```sh
ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i /secure/home-canary.yml deploy/canary.yml -e '{"canary_activate":true}'
```

This starts a bounded Python server on `127.0.0.1:8789`. Integrate
`deploy/caddy-canary.example` into the existing TLS vhost through the home edge's
normal IaC review/deploy workflow. The play does not edit or reload Caddy. Only
`/v1/observer/canary` should reach it. Keep existing application and access-control
routes intact. This task has not changed the home edge or its inventory.

The response echoes a single valid 128-bit nonce with a current UTC timestamp and
`Cache-Control: no-store`. It exposes no queue, host inventory or credentials.
HTTPS remains the existing edge's responsibility. Readiness checks still target
the actual application; a healthy canary alone cannot make readiness pass.

## 5. Optional private coverage

Leave `private.enabled: false` for public-edge monitoring. Private queue coverage
requires the exact [heartbeat contract](CONFIGURATION.md), root-managed CA trust,
a read-only credential and Tailscale userspace proxy on `127.0.0.1:1055`.
The home queue adapter is a separate home-infrastructure integration; this package
does not read the queue database or fabricate a healthy queue response.

Use the hosting operator's Tailscale package/enrollment workflow with
`tailscaled --tun=userspace-networking --socks5-server=127.0.0.1:1055` and a
dedicated observer identity. Grant exactly the heartbeat destination and TCP port;
no subnet routes, exit node, Tailscale SSH, Serve/Funnel or broad LAN access.
Keep auth keys off argv/history. Verify allowed target access and denial of an
unrelated host and port **through that proxy**, with no direct fallback. Re-run
installation after changing private mode so its credential drop-ins match.

## 6. Provider acceptance, then activation

These commands deliberately contact providers and may notify the configured
recipient. Run only when the monitoring owner is ready to receive the tests:

```sh
systemctl start offsite-observer-provider-test@incident.service
journalctl -u offsite-observer-provider-test@incident.service -n 10 --no-pager
systemctl start offsite-observer-provider-test@recovery.service
systemctl start offsite-observer-provider-test@heartbeat.service
```

Confirm both Telegram messages on the handset, matching the printed event IDs.
With the timer still disabled, wait past the configured Healthchecks threshold;
confirm the missing-heartbeat message arrives through the independent channel.
Then run the heartbeat test again and confirm recovery. Separately run
`offsite-observer-provider-test@failure.service`, confirm its failure notification,
and then run `@heartbeat.service` again. An explicit `/fail` alone does not test
missing-heartbeat detection. Provider tests never change the monitoring spool.

Set `provider.contract_verified` and `enabled` true in your protected source config,
then re-run `install.yml` with your private inputs. From the source checkout:

```sh
ANSIBLE_CONFIG=deploy/ansible.cfg ansible-playbook -i deploy/inventory.local.yml deploy/activate.yml -e '{"observer_activate":true}'
```

Activation rechecks files, credentials, reserved-placeholder rejection and real
sandbox/clock operation. A separate acceptance unit requires all configured
probes healthy, provider heartbeat accepted, no open incidents, no pending events
and no dropped events **before enabling the timer**. An acceptance-cycle failure leaves the timer
disabled. Earlier validation/preflight failure leaves existing timer state unchanged. Inspect reduced journal evidence, repair the cause and retry; do not
clear state to conceal failures. A previously opened incident may need two
healthy acceptance cycles and an additional cycle to deliver its recovery.

```sh
systemctl list-timers offsite-observer.timer
journalctl -u offsite-observer.service --since '-5 minutes' --no-pager
```

Finally stop the timer and worker, verify actual missing-heartbeat alert and
recovery on restart. Test loss of Telegram delivery using test-only credentials:
Healthchecks stays failed while the local spool is pending, including backoff.
Restore the credential, drain events in order and confirm both paths recover.
Do not simulate this by firewall changes on shared production infrastructure.
Complete encrypted backup and an isolated restore as described in
[Operations](OPERATIONS.md); retain operational evidence privately.
