# Project Watchtower

Project Watchtower is a bounded monitoring agent for the public Digidai project surface.
It inventories GitHub repositories, checks known project URLs, records system/network
metrics, and writes auditable JSON/Markdown reports.
It also serves a read-only dashboard from the generated report directory.

The implementation is intentionally conservative:

- standard-library monitoring and dashboard; the root-only subscription adapter uses the server's existing PyYAML
- no package manager requirement on the server
- explicit host allowlist
- localhost and non-public IP literal checks for dynamically discovered hosts
- per-request timeout
- per-request and per-run byte budgets
- low concurrency
- systemd CPU and memory limits
- optional forced-command SSH for GitHub Actions

## Quick Start

Local smoke run:

```bash
python3 -m watchtower.cli run --mode core --config config/targets.json --output-dir reports --max-urls 5 --no-fail
```

Deploy to the provisioned OCI instance without using `dnf`. The private dashboard
ingress and root-only subscription settings described below must exist first:

```bash
WATCHTOWER_HOST=<server-ip> \
WATCHTOWER_USER=opc \
WATCHTOWER_KEY=<path-to-ssh-key> \
WATCHTOWER_AUTHORIZED_KEY="$(cat .secrets/watchtower_ed25519.pub)" \
WATCHTOWER_DASHBOARD_PASSWORD=<dashboard-password> \
./scripts/deploy.sh
```

## Modes

- `core`: checks the curated core URL list every 5 minutes with no GitHub inventory fetch.
- `self`: checks server resources, expected Watchtower timers, and the Oracle
  HY2/Xray/Trojan-WS residential proxy service path every 5 minutes.
- `github-lite`: checks recent GitHub project health about every 15 minutes with a small API and URL budget.
- `daily`: fetches the Digidai public repository inventory, checks repo homepages, samples README links, and checks recent repo workflow status.
- `weekly`: deeper checks with a larger URL and byte budget.
- `venture-discover`: refreshes the VentureDex profile/company cache hourly.
- `venture-check`: checks a rotating cached batch of VentureDex company homepages every 10 minutes.

## Dashboard

The dashboard serves `/var/lib/project-watchtower/reports/index.html` only on
`127.0.0.1:8765`, behind an authenticated Cloudflare Tunnel ingress. Public port 80
is closed; use `https://oracle.syncany.app/`, not the instance IP, to sign in.
The page aggregates the newest report per mode, self-check service state, resource metrics,
and current failures.
The self-check service state includes the Oracle HY2 residential proxy units,
the Trojan-WS TCP entry, local Xray listeners, direct residential Xray outbound
shape, SOCKS exit IP, and the Trojan-WS watchdog timer.
It is still rendered as dependency-free static HTML, with an in-page English/Chinese
language switch that stores the selected language in browser local storage.
The HTTP server disables directory listings and adds conservative response headers
for no-store caching, clickjacking protection, content-type sniffing protection,
and a self-only content security policy.
The server refuses to start without a password and `WATCHTOWER_ORIGIN_SECRET`.
Unauthenticated visitors see the restricted pre-launch page. Random server-side
sessions expire after eight hours, are revoked on logout, and use Secure/HttpOnly/
SameSite cookies. Login attempts are bounded per client and globally. Credentials
stay in root-only `/etc/project-watchtower/dashboard.env`, never in this repository.

## Cloudflare Domain

`oracle.syncany.app` is served through a Cloudflare Worker route:

- `oracle.syncany.app/*` -> `oracle-watchtower-proxy`
- `oracle.syncany.app` -> proxied A record for the public instance IP
- `oracle-origin.syncany.app` -> proxied CNAME to the named tunnel's `cfargotunnel.com` target

The Worker uses HTTPS to reach the tunnel, with a shared origin secret. The tunnel
uses authenticated encrypted outbound connections to Cloudflare, then loopback
HTTP to the dashboard; no cleartext traffic crosses the Internet. The Worker secret
`WATCHTOWER_ORIGIN_SECRET` must match the root-only server environment. Direct
requests to the origin without that secret fail closed. Keep the HY2 UDP and
Trojan TCP 443 listeners unchanged. Redeploy the Worker after proxy changes with:

```bash
wrangler deploy --config cloudflare/wrangler.oracle.jsonc
```

## Surge Stability

The Oracle proxy stack keeps two TCP paths available for the same Trojan-WS
entry:

- `v2-oracle.syncany.app:443` through Cloudflare, useful on networks where the
  origin IP is noisy or blocked.
- `159.54.189.18:443` with `sni=v2-oracle.syncany.app`, useful as the lower
  latency direct path when the network allows TCP 443 to the origin.

Keep the direct origin IP in Surge's `DIRECT` rules so proxy handshakes do not
loop back through the same policy group.

## GitHub Actions Setup

Create a dedicated SSH key for GitHub Actions, add the public key to the server
for a restricted `watchtower` login, then set repository secrets:

- `WATCHTOWER_HOST`
- `WATCHTOWER_USER`
- `WATCHTOWER_PORT`
- `WATCHTOWER_SSH_KEY`
- `WATCHTOWER_KNOWN_HOSTS`

The workflow sends only approved Watchtower modes as the SSH command. On the
server, `scripts/forced-command.sh` rejects every other command. If a server-side
timer is already running, GitHub-triggered runs return a bounded `busy` response
instead of opening a shell or stacking parallel jobs.

The GitHub workflow requests a 15-minute schedule and daily checks. GitHub may
delay or omit scheduled runs; the schedule is not an uptime guarantee. Independent
systemd timers provide the primary cadence. SSH errors and critical report failures
fail the workflow; lock contention is retried within a bounded window.

Recommended key setup:

```bash
mkdir -p .secrets
ssh-keygen -t ed25519 -C project-watchtower@github -f .secrets/watchtower_ed25519 -N ""
gh secret set WATCHTOWER_SSH_KEY < .secrets/watchtower_ed25519
gh secret set WATCHTOWER_HOST --body "<server-ip>"
gh secret set WATCHTOWER_USER --body "watchtower"
gh secret set WATCHTOWER_PORT --body "22"
# Verify the server fingerprint through a trusted channel before storing known_hosts.
```

## Safety Model

This project performs real health monitoring. It does not run artificial CPU
burners, traffic generators, stress tests, mining, or unrelated third-party
traffic. The byte budget exists to prevent runaway network usage, not to create
synthetic load.

URL failures are split into critical and observed failures. Curated core URLs are
critical; repo pages, repo homepages, README-discovered links, and VentureDex
company homepages are observed so that one stale upstream URL does not make the
server itself look broken.

## Proxy Operations

`ops/equaldcdn_sync.py` reads root-only `/etc/equaldcdn/subscription.json` (`url`
and `expected_ip`). Every 30 minutes it refreshes the subscription, verifies the
actual SOCKS exit, and preserves a healthy current node. Failover candidates must
pass an isolated exit test; changes are validated with Xray, written atomically,
and rolled back if the installed path fails. Ten private backups are retained.
The watchdog requires consecutive failures and a 15-minute recovery cooldown.
HY2 is kept alive during backend Xray restarts.

`ops/proxy_status.py` publishes only allowlisted, credential-free fields into
`/run/project-watchtower-status`. The unprivileged monitor reads those views,
checks their freshness, checks credential permissions and sync age, and reports
excessive switches. It cannot read live credentials or private backups.

Regression checks: `python3 -m unittest discover -s tests -v`.
Deployment includes bounded smoke checks and fails on missing/invalid summaries.
External project failures remain visible; they are not silently suppressed.
