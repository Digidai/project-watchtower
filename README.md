# Project Watchtower

Project Watchtower is a bounded monitoring agent for the public Digidai project surface.
It inventories GitHub repositories, checks known project URLs, records system/network
metrics, and writes auditable JSON/Markdown reports.

The implementation is intentionally conservative:

- no third-party Python dependencies
- no package manager requirement on the server
- explicit host allowlist
- per-request timeout
- per-request and per-run byte budgets
- low concurrency
- systemd CPU and memory limits
- optional forced-command SSH for GitHub Actions

## Quick Start

Local smoke run:

```bash
python3 -m watchtower.cli run --mode light --config config/targets.json --output-dir reports --max-urls 5 --no-fail
```

Deploy to the OCI instance without using `dnf`:

```bash
WATCHTOWER_HOST=<server-ip> \
WATCHTOWER_USER=opc \
WATCHTOWER_KEY=<path-to-ssh-key> \
WATCHTOWER_AUTHORIZED_KEY="$(cat .secrets/watchtower_ed25519.pub)" \
./scripts/deploy.sh
```

## Modes

- `light`: checks the curated core URL list hourly.
- `daily`: fetches the Digidai public repository inventory and checks repo homepages.
- `weekly`: reserved for deeper checks with a larger byte budget.

## GitHub Actions Setup

Create a dedicated SSH key for GitHub Actions, add the public key to the server
for a restricted `watchtower` login, then set repository secrets:

- `WATCHTOWER_HOST`
- `WATCHTOWER_USER`
- `WATCHTOWER_PORT`
- `WATCHTOWER_SSH_KEY`
- `WATCHTOWER_KNOWN_HOSTS`

The workflow sends only `light`, `daily`, or `weekly` as the SSH command. On the
server, `scripts/forced-command.sh` rejects every other command.

Recommended key setup:

```bash
mkdir -p .secrets
ssh-keygen -t ed25519 -C project-watchtower@github -f .secrets/watchtower_ed25519 -N ""
gh secret set WATCHTOWER_SSH_KEY < .secrets/watchtower_ed25519
gh secret set WATCHTOWER_HOST --body "<server-ip>"
gh secret set WATCHTOWER_USER --body "watchtower"
gh secret set WATCHTOWER_PORT --body "22"
ssh-keyscan -t ed25519 <server-ip> | gh secret set WATCHTOWER_KNOWN_HOSTS
```

## Safety Model

This project performs real health monitoring. It does not run artificial CPU
burners, traffic generators, stress tests, mining, or unrelated third-party
traffic. The byte budget exists to prevent runaway network usage, not to create
synthetic load.
