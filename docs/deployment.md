# Deploying `verderer run` (M10 — continuous operation)

`verderer run` turns Verderer from a manual demo into a self-running watchdog: it re-observes the
curated set on each target's own cadence (`interval` in `data/targets.toml`, default 1 day),
observes only what is *due* through the polite M9 layer (robots.txt, per-host rate-limiting,
conditional GET), appends any diffs, and fires the alert pipeline (`verderer notify`) on each new
diff. Schedule state (`verderer-data/schedule-state.json`) persists per-target `next_due`, so a
restart resumes exactly where it left off — it never re-hits a target that ran minutes ago.

Two shapes:

- **`verderer run --once`** — process exactly the currently-due targets and exit. Ideal under an
  external timer (cron / systemd timer / a Kubernetes CronJob). One tick, then gone.
- **`verderer run`** — a long-lived loop: process the due set, sleep until the next target is
  due (capped by `--poll`, default 300 s, so config/state changes are picked up), repeat.
  Ideal as a supervised service (systemd, Docker, a process manager).

Both fire alerts by default; pass `--no-notify` to observe + record without alerting, and the
usual `--subscriptions` / `--smtp-*` / `--email-from` flags to configure delivery (see
`verderer notify --help` and `data/subscriptions.toml`).

The kernel binaries (`verderer-ledger`, `verderer-verify`) must be on `PATH` or discoverable next to
the repo (`cargo build --release --manifest-path rust/Cargo.toml`). The Python package must be
installed (`pip install -e .`). Run as an unprivileged user; the only writable state is
`--data-dir` (default `./verderer-data`).

---

## Option A — systemd service (long-lived loop)

`/etc/systemd/system/verderer.service`:

```ini
[Unit]
Description=Verderer watchdog (continuous re-observation + alerts)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=verderer
WorkingDirectory=/opt/verderer
Environment=PATH=/opt/verderer/.venv/bin:/opt/verderer/rust/target/release:/usr/bin:/bin
ExecStart=/opt/verderer/.venv/bin/python -m verderer --data-dir /var/lib/verderer run --poll 300
Restart=on-failure
RestartSec=30
# Hardening: Verderer needs only its data dir writable.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/verderer
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now verderer.service
journalctl -u verderer.service -f          # watch it observe + alert
```

## Option B — systemd timer (periodic `--once`)

Prefer this if you want the OS, not a long-lived process, to own the cadence.

`/etc/systemd/system/verderer.service` (oneshot):

```ini
[Unit]
Description=Verderer watchdog tick (one pass over the due set)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=verderer
WorkingDirectory=/opt/verderer
Environment=PATH=/opt/verderer/.venv/bin:/opt/verderer/rust/target/release:/usr/bin:/bin
ExecStart=/opt/verderer/.venv/bin/python -m verderer --data-dir /var/lib/verderer run --once
```

`/etc/systemd/system/verderer.timer`:

```ini
[Unit]
Description=Run Verderer every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now verderer.timer
```

The timer cadence is just how often Verderer *wakes up*; whether a target is actually re-observed
is decided per target by its `interval` (a 15-minute tick over a 12-hour target simply finds it
not due and does nothing — cheap).

## Option C — cron (periodic `--once`)

```cron
# m h dom mon dow   command
*/15 * * * *  cd /opt/verderer && .venv/bin/python -m verderer --data-dir /var/lib/verderer run --once >> /var/log/verderer.log 2>&1
```

## Option D — Docker

```dockerfile
FROM python:3.11-slim
# Build the Rust kernel in a builder stage (omitted) and COPY the two binaries onto PATH:
COPY --from=build /src/rust/target/release/verderer-ledger /usr/local/bin/
COPY --from=build /src/rust/target/release/verderer-verify /usr/local/bin/
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
VOLUME /data
ENTRYPOINT ["python", "-m", "verderer", "--data-dir", "/data"]
CMD ["run", "--poll", "300"]
```

```bash
docker build -t verderer .
docker run -d --name verderer -v verderer-data:/data --restart unless-stopped verderer
docker logs -f verderer
```

---

## Operating notes

- **Cadence lives in the data.** Set each target's `interval` (`"6h"`, `"12h"`, `"1d"`, `"90s"`)
  in `data/targets.toml`. Fast-moving or deletion-risk targets get a shorter interval; a large
  dataset that rarely changes gets a longer one. A frequent cadence on an unchanged page is
  cheap — the polite layer conditional-GETs, so the server returns a `304` and nothing is logged.
- **A tick is idempotent and crash-safe.** Schedule state is written atomically after each
  target, and alert delivery is de-duplicated per (subscription, event), so a killed process or
  an overlapping run never double-observes or double-alerts. A failed target is retried soon
  (a short, capped backoff), not dropped until its next full cycle.
- **Don't run two loops against one data dir.** They'd race on the ledger and schedule state.
  Pick the service *or* the timer, not both.
- **Verification is independent of the scheduler.** `verderer verify` and a downloaded proof
  bundle verify offline regardless of whether `verderer run` is up — the courtesy/scheduling layer
  is never part of the trust core.
