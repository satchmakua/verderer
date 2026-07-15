# Deploying `annals run` (M10 — continuous operation)

`annals run` turns Annals from a manual demo into a self-running watchdog: it re-observes the
curated set on each target's own cadence (`interval` in `data/targets.toml`, default 1 day),
observes only what is *due* through the polite M9 layer (robots.txt, per-host rate-limiting,
conditional GET), appends any diffs, and fires the alert pipeline (`annals notify`) on each new
diff. Schedule state (`annals-data/schedule-state.json`) persists per-target `next_due`, so a
restart resumes exactly where it left off — it never re-hits a target that ran minutes ago.

Two shapes:

- **`annals run --once`** — process exactly the currently-due targets and exit. Ideal under an
  external timer (cron / systemd timer / a Kubernetes CronJob). One tick, then gone.
- **`annals run`** — a long-lived loop: process the due set, sleep until the next target is
  due (capped by `--poll`, default 300 s, so config/state changes are picked up), repeat.
  Ideal as a supervised service (systemd, Docker, a process manager).

Both fire alerts by default; pass `--no-notify` to observe + record without alerting, and the
usual `--subscriptions` / `--smtp-*` / `--email-from` flags to configure delivery (see
`annals notify --help` and `data/subscriptions.toml`).

The kernel binaries (`annals-ledger`, `annals-verify`) must be on `PATH` or discoverable next to
the repo (`cargo build --release --manifest-path rust/Cargo.toml`). The Python package must be
installed (`pip install -e .`). Run as an unprivileged user; the only writable state is
`--data-dir` (default `./annals-data`).

---

## Option A — systemd service (long-lived loop)

`/etc/systemd/system/annals.service`:

```ini
[Unit]
Description=Annals watchdog (continuous re-observation + alerts)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=annals
WorkingDirectory=/opt/annals
Environment=PATH=/opt/annals/.venv/bin:/opt/annals/rust/target/release:/usr/bin:/bin
ExecStart=/opt/annals/.venv/bin/python -m annals --data-dir /var/lib/annals run --poll 300
Restart=on-failure
RestartSec=30
# Hardening: Annals needs only its data dir writable.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/annals
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now annals.service
journalctl -u annals.service -f          # watch it observe + alert
```

## Option B — systemd timer (periodic `--once`)

Prefer this if you want the OS, not a long-lived process, to own the cadence.

`/etc/systemd/system/annals.service` (oneshot):

```ini
[Unit]
Description=Annals watchdog tick (one pass over the due set)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=annals
WorkingDirectory=/opt/annals
Environment=PATH=/opt/annals/.venv/bin:/opt/annals/rust/target/release:/usr/bin:/bin
ExecStart=/opt/annals/.venv/bin/python -m annals --data-dir /var/lib/annals run --once
```

`/etc/systemd/system/annals.timer`:

```ini
[Unit]
Description=Run Annals every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now annals.timer
```

The timer cadence is just how often Annals *wakes up*; whether a target is actually re-observed
is decided per target by its `interval` (a 15-minute tick over a 12-hour target simply finds it
not due and does nothing — cheap).

## Option C — cron (periodic `--once`)

```cron
# m h dom mon dow   command
*/15 * * * *  cd /opt/annals && .venv/bin/python -m annals --data-dir /var/lib/annals run --once >> /var/log/annals.log 2>&1
```

## Option D — Docker

```dockerfile
FROM python:3.11-slim
# Build the Rust kernel in a builder stage (omitted) and COPY the two binaries onto PATH:
COPY --from=build /src/rust/target/release/annals-ledger /usr/local/bin/
COPY --from=build /src/rust/target/release/annals-verify /usr/local/bin/
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
VOLUME /data
ENTRYPOINT ["python", "-m", "annals", "--data-dir", "/data"]
CMD ["run", "--poll", "300"]
```

```bash
docker build -t annals .
docker run -d --name annals -v annals-data:/data --restart unless-stopped annals
docker logs -f annals
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
- **Verification is independent of the scheduler.** `annals verify` and a downloaded proof
  bundle verify offline regardless of whether `annals run` is up — the courtesy/scheduling layer
  is never part of the trust core.
