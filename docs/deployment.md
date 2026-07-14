# Deploying `druid run` (M10 — continuous operation)

`druid run` turns Druid from a manual demo into a self-running watchdog: it re-observes the
curated set on each target's own cadence (`interval` in `data/targets.toml`, default 1 day),
observes only what is *due* through the polite M9 layer (robots.txt, per-host rate-limiting,
conditional GET), appends any diffs, and fires the alert pipeline (`druid notify`) on each new
diff. Schedule state (`druid-data/schedule-state.json`) persists per-target `next_due`, so a
restart resumes exactly where it left off — it never re-hits a target that ran minutes ago.

Two shapes:

- **`druid run --once`** — process exactly the currently-due targets and exit. Ideal under an
  external timer (cron / systemd timer / a Kubernetes CronJob). One tick, then gone.
- **`druid run`** — a long-lived loop: process the due set, sleep until the next target is
  due (capped by `--poll`, default 300 s, so config/state changes are picked up), repeat.
  Ideal as a supervised service (systemd, Docker, a process manager).

Both fire alerts by default; pass `--no-notify` to observe + record without alerting, and the
usual `--subscriptions` / `--smtp-*` / `--email-from` flags to configure delivery (see
`druid notify --help` and `data/subscriptions.toml`).

The kernel binaries (`druid-ledger`, `druid-verify`) must be on `PATH` or discoverable next to
the repo (`cargo build --release --manifest-path rust/Cargo.toml`). The Python package must be
installed (`pip install -e .`). Run as an unprivileged user; the only writable state is
`--data-dir` (default `./druid-data`).

---

## Option A — systemd service (long-lived loop)

`/etc/systemd/system/druid.service`:

```ini
[Unit]
Description=Druid watchdog (continuous re-observation + alerts)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=druid
WorkingDirectory=/opt/druid
Environment=PATH=/opt/druid/.venv/bin:/opt/druid/rust/target/release:/usr/bin:/bin
ExecStart=/opt/druid/.venv/bin/python -m druid --data-dir /var/lib/druid run --poll 300
Restart=on-failure
RestartSec=30
# Hardening: Druid needs only its data dir writable.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/druid
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now druid.service
journalctl -u druid.service -f          # watch it observe + alert
```

## Option B — systemd timer (periodic `--once`)

Prefer this if you want the OS, not a long-lived process, to own the cadence.

`/etc/systemd/system/druid.service` (oneshot):

```ini
[Unit]
Description=Druid watchdog tick (one pass over the due set)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=druid
WorkingDirectory=/opt/druid
Environment=PATH=/opt/druid/.venv/bin:/opt/druid/rust/target/release:/usr/bin:/bin
ExecStart=/opt/druid/.venv/bin/python -m druid --data-dir /var/lib/druid run --once
```

`/etc/systemd/system/druid.timer`:

```ini
[Unit]
Description=Run Druid every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now druid.timer
```

The timer cadence is just how often Druid *wakes up*; whether a target is actually re-observed
is decided per target by its `interval` (a 15-minute tick over a 12-hour target simply finds it
not due and does nothing — cheap).

## Option C — cron (periodic `--once`)

```cron
# m h dom mon dow   command
*/15 * * * *  cd /opt/druid && .venv/bin/python -m druid --data-dir /var/lib/druid run --once >> /var/log/druid.log 2>&1
```

## Option D — Docker

```dockerfile
FROM python:3.11-slim
# Build the Rust kernel in a builder stage (omitted) and COPY the two binaries onto PATH:
COPY --from=build /src/rust/target/release/druid-ledger /usr/local/bin/
COPY --from=build /src/rust/target/release/druid-verify /usr/local/bin/
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .
VOLUME /data
ENTRYPOINT ["python", "-m", "druid", "--data-dir", "/data"]
CMD ["run", "--poll", "300"]
```

```bash
docker build -t druid .
docker run -d --name druid -v druid-data:/data --restart unless-stopped druid
docker logs -f druid
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
- **Verification is independent of the scheduler.** `druid verify` and a downloaded proof
  bundle verify offline regardless of whether `druid run` is up — the courtesy/scheduling layer
  is never part of the trust core.
