<div align="center">

# TinyWatch

A server monitoring dashboard in one Python file.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB)](https://www.python.org/)
[![CI](https://github.com/b23r0/TinyWatch/actions/workflows/ci.yml/badge.svg)](https://github.com/b23r0/TinyWatch/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

**English** · [简体中文](README.zh-CN.md)

[Quick start](#quick-start) · [Features](#features) · [Remote hosts](#remote-hosts) · [Data and backups](#data-and-backups)

</div>

TinyWatch monitors local and remote servers from a browser. The collectors, HTTP API, HTML, CSS and JavaScript are included in `tinywatch.py`. It uses the Python standard library; there are no packages to install or frontend assets to download.

Supports Windows, Linux, macOS and other Unix systems. The dashboard works on desktop and mobile, with dark/light themes and English, Chinese, Japanese, French, Russian and German interfaces. English is the default.

## Quick start

```bash
git clone https://github.com/b23r0/TinyWatch.git
cd TinyWatch
python3 tinywatch.py
```

On Windows, use `py -3 tinywatch.py`.

Open [http://127.0.0.1:8765/](http://127.0.0.1:8765/). On first launch, enter the setup code printed in the server terminal and choose an administrator password of at least 10 characters. The code expires after setup or a server restart.

Python **3.10 or newer** is required. No build step is needed.

## Features

| Area | Details |
| --- | --- |
| Resources | CPU and individual cores, memory, disk partitions, network rates and interfaces, system load |
| Host details | Processor, OS and kernel versions, uptime, memory capacity and current sessions |
| Processes | CPU, memory, state and network activity where supported |
| Events and DNS | SSH/RDP login records and DNS cache, subject to OS support and permissions |
| Dashboard | Cards for different hosts and metrics, drag-to-reorder layout, mobile access |
| History | Date/time selection, chart axes, mouse/touch/keyboard inspection and collection gaps |
| Alerts | Thresholds, historical baselines, acknowledgement, recovery and trigger context |
| Investigation | Linked charts, change timeline, notes and offline HTML reports |
| Services | HTTP/HTTPS and TCP checks, webhook notifications and maintenance windows |
| Scheduled tasks | Success reports, missed-deadline alerts and recovery notifications |
| Diagnostics | Collector errors, sample age, worker status, write failures and notification backlog |

The visible dashboard refreshes every 2.5 seconds; background tabs refresh every 30 seconds. The server records resource history and evaluates resource alerts every minute, including when no browser is open. Slow collectors refresh separately: processes every 10 seconds, disk/host details every 30 seconds, login/DNS details every 60 seconds.

## Remote hosts

1. Run TinyWatch on each host. Use `--host` and `--port` to make it reachable from the central instance.
2. Sign in to the remote instance and copy its agent token from **Assets**.
3. In the central instance, add the host name, address and token under **Assets**. An address such as `192.168.1.10:8765` uses HTTP; HTTPS URLs are also accepted.
4. Add dashboard cards for that host.

Each node has one shared token. The central instance requests `/api/agent/metrics` with an `X-TinyWatch-Token` header and stores its own history. HTTP sends the token unencrypted; use it on a trusted network. HTTPS verifies certificates. Agent requests do not follow redirects.

Limits: **16 remote hosts** and **32 dashboard cards**.

## Alerts and investigation

Open **Alerts** to view incidents or change rules. Defaults apply to all hosts:

| Metric | Trigger | Recovery |
| --- | --- | --- |
| CPU / memory | Above 90% for 3 minutes | Below 85% |
| Disk | Most used partition above 90% for 5 minutes | Below 85% |
| Offline | Unreachable for 2 minutes | Reachable |

Resource rules have a five-minute cooldown after recovery. Rules can also monitor bandwidth, load and sample age, or select a particular disk partition. Older agents without partition details use aggregate disk usage.

Baseline rules use raw samples from the preceding 24 hours, excluding the latest 10 minutes, with at least 30 samples. The trigger is `median + max(minimum increase, 3 × 1.4826 × MAD)`; recovery uses 70% of the increase. The baseline stays fixed during an incident. Missing data does not count as recovery.

Incidents survive restarts. Acknowledgement does not close an incident. Up to 32 rules and 1,024 incidents are retained; old resolved incidents may be removed before the retention deadline when the limit is reached.

**Investigate & replay** opens resource charts on a shared time axis. Choose a host, partition and date/time range, add a deployment or maintenance note, or export a standalone HTML report. Reports include observations but exclude credentials and dashboard settings.

Recorded context includes the three busiest processes by CPU, recent readable login records, DNS count/source and collection errors. The timeline records observed reboots, system/interface/partition changes and new login records. These are sampled observations, not a complete audit log. Login timestamps in the timeline indicate when TinyWatch first observed the record.

## Service checks and notifications

Open **Services** to configure up to 24 HTTP/HTTPS or TCP monitors. Checks run from the **central instance**, regardless of the associated host. Host association controls incident ownership and maintenance scope.

- Interval: 30–3,600 seconds; socket timeout: 1–10 seconds; failure threshold: 1–10 consecutive checks. One successful check resolves the incident.
- HTTP checks compare an expected status code and optionally match literal UTF-8 text in the first 64 KiB. Redirects are rejected. TCP checks establish a connection only.
- Four checks can run concurrently. Missed runs are skipped. DNS resolution can exceed the socket timeout and occupy a worker; diagnostics show overdue checks.
- Renaming preserves history. Interval, timeout and failure-threshold changes reset pending failure counts. Disabling closes the active incident. Changing the target, protocol, host or matching conditions resets that monitor's history.
- Charts show mean probe duration and sampled success over the latest 24 hours. Failed checks contribute to both statistics. This is not a time-weighted uptime calculation. Each monitor retains up to 2,048 five-minute buckets, also subject to the configured retention.

Service settings use revision numbers. If another session has saved newer settings, refresh before retrying. Failed configuration writes roll back the in-memory candidate.

### Webhooks

The **Notifications** tab accepts a generic HTTP/HTTPS JSON receiver. Notifications are disabled by default. Payloads contain incident and transition details, without credentials or process/login context.

The persistent queue holds up to 128 jobs. Delivery allows five attempts with backoff; jobs expire after 24 hours before delivery. A restart may repeat a successful request, so receivers should deduplicate `event_id`. The interface shows delivery status and dropped-notification warnings. Webhook URLs may contain secrets and are stored in the configuration file.

### Maintenance

Create up to 32 one-off windows for one host or all hosts, each lasting at most 30 days. Collection and incident tracking continue; notifications are held. Incidents still active when maintenance ends are notified. Incidents resolved during maintenance remain silent. Requests already in flight cannot be recalled.

### Scheduled tasks

Under **Services → Scheduled tasks**, add a job with an expected interval (1 minute–30 days) and grace period (0–7 days). The deadline starts at creation and restarts after each successful report. A missed deadline opens an incident; a successful report resolves it. Jobs use the same notifications and maintenance windows as service checks.

After a successful run, report with that job's token:

```bash
curl --fail -X POST http://127.0.0.1:8765/api/heartbeat \
  -H 'Content-Type: application/json' \
  -H 'X-TinyWatch-Heartbeat: YOUR_TASK_TOKEN' \
  --data '{"duration_ms":123}'
```

Report only successful completion. Invalid tokens return 403; write failures return 503 and can be retried. Each accepted report counts as a new success. TinyWatch checks elapsed intervals; it does not parse cron expressions or execute tasks.

## Data and backups

Settings are stored in a JSON index. Resource samples, process context and service buckets are stored in daily JSONL files under `<data-file>.history/`. Shards are written before the index is atomically replaced. A previous index is kept at `<data-file>.bak`; cleanup preserves shards referenced by either index.

**Stop TinyWatch before backing up, then copy the JSON file, `.bak` and the entire `.history/` directory together.** Protect these files: they contain tokens, host observations and configuration.

Existing schema-1 databases with embedded history are read automatically and migrated on the next save. Older versions cannot read the new history manifest; do not downgrade against the migrated data. On startup, shard checksums are verified. A damaged generation is recovered from a valid backup; without one, startup stops.

Retention can be set to **1, 3, 7, 14 or 30 days**, with a default of 7. Reducing it removes expired history from both stored generations.

| Age | Retained samples |
| --- | --- |
| Last 24 hours | Original minute samples |
| 1–7 days | First, last, minimum and maximum per five-minute bucket |
| Older than 7 days | First, last, minimum and maximum per hourly bucket |

Retained values keep their actual timestamps. Charts preserve collection gaps and return at most 1,200 points per query. Older samples cannot reconstruct every minute or the exact duration of a peak. Retained history still loads into memory for queries and baselines; sharding reduces repeated writes, not memory usage. Run only one TinyWatch process per data file.

## Configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Listen address |
| `--port` | `8765` | HTTP port |
| `--data` | `~/.tinywatch/data.json` | JSON index path |
| `--secure-cookie` | Off | Mark session cookies Secure when HTTPS is provided by a reverse proxy |
| `--version` | — | Print version and exit |

```bash
python3 tinywatch.py --port 9000 --data ./tinywatch-data.json
python3 tinywatch.py --host 0.0.0.0 --port 8765
```

`TINYWATCH_DATA` also sets the data path; `--data` takes precedence.

## Platform and deployment notes

- Optional native commands such as PowerShell, `ss`, `journalctl`, `who` and `netstat` are used where available. They are not Python package dependencies.
- Per-process network rates currently rely on Linux `ss` counters and permissions. Other platforms may show socket counts or no network rate.
- Login records and DNS cache depend on OS interfaces and permissions. Some systems use the hosts file as a DNS fallback. An empty panel does not establish that no events occurred.
- Windows has no Unix load average; its load panel uses a CPU reference value.
- The built-in server uses HTTP and binds to localhost by default. For access outside a trusted network, use a TLS reverse proxy with `--secure-cookie`, keep the backend on localhost and restrict access. TinyWatch does not trust forwarded address headers; the proxy should handle client login rate limits.
- Passwords use salted PBKDF2-HMAC-SHA256 hashes. Setup codes, passwords and tokens should not be shared in issue reports.
- HTTP connections have a 10-second inactivity timeout and a 32-request concurrency limit. These are not hard deadlines for DNS resolution or slow-trickle traffic.

## API

| Route | Authentication / purpose |
| --- | --- |
| `GET /api/status` | Setup and session status |
| `POST /api/setup` | Setup code; create administrator password |
| `POST /api/login`, `POST /api/logout` | Start / end session |
| `GET/POST /api/config` | Session; assets, cards, theme and retention |
| `GET /api/metrics`, `GET /api/history` | Session; live metrics and retained samples |
| `GET/POST /api/alerts` | Session; rules, incidents and acknowledgement |
| `GET/POST /api/services` | Session; checks, tasks, maintenance and webhooks; writes require the current `revision` |
| `GET /api/investigation` | Session; host and exact `start`/`end` interval, optional `partition` |
| `POST /api/annotations` | Session; add `{node, timestamp, message}` or remove `{action: "remove", id}` |
| `GET /api/diagnostics` | Session; host and monitor health |
| `GET /api/agent/metrics` | `X-TinyWatch-Token`; local metrics |
| `POST /api/heartbeat` | `X-TinyWatch-Heartbeat`; task success report |

History example: `/api/history?node=local&metric=cpu&range=24h`.

Ranges: `1h`, `6h`, `24h`, `3d`, `7d`, `14d`, `30d`, or `custom` with Unix-second `start` and `end`. Queries must fit the retention window. Disk queries accept `partition=<id>` from the current metrics response; otherwise they show aggregate usage.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development commands and [SECURITY.md](SECURITY.md) for private vulnerability reports. CI uses Python and Node.js on Linux, Windows and macOS; Node.js is only a development tool.

## License

[MIT](LICENSE)
