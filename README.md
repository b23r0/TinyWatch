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
| Services | HTTP/HTTPS, TCP and TLS certificate checks, webhook notifications and maintenance windows |
| Scheduled tasks | Start/success/failure reports, runtime limits, run history and recovery |
| Diagnostics | Collector errors, sample age, worker status, write failures and notification backlog |

The visible dashboard refreshes every 2.5 seconds; background tabs refresh every 30 seconds. The server records resource history and evaluates resource alerts every minute, including when no browser is open. Slow collectors refresh separately: processes every 10 seconds, disk/host details every 30 seconds, login/DNS details every 60 seconds.

## Remote hosts

1. Run TinyWatch on each host. Use `--host` and `--port` to make it reachable from the central instance.
2. Sign in to the remote instance and copy its agent token from **Assets**.
3. In the central instance, add the host name, address and token under **Assets**. An address such as `192.168.1.10:8765` uses HTTP; HTTPS URLs are also accepted.
4. Add dashboard cards for that host.

Hosts are sampled independently, with up to eight requests in flight and one per host. Successful hosts refresh approximately every five seconds while the dashboard is active, or once a minute when idle. Failures use backoff up to five minutes. Changing a host configuration resets its schedule; cached samples keep their source timestamp. A slow request does not delay completed hosts.

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

### Before and after a change

In **Investigate & replay**, move the cursor to a deployment note or another change, then select **Compare around cursor**. Choose a window of 5, 30 or 120 minutes on each side. The comparison includes resource sample medians and peaks, service mean durations and failed-check counts, and incident transitions.

Resource statistics use raw minute samples only; older compacted extrema are excluded. Percentage metric deltas are percentage points. Each side shows observed coverage, and a result is marked incomplete when coverage falls below 80% or the following window has not ended. Service statistics include failures and use only five-minute buckets fully inside the window; coverage is the span between observed checks in those buckets, not an uptime calculation. A change in metrics provides a lead for investigation, not proof that the deployment caused it.

### Incident recordings

Enable **local incident recording** in Settings. It is off by default. While enabled, a bounded memory buffer samples local resources every two seconds. A local incident saves up to five minutes before the trigger and continues for two minutes afterward. Open the recording from the incident card; charts share a cursor, and the process table shows the original process collector timestamp.

The recorder reuses existing collectors and caches. Process values still refresh on their ten-second schedule, and disk values on their thirty-second schedule. It does not execute extra process commands for every frame. Recordings contain resource values (disk use is the most occupied partition), up to three CPU-intensive processes and collector error names; they do not contain DNS entries or login records.

The ring holds at most 150 frames and 300,000 bytes of encoded samples. Stored clips are limited to 16, 211 frames each, and a 2 MiB budget, also subject to history retention. Oldest clips are removed when the budget is reached. Coverage measures recorded timestamps across the intended seven-minute window; missing values remain chart gaps. Frames are persisted at most every thirty seconds by the recorder, and can also be saved by other store writes. Graceful shutdown stops and flushes recordings; abrupt termination may lose recent frames. Remote incidents retain their ordinary trigger context.

### Rule preview

In the rule editor, choose a date/time interval and select **Preview rule** before saving. The result shows triggers, observed durations and intervals that could not be evaluated. Preview does not save rules, create incidents, send notifications or request remote metrics.

Only retained raw samples are evaluated. Compacted extrema cannot reconstruct sustained threshold violations and are marked unknown. Baseline evaluation uses only earlier samples, excluding the preceding ten minutes; an active simulated incident keeps its triggering baseline. Offline/stale rules are unavailable because their decision history is not recorded. A seven-day preview can therefore have low coverage even when charts contain older points.

One preview runs at a time. Intervals are limited to seven days, with a budget of 3,000 raw evaluations for baseline rules or 80,000 for fixed thresholds; choose a smaller interval or one host when needed. Results include at most 200 events across hosts. Unknown intervals make event durations incomplete, so the result is not an exact reconstruction of past alerts.

### Disk capacity outlook

Open disk details to view per-partition growth and estimated remaining days. The estimate uses the last seven days, requiring four days with samples in at least twelve distinct hours each, spanning at least three days. It uses the median of daily endpoint growth rates and rejects inconsistent trends.

No remaining-time estimate is shown after a capacity change, a gap longer than six hours, stale samples, insufficient data, unstable growth, or when the result exceeds one year. Flat/decreasing usage is shown separately. Forecasts assume the current growth trend continues; they are not reserved capacity or a guarantee. Unix hosts also show inode usage where `statvfs` provides it.

## Service checks and notifications

Open **Services** to configure up to 24 HTTP/HTTPS, TCP or TLS certificate monitors. Checks run from the **central instance**, regardless of the associated host. Host association controls incident ownership and maintenance scope.

- Interval: 30–3,600 seconds; socket timeout: 1–10 seconds; failure threshold: 1–10 consecutive checks. One successful check resolves the incident.
- TLS certificate checks verify the hostname and certificate chain, display the expiry date, and alert when validity falls below the selected 7, 14 or 30 days. Invalid certificates fail the check; failed verification does not expose expiry details. Checks use the existing failure threshold, maintenance and notification settings.
- HTTP checks compare an expected status code and optionally match literal UTF-8 text in the first 64 KiB. Redirects are rejected. TCP checks establish a connection only.
- Four checks can run concurrently. Missed runs are skipped. Each probe runs in a disposable subprocess with a total deadline of its configured socket timeout plus two seconds, including process startup, DNS and response reads. Asset requests have a twelve-second deadline and eight slots.
- Renaming preserves history. Interval, timeout and failure-threshold changes reset pending failure counts. Disabling closes the active incident. Changing the target, protocol, host or matching conditions resets that monitor's history.
- Charts show mean probe duration and sampled success over the latest 24 hours. Failed checks contribute to both statistics. This is not a time-weighted uptime calculation. Each monitor retains up to 2,048 five-minute buckets, also subject to the configured retention.

Service settings use revision numbers. If another session has saved newer settings, refresh before retrying. Failed configuration writes roll back the in-memory candidate.

### Webhooks

The **Notifications** tab accepts a generic HTTP/HTTPS JSON receiver. Notifications are disabled by default. Payloads contain incident and transition details, without credentials or process/login context.

The persistent queue holds up to 128 jobs. Delivery allows five attempts with backoff; jobs expire after 24 hours before delivery. A restart may repeat a successful request, so receivers should deduplicate `event_id`. The interface shows delivery status and dropped-notification warnings. Webhook URLs may contain secrets and are stored in the configuration file.

### Maintenance

Create up to 32 one-off windows for one host or all hosts, each lasting at most 30 days. Collection and incident tracking continue; notifications are held. Incidents still active when maintenance ends are notified. Incidents resolved during maintenance remain silent. Requests already in flight cannot be recalled.

### Scheduled tasks

Under **Services → Scheduled tasks**, add a job with an expected interval (1 minute–30 days), grace period (0–7 days), and maximum runtime (1 minute–7 days, default 60 minutes). Jobs use the existing incident, maintenance and notification settings. TinyWatch tracks reports; it does not execute tasks or parse cron expressions.

Use the task token in `X-TinyWatch-Heartbeat` for `POST /api/heartbeat`. Send a unique `run_id` for each execution:

```json
{"event":"start","run_id":"backup-20261002-01"}
```

```json
{"event":"success","run_id":"backup-20261002-01","duration_ms":1234,"message":"Backup complete"}
```

Report a failed completion with `"event":"fail"` and the same run ID. Start and failure reports require an ID. Messages are optional and limited to 240 characters; no command output is collected automatically. When duration is omitted, the server measures elapsed time from the accepted start, or records zero for completion-only reports.

A failure or exceeded runtime opens an incident. A success resolves the task incident and resets its expected-success deadline. While executions are running, their runtime limits replace the idle success-deadline check. Starting a task does not resolve an existing incident. Overlapping executions are marked; each job allows up to four simultaneous runs.

Recent executions appear in an expandable table. Each task keeps up to 50 runs within retention, preserving running entries. Repeated reports of the same retained ID and state are idempotent; conflicting completed results are rejected. A timed-out run can accept a late success/failure and retains its timeout marker. After an ID is pruned, it no longer provides deduplication.

The earlier `{"duration_ms":123}` format still reports success; every accepted report creates a separate completion entry. Invalid tokens return 403; invalid reports return 400; write failures return 503 and may be retried. Restarted instances check persisted starts for missed runtime limits.

## Data and backups

**Settings → Download backup** exports a consistent ZIP while the server runs. The archive contains both index generations and their referenced history files, including stored credentials. Compression runs outside the data lock; referenced shards remain protected from cleanup until the archive is complete. A single browser export runs at a time.

For command-line export, stop the instance first:

```sh
python3 tinywatch.py --data ./data/data.json --backup ./tinywatch-backup.zip
```

Restore into a **new directory** whose parent already exists, then start that instance:

```sh
python3 tinywatch.py --restore-backup ./tinywatch-backup.zip --data ./restored/data.json
python3 tinywatch.py --data ./restored/data.json
```

Restore checks filenames, manifests and shard checksums before publishing the directory. It refuses an existing destination directory. Archives are limited to 512 MiB of uncompressed data, 750 files, 8 MiB per index and 128 MiB per shard. For larger stores, use the stopped-instance directory backup below. ZIP backups are not encrypted.

History queries snapshot pending rows under the lock and read committed shards outside it. The shard cache holds up to eight files with a 32 MiB estimated object budget. Configuration changes share immutable history rows; heartbeat updates copy only the affected job buckets. Startup still loads retained history for compaction and baseline evaluation.

Asset diagnostics distinguish initialization, connection failure, stale samples and normal operation, and show consecutive failures and the next scheduled attempt. Initializing nodes are unknown to offline rules until a request completes.

Settings, task executions and bounded incident recordings are stored in a JSON index. Resource samples, process context and service buckets are stored in daily JSONL files under `<data-file>.history/`. Only changed dates are sorted and encoded during ordinary saves; retention, compaction and monitor removal also mark affected dates. Queries read selected days and overlay uncommitted samples. Shards are written before the index is atomically replaced. A previous index is kept at `<data-file>.bak`; cleanup preserves shards referenced by either index.

**Stop TinyWatch before backing up, then copy the JSON file, `.bak` and the entire `.history/` directory together.** Protect these files: they contain tokens, host observations and configuration.

Schema-1 databases, including embedded history and the earlier shard manifest, are read automatically. The next save writes schema 2; older versions reject that index. Do not downgrade against the migrated data. On startup, shard checksums are verified. A damaged generation is recovered from a valid backup; without one, startup stops.

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
| `--backup ZIP` | — | Export a stopped-instance backup and exit |
| `--restore-backup ZIP` | — | Validate and restore into a new data directory, then exit |
| `--version` | — | Print version and exit |

```bash
python3 tinywatch.py --port 9000 --data ./tinywatch-data.json
python3 tinywatch.py --host 0.0.0.0 --port 8765
```

`TINYWATCH_DATA` also sets the data path; `--data` takes precedence.

### Worker recovery

Diagnostics show progress, retries, the last exception type, and occupied/overdue request slots. Workers can retry three times within ten minutes, with backoff; a fourth failure stops the worker until a server restart. Exception messages that may contain targets or credentials are not exposed. Asset and service subprocesses are terminated and reaped after their deadlines. Replacement pools wait for existing requests to release their slots. Webhook delivery still uses socket timeouts rather than a subprocess deadline.

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
| `POST /api/alerts/preview` | Session; `{rule, start, end}`; read-only historical rule preview |
| `GET /api/capacity?node=local` | Session; per-partition capacity forecasts |
| `GET /api/agent/metrics` | `X-TinyWatch-Token`; local metrics |
| `POST /api/heartbeat` | `X-TinyWatch-Heartbeat`; task success report |

History example: `/api/history?node=local&metric=cpu&range=24h`.

Ranges: `1h`, `6h`, `24h`, `3d`, `7d`, `14d`, `30d`, or `custom` with Unix-second `start` and `end`. Queries must fit the retention window. Disk queries accept `partition=<id>` from the current metrics response; otherwise they show aggregate usage.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development commands and [SECURITY.md](SECURITY.md) for private vulnerability reports. CI uses Python and Node.js on Linux, Windows and macOS; Node.js is only a development tool.

## License

[MIT](LICENSE)
