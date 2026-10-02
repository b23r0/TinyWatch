# Contributing to TinyWatch

TinyWatch keeps its runtime intentionally small: the application, HTTP API, collectors, and embedded browser UI live in `tinywatch.py` and use only Python's standard library. Tests and project documentation are separate development files and do not add runtime dependencies.

## Development setup

Use Python 3.10 or newer. No package installation or frontend build is required.

```bash
python -m py_compile tinywatch.py
python -m unittest discover -s tests -v
python scripts/check_inline_js.py
```

The Python checks use only the standard library. The embedded UI check uses Node.js 20 to parse the inline script and verify peak/gap preservation, sparse retained history, six-language labels, and escaped incident observations without a browser or network; Node is a development tool and is not needed to run TinyWatch. GitHub Actions runs all checks on Linux, Windows, and macOS with Python 3.10 and 3.12. Keep regression tests self-contained; do not add remote assets, real credentials, or host-specific assumptions.

## Change guidelines

- Keep monitoring data collection best-effort and report unavailable platform capabilities clearly.
- Isolate collector errors so one unavailable subsystem does not fail a complete host snapshot; avoid writing fabricated zero values to history for failed collectors.
- Preserve alert deduplication across restarts, hysteresis and cooldown; unknown measurements must never count as recovery. Retain trigger context as observations, not a claimed diagnosis.
- Keep history sampling independent of authenticated browser polling and retain a bounded cache for remote node snapshots.
- Keep chart and UI assets embedded. Do not add CDN scripts, remote fonts, or external stylesheets.
- Preserve backward compatibility for the JSON schema, or include an explicit recovery/migration path.
- Never log passwords, session cookies, or agent tokens. Keep the per-node shared-token model simple. HTTP is supported for trusted networks; HTTPS must verify certificates and token-bearing requests must not follow redirects.
- Keep changes focused, document user-visible behavior, and add regression coverage for persistence and security-sensitive paths.
- Run the syntax and unit checks above before opening a pull request. Include the operating system and Python version if a failure is platform-specific.

## Pull requests

Describe the user-visible change, its platform impact, and the verification performed. Do not include real host names, database files, tokens, or screenshots containing private infrastructure details.

## Collection and replay invariants

- Independent collector caches use monotonic expiry. Preserve individual wall-clock timestamps and error status; do not relabel cached details as newly collected.
- Disk overview charts are aggregate usage; default disk alerts inspect the most used partition. Partition keys derive from device and mount, and capacities that change must interrupt the plotted series.
- Baselines consume raw minute samples only. Compacted extreme points cannot represent an unbiased distribution.
- Replay reads persisted data without contacting agents. All charts share bounds and report nearest observed timestamps instead of synthetic values. Keep context/event budgets and explicit gaps.
- HTML report exports must contain no credential/configuration payload, executable script or remote assets. Escape all host observations and user notes. Preserve the six-language message arrays for new controls.

## Service/notification worker invariants

- Slow collectors publish immutable cache entries under a short lock and run without the fast resource snapshot lock. Resource requests return the last detail sample with its original timestamp/error, or an explicit pending state.
- Keep at most four outstanding probes, skip missed ticks, prefer oldest due work, and reject completions from edited/removed monitor configurations. Keep DNS and response reads inside the disposable probe subprocess deadline; kill and reap timed-out children. Do not launch replacement work before the previous slot is released.
- Probe success ratios describe sampled checks, not time-weighted uptime. Preserve bounded buckets and failure-gap semantics.
- Deliver webhook transitions outside collector/store locks. Persist stable event IDs, finite retries and expiry. Receivers deduplicate; never claim exactly-once delivery.
- Maintenance suppresses notifications, not collection or incident tracking. A held job must not starve other assets. Do not add arbitrary command execution to service monitors.

## Storage and configuration invariants

Keep legacy embedded-history loading, checksum-checked daily shard manifests, atomic index publication, and both generations' shard references intact. No cleanup may delete shards still referenced by the main or backup index. Configuration edits must preserve measurements when only presentation changes, reject stale service revisions, and roll back candidate state on persistence failure. Heartbeat jobs reuse incidents/maintenance and must not execute task commands or expose their token in notification payloads.

Use an isolated data directory for migration and write-failure checks. Cover renamed monitors, stale revisions, shard recovery and heartbeat deadlines; do not use a running instance’s database.

## Sampling and preview behavior

Asset completions publish independently. Keep one request per asset, a bounded shared pool, monotonic retry scheduling, and configuration checks before accepting results. Browser requests must not wait for all remote hosts.

Mark changed history dates for append, pruning, compaction and monitor deletion. Clear dirty dates only after the index commits; readers overlay uncommitted data. Schema 1 remains readable, while new writes use schema 2.

Rule preview is read-only and uses past raw samples only. Do not infer sustained violations from compacted extrema, fill missing intervals with zero, or resolve simulated incidents across unknown data. Capacity estimates require sufficient coverage and stable capacity; keep refusal reasons visible.

History readers pin immutable shard names before leaving the data lock. Cleanup must retain every pinned file. Cache entries are shared read-only; returned points must be copied. Configuration transactions may share immutable history rows, but heartbeat transactions must copy every bucket they update. Backup compression must run outside the data lock, and restore must validate in a new private staging directory before publication.

Change comparison uses raw resource samples for medians and observed intervals for coverage. Do not treat compacted extrema as equally weighted samples or claim that metric changes establish causation. Service comparison must exclude buckets crossing a window boundary.

Run IDs provide deduplication only while their records are retained. Preserve running entries within the per-task cap, keep timeout markers for late completions, and roll back run state with incident and history changes after a failed write. Legacy completion reports remain supported.

Incident recording is local and opt-in. Reuse collector timestamps, preserve missing-data gaps, and keep both the memory ring and persisted clips bounded. The recorder never holds its ring lock while taking the store lock. Shutdown should flush pending frames without starting a new collector.
