# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Do not publish an unpatched vulnerability, credentials, agent tokens, or a TinyWatch database in a public issue. Include the affected version, impact, and a minimal reproduction without real infrastructure details.

## Deployment guidance

- TinyWatch binds to localhost by default. Use a firewall and a trusted TLS reverse proxy before making the dashboard reachable beyond the local host.
- First-run setup requires a random one-time code printed to the server terminal. The code is not exposed by the API and expires after setup or process restart. Keep startup logs private until setup is complete.
- When TLS terminates at a trusted reverse proxy, start TinyWatch with `--secure-cookie`. TinyWatch does not trust forwarded client-address headers; apply login rate limits at the proxy because the backend sees the proxy's address.
- Distributed credentials are intentionally simple: each node uses one shared token. Bare IP:port addresses use HTTP and explicit HTTP/HTTPS URLs are accepted. HTTP transmits the token without encryption and is intended for trusted networks; HTTPS verifies certificates. TinyWatch refuses redirects so an agent token is not forwarded to another host.
- Password hashes, agent tokens, settings, history, and incident context (process and login observations) are stored in the JSON database. Protect the file, its `.bak` copy and the entire `.history/` shard directory; startup and retention changes prune expired samples from both. Rotate credentials if either file is exposed.
- Keep one TinyWatch process per data file. The JSON store provides atomic single-process writes and recovery, not concurrent multi-process transactions.
- If the primary JSON file is corrupt and a valid `.bak` exists, TinyWatch preserves the damaged file and restores the backup. If no valid copy exists, startup stops and leaves the files untouched.
- History collection runs in a background sampler. The dashboard serves a short-lived cluster snapshot cache; per-node collection failures remain visible without hiding metrics from other nodes.

Alert acknowledgement does not end an active incident. Collection errors or missing measurements are not treated as recovery. Historical-baseline detection is a local heuristic, not a guaranteed diagnosis; minute sampling can miss shorter events.

## Offline investigation reports

Reports include retained host observations, process names/PIDs, readable login context and manual notes. Export does not include administrator hashes, agent tokens, session cookies or dashboard configuration. Treat reports as infrastructure data. Reports are self-contained HTML with static SVG and no JavaScript or external assets; their content is escaped before export. The investigation and annotation APIs require an authenticated administrator session, not just an agent token.

## Explicit outbound monitoring and notification targets

Only authenticated administrators can configure service targets, maintenance windows and webhooks. Private/LAN targets are intentionally supported. Probes originate from the console host and expose no remote command facility. HTTP probes and webhooks disable environment proxy discovery, reject embedded URL credentials and do not follow redirects; HTTPS uses standard certificate verification. Socket timeouts do not provide a portable hard DNS deadline. Webhook URLs can contain secrets and remain in the protected JSON store; worker errors do not print them. A notification payload excludes collector observations and credentials. No test notification is sent during configuration.

### Scheduled task tokens and sharded history

Heartbeat job tokens authorize successful-run reports for one configured job only. They do not grant dashboard/agent access and are excluded from webhook payloads. Administrators can view the tokens; send them in `X-TinyWatch-Heartbeat`, never in URLs. Deleting a job invalidates its token. HTTP transport retains the existing trusted-network tradeoff.

Back up the JSON index, backup index and daily history directory as one stopped-instance snapshot. Checksums detect accidental damage, not malicious modification by a user who can write the data directory. Thirty-two request slots and socket inactivity timeouts bound some resource use; they are not a general hard deadline for DNS resolution or slow-trickle traffic.
