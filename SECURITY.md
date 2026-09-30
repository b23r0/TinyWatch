# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Do not publish an unpatched vulnerability, credentials, agent tokens, or a TinyWatch database in a public issue. Include the affected version, impact, and a minimal reproduction without real infrastructure details.

## Deployment guidance

- TinyWatch binds to localhost by default. Use a firewall and a trusted TLS reverse proxy before making the dashboard reachable beyond the local host.
- Remote asset URLs must use HTTPS with a valid certificate. HTTP is permitted only for localhost and IP loopback addresses. TinyWatch refuses redirects so an agent token is not forwarded to another host.
- Password hashes, agent tokens, settings, and history are stored in the JSON database. Protect the file and its `.bak` copy; startup and retention changes prune expired samples from both. Rotate credentials if either file is exposed.
- Keep one TinyWatch process per data file. The JSON store provides atomic single-process writes and recovery, not concurrent multi-process transactions.
- If the primary JSON file is corrupt and a valid `.bak` exists, TinyWatch preserves the damaged file and restores the backup. If no valid copy exists, startup stops and leaves the files untouched.
