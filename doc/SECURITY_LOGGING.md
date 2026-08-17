# letmeind Security Logging

letmeind emits structured security log lines for all authentication and connection
events. These logs are designed to be parsed by **fail2ban**, **SIEM** systems,
and other intrusion-detection tools.

## Log format

```
letmeind: [<LEVEL>] <EVENT> peer=<IP> proto=<TCP|UDP> [key=value ...] -- <human message>
```

| Field | Description |
|---|---|
| `LEVEL` | `INFO`, `WARN`, or `ERROR` (see below) |
| `EVENT` | Stable keyword identifying the event type (never changes between releases) |
| `peer=` | IP address of the remote client |
| `proto=` | Transport protocol: `TCP` or `UDP` |
| `key=value` | Optional structured fields relevant to the event |
| `--` | Separator between machine-readable fields and the human message |

### Log levels

| Token | Meaning |
|---|---|
| `INFO` | Normal, expected events |
| `WARN` | Suspicious events that a legitimate client should not produce |
| `ERROR` | Events that a legitimate, correctly configured client will never produce |

Under systemd/journald, stdout and stderr are captured automatically. The process name
and PID are prepended by the journal, so a forwarded syslog entry looks like:

```
letmeind[1234]: letmeind: [WARN] AUTH_FAILURE peer=192.0.2.50 proto=TCP user=DEADBEEF resource=0000539F stage=knock -- Initial knock authentication (HMAC) failed
```

## Event keyword reference

These keywords are **stable** - they will not be renamed without a deprecation notice.
Use them as anchors in fail2ban filter `failregex` and SIEM pattern rules.

| Keyword | Level | Fail2ban target | Description |
|---|---|---|---|
| `CONN_LIMIT_EXCEEDED` | WARN | yes | Per-IP simultaneous connection limit exceeded. Possible scanner or DoS. |
| `PREAUTH_TIMEOUT` | WARN | yes | Client connected but did not send any data within the timeout. Possible scanner or Slowloris attempt. |
| `POSTAUTH_TIMEOUT` | WARN | no | Timeout during the challenge-response sequence after basic auth. |
| `AUTH_FAILURE` | WARN | yes | HMAC authentication check failed. Wrong key, brute-force, or replay attempt. `stage=knock` is the first check; `stage=challenge-response` is the full check. |
| `UNKNOWN_USER` | WARN | yes | User ID in the knock packet is not in the server configuration. |
| `UNKNOWN_RESOURCE` | WARN | yes | Resource ID is not in the server configuration (after basic auth). |
| `ACCESS_DENIED` | WARN | yes | Authenticated user is not permitted to access the requested resource. |
| `PROTOCOL_ABUSE` | ERROR | yes (maxretry=1) | Wrong message operation in the handshake sequence, or user/resource ID changed mid-session. A legitimate client will never produce this. |
| `KNOCK_SUCCESS` | INFO | no | Firewall rule installed. `user=` and `resource=` identify what was opened. |
| `REVOKE_SUCCESS` | INFO | no | Firewall rule removed. |
| `GOAWAY_SEND_FAILED`  | WARN | no | Server tried to send a rejection message to the client but the write failed. |
| `SECCOMP_ACTIVE`        | INFO | no | Seccomp syscall filter installed at startup. `mode=log` or `mode=kill`. |
| `SECCOMP_DISABLED`      | WARN (server/fwd), INFO (client) | no | Seccomp explicitly disabled in configuration. The server (`letmeind`) and firewall daemon (`letmeinfwd`) use `WARN` because disabling seccomp on a long-running daemon is a meaningful security reduction. The client (`letmein`) uses `INFO` because seccomp-off is a common and expected client configuration. |
| `SECCOMP_UNAVAILABLE`   | WARN | no | Architecture does not support seccomp; filter not active. |
| `SERVER_REPLY_MISMATCH` | WARN | no | **Client-side.** Server replied with a different user or resource ID than was sent. Possible rogue server or MitM. Emitted by the `letmein` client. |
| `DNS_FALLBACK`          | WARN/INFO | no | **Client-side.** System DNS resolver failed; falling back to external resolvers. `WARN` when visible to the user; `INFO` on a quiet retry. `host=` and `addr_type=` fields identify the lookup. |
| `CONFIG_INSECURE_OWNERSHIP`      | WARN | no | Config file is not owned by the expected UID. `path=`, `actual_uid=`, `expected_uid=` fields. Server only. |
| `CONFIG_INSECURE_PERMISSIONS`    | WARN | no | Config file has overly permissive mode bits. `path=`, `mode=`, `recommended=` fields. Server only. |
| `CONFIG_PERMISSION_CHECK_FAILED` | WARN | no | Could not stat the config file to check permissions. `path=` field. Server only. |
| `UDP_MALFORMED_PACKET`    | WARN | no | UDP datagram received with wrong size. `peer=` (IP only), `expected_size=`, `actual_size=` fields. |
| `UDP_QUEUE_OVERFLOW`      | WARN | no | Single peer flooded the UDP RX queue; connection dropped. `peer=` (IP only), `queue_max=` fields. |
| `UDP_CONN_LIMIT_EXCEEDED`  | WARN | no | UDP connection table full; new connection dropped. `peer=` (IP only), `conn_max=` fields. |
| `FIREWALL_RULE_SKIPPED`    | WARN | no | A firewall rule could not be installed - either the nftables rule comment exceeded the kernel length limit, or the client's IP version is incompatible with the configured nftables family. `reason=`, `peer=` fields. The knock fails safely (port stays closed). |

The `letmeinfwd` firewall daemon emits these additional events directly to stderr:

| Line fragment | Meaning |
|---|---|
| `letmeinfwd: [INFO] LEASE_EXPIRED --` | A timed-out firewall lease was removed. |
| `letmeinfwd: [WARN] FIREWALL_REBUILD_TRIGGERED --` | A lease rule removal failed; letmeinfwd triggered a full nftables table rebuild. |
| `letmeinfwd: [ERROR] FIREWALL_SHUTDOWN_FAILED --`   | Firewall rules could not be removed on daemon shutdown. Leased ports may remain open. |
| `letmeinfwd: [WARN] IPC_CONF_MISMATCH --`           | letmeind and letmeinfwd loaded different config checksums. Firewall request rejected. |
| `letmeinfwd: [ERROR] IPC_UNAUTHORIZED_CONNECT --`   | Something other than letmeind connected to the firewall IPC socket. `connected_pid/uid/gid=` and `expected_*=` fields. |
| `letmeinfwd: [WARN] IPC_MALFORMED_MESSAGE --`       | letmeinfwd received a structurally invalid IPC message (missing checksum or missing client address). `reason=` field. A correctly functioning letmeind will never produce this. |


## Example log lines

```
# Successful knock
letmeind: [INFO] KNOCK_SUCCESS peer=192.168.1.10 proto=TCP user=A1B2C3D4 resource=0000539F -- Resource 0000539F successfully knocked. Firewall rules changed.

# Wrong key / brute force
letmeind: [WARN] AUTH_FAILURE peer=192.168.1.50 proto=TCP user=DEADBEEF resource=0000539F stage=knock -- Initial knock authentication (HMAC) failed

# Challenge-response replay / MitM
letmeind: [WARN] AUTH_FAILURE peer=192.168.1.50 proto=TCP user=DEADBEEF resource=0000539F stage=challenge-response -- Challenge-response authentication (HMAC) failed

# Scanner / Slowloris
letmeind: [WARN] PREAUTH_TIMEOUT peer=198.51.100.7 proto=TCP -- Connection timed out before client sent initial message

# Malformed / junk packet (operation out of sequence)
letmeind: [ERROR] PROTOCOL_ABUSE peer=198.51.100.7 proto=UDP expected=[Knock, Revoke] got=ComeIn -- Unexpected message operation - protocol sequence violated

# Connection flood from one IP
letmeind: [WARN] CONN_LIMIT_EXCEEDED peer=10.0.0.1 proto=TCP -- Per-IP simultaneous connection limit exceeded. Connection dropped.

# Unknown user probe
letmeind: [WARN] UNKNOWN_USER peer=203.0.113.99 proto=TCP user=CAFEBABE -- User ID not found in server configuration

# Expired firewall lease (from letmeinfwd)
letmeinfwd: [INFO] LEASE_EXPIRED -- Lease(client_addr=192.168.1.10, Port(443/TCP))
```

## Fail2ban integration

See `scripts/fail2ban/` for ready-to-use filter and jail configuration files.

### Quick start

```bash
# Copy files into place
sudo cp scripts/fail2ban/filter.d/letmeind.conf /etc/fail2ban/filter.d/
sudo cp scripts/fail2ban/jail.d/letmeind.conf   /etc/fail2ban/jail.d/

# Reload fail2ban
sudo systemctl reload fail2ban

# Verify the filter matches your logs
sudo fail2ban-regex /var/log/syslog /etc/fail2ban/filter.d/letmeind.conf
# (or use journalctl output if syslog forwarding is not configured)
```

### Journald without syslog forwarding

If your system uses journald but does not forward to `/var/log/syslog`, configure
the jail to read from the journal:

```ini
[letmeind-auth]
backend = systemd
journalmatch = SYSLOG_IDENTIFIER=letmeind
```

### Recommended jail strategy

| Jail | Event(s) | `maxretry` | `findtime` | `bantime` |
|---|---|---|---|---|
| `letmeind-auth` | `AUTH_FAILURE`, `UNKNOWN_USER`, `ACCESS_DENIED` | 5 | 60s | 600s |
| `letmeind-abuse` | `PROTOCOL_ABUSE` | 1 | 60s | 86400s |
| `letmeind-scan` | `PREAUTH_TIMEOUT`, `CONN_LIMIT_EXCEEDED` | 3 | 30s | 3600s |
| `letmeind-probe` | `UNKNOWN_RESOURCE` | 10 | 120s | 300s |

A single `PROTOCOL_ABUSE` event is a strong indicator of automated scanning or
exploit tooling - ban immediately (`maxretry=1`) and for a long period.

`AUTH_FAILURE` at `stage=challenge-response` means the attacker passed the initial
HMAC check (they know a valid user ID and resource ID) but failed the replay-safe
part. This is more serious than a basic `stage=knock` failure.

## SIEM integration

The structured `key=value` fields before `--` can be extracted with most log
parsers. Example Grok pattern for Elastic/Logstash:

```
letmeind: \[%{WORD:level}\] %{WORD:event} peer=%{IP:src_ip} proto=%{WORD:proto}( %{DATA:kv_fields})? -- %{GREEDYDATA:message}
```

Suggested alert rules:

- Alert on any `ERROR` level event from a new source IP.
- Alert on `AUTH_FAILURE` count > 10 from the same IP within 5 minutes.
- Alert on `PROTOCOL_ABUSE` - any occurrence warrants investigation.
- Dashboard: `KNOCK_SUCCESS` / `REVOKE_SUCCESS` events show which users are accessing which resources and from where.

## Log management

letmein and letmeind write all output to **stderr**. On Linux with systemd this is captured by journald automatically — no log files or rotation configuration are needed. View live daemon logs with `journalctl -u letmeind.service -f`, or filter for security events with `journalctl -u letmeind.service | grep -E '\[(WARN|ERROR)\]'`. For explicit retention, set `MaxRetentionSec=90day` and `SystemMaxUse=500M` in `/etc/systemd/journald.conf` (90 days is the minimum recommended for security audit). If you forward to syslog, filter on `$programname == 'letmeind'` in rsyslog or `program("letmeind")` in syslog-ng and apply standard logrotate with `rotate 90`.

On systems without systemd (OpenRC, runit, s6) redirect stderr to `/var/log/letmeind.log` in your service definition and apply the logrotate config above. The `letmein` client is short-lived and emits at most one or two lines per invocation; log volume is negligible on all platforms. On macOS, pipe through `logger -t letmein` to send to the Unified Logging system. On Windows, redirect stderr to a file with `2>letmein.log` and rotate weekly if needed.
