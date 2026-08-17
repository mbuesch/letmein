// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Structured security logging for letmeind.
//!
//! All security-relevant events are emitted as a single log line in a
//! consistent, machine-readable format that fail2ban filters and SIEMs
//! can parse reliably.
//!
//! # Line format
//!
//! ```text
//! letmeind: [<LEVEL>] <EVENT> peer=<IP> proto=<TCP|UDP> [key=value ...] -- <human message>
//! ```
//!
//! Journald captures stdout/stderr and adds the process name and PID automatically,
//! so the prefix `letmeind[<PID>]:` appears in syslog-forwarded output.
//!
//! # Levels
//!
//! | Token   | Use                                              |
//! |---------|--------------------------------------------------|
//! | `INFO`  | Normal operation events (successful knock, etc.) |
//! | `WARN`  | Suspicious but possibly legitimate events        |
//! | `ERROR` | Events that should never occur with a valid client |
//!
//! # Event keywords (stable - do not rename without updating fail2ban configs)
//!
//! | Keyword               | Meaning                                           |
//! |-----------------------|---------------------------------------------------|
//! | `CONN_ACCEPT`         | New connection accepted                           |
//! | `CONN_LIMIT_EXCEEDED` | Per-IP simultaneous connection limit exceeded     |
//! | `PREAUTH_TIMEOUT`     | Timeout before client sent initial message        |
//! | `POSTAUTH_TIMEOUT`    | Timeout after authentication during sequence      |
//! | `PROTOCOL_ABUSE`      | Wrong operation in sequence or ID mismatch        |
//! | `UNKNOWN_USER`        | User ID not found in server configuration         |
//! | `UNKNOWN_RESOURCE`    | Resource ID not found in server configuration     |
//! | `ACCESS_DENIED`       | Authenticated user not permitted for resource     |
//! | `AUTH_FAILURE`        | Cryptographic authentication (HMAC) check failed  |
//! | `KNOCK_SUCCESS`       | Firewall rule installed successfully              |
//! | `REVOKE_SUCCESS`      | Firewall rule revoked successfully                |
//! | `GOAWAY_SEND_FAILED`          | Could not send the GoAway rejection to client             |
//! | `FIREWALL_REBUILD_TRIGGERED`  | Lease removal failed; full nftables table rebuild invoked |
//! | `SECCOMP_ACTIVE`              | Seccomp syscall filter installed; `mode=log\|kill`        |
//! | `SECCOMP_DISABLED`            | Seccomp explicitly disabled. `[WARN]` on server/fwd, `[INFO]` on client |
//! | `SECCOMP_UNAVAILABLE`         | Architecture does not support seccomp                     |
//! | `IPC_MALFORMED_MESSAGE`       | letmeinfwd received a structurally invalid IPC message (missing checksum/address). `reason=` field |

/// Emit a structured security log line to stderr.
///
/// Two forms:
///
/// With extra key=value fields:
/// ```rust,ignore
/// log_security!(WARN, "AUTH_FAILURE", peer_ip, proto, "user=DEADBEEF stage=knock"
///     => "Initial knock authentication failed");
/// ```
///
/// Without extra fields:
/// ```rust,ignore
/// log_security!(WARN, "PREAUTH_TIMEOUT", peer_ip, proto
///     => "Connection timed out before client sent initial message");
/// ```
///
/// The `=>` separator splits machine-readable key=value pairs from the
/// human-readable description.  Both parts end up on the same line.
#[macro_export]
macro_rules! log_security {
    // With extra key=value fields:
    ($level:ident, $event:expr, $peer:expr, $proto:expr, $fields:expr => $msg:expr) => {
        eprintln!(
            "letmeind: [{}] {} peer={} proto={} {} -- {}",
            stringify!($level),
            $event,
            $peer,
            $proto,
            $fields,
            $msg,
        )
    };
    // Without extra fields:
    ($level:ident, $event:expr, $peer:expr, $proto:expr => $msg:expr) => {
        eprintln!(
            "letmeind: [{}] {} peer={} proto={} -- {}",
            stringify!($level),
            $event,
            $peer,
            $proto,
            $msg,
        )
    };
}

// vim: ts=4 sw=4 expandtab
