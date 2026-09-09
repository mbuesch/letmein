// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    Opts,
    limiter::{
        global::{GlobalLimiter, GlobalLimiterPermit},
        ip::{IpLimiter, IpLimiterPermit},
    },
    server::{Connection, ConnectionOps as _},
};
use std::sync::Arc;

mod global;
mod ip;

pub struct Limiter {
    ip_lim: Arc<IpLimiter>,
    global_lim: Arc<GlobalLimiter>,
}

impl Limiter {
    pub fn new(opts: &Opts) -> Self {
        Self {
            ip_lim: Arc::new(IpLimiter::new(
                opts.num_ip_connections.min(opts.num_connections),
            )),
            global_lim: Arc::new(GlobalLimiter::new(opts.num_connections)),
        }
    }

    pub async fn acquire_permit(&self, conn: &Arc<Connection>) -> Option<LimiterPermit> {
        let peer_ip = conn.peer_addr().ip();

        // Limit the number of simultaneous connections from the same IP address.
        let Some(ip_permit) = self.ip_lim.acquire_permit(peer_ip) else {
            conn.close().await;
            //TODO rate limit this message
            eprintln!(
                "Client '{peer_ip}': ERROR: \
                Too many simultaneous connections (ip_limiter). \
                Dropping connection."
            );
            return None;
        };

        // Acquire a global connection slot.
        let Some(global_permit) = Arc::clone(&self.global_lim)
            .acquire_permit(Arc::clone(conn))
            .await
        else {
            conn.close().await;
            //TODO rate limit this message
            eprintln!(
                "Client '{peer_ip}': ERROR: \
                Too many simultaneous connections (global limit). \
                Dropping connection."
            );
            return None;
        };

        Some(LimiterPermit::new(conn, global_permit, ip_permit))
    }
}

pub struct LimiterPermit {
    conn: Arc<Connection>,
    global_permit: GlobalLimiterPermit,
    ip_permit: IpLimiterPermit,
    dropped: bool,
}

impl LimiterPermit {
    fn new(
        conn: &Arc<Connection>,
        global_permit: GlobalLimiterPermit,
        ip_permit: IpLimiterPermit,
    ) -> Self {
        Self {
            conn: Arc::clone(conn),
            global_permit,
            ip_permit,
            dropped: false,
        }
    }

    /// Return the permit and close the connection.
    pub async fn drop_permit(mut self) {
        self.conn.close().await;
        self.dropped = true;
    }
}

impl Drop for LimiterPermit {
    fn drop(&mut self) {
        /* Must call drop_permit() instead of dropping. */
        assert!(self.dropped);

        let _ = self.global_permit;
        let _ = self.ip_permit;
    }
}

// vim: ts=4 sw=4 expandtab
