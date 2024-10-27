// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::firewall_client::FirewallClient;
use anyhow as ah;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const MON_ERROR_THRES: u32 = 3;
const MON_TIMEOUT: Duration = Duration::from_millis(1000 * 60 * 60 * 12);

//TODO for IPv6 use the net prefix as key.

struct MonitorData {
    errors: u32,
    timeout: Instant,
}

impl MonitorData {
    fn new() -> Self {
        Self {
            errors: 0,
            timeout: Instant::now() + MON_TIMEOUT,
        }
    }
}

struct MonitorInner {
    rundir: PathBuf,
    clients: HashMap<IpAddr, MonitorData>,
}

impl MonitorInner {
    fn new(rundir: PathBuf) -> Self {
        Self {
            rundir,
            clients: HashMap::new(),
        }
    }

    async fn maintenance(&mut self) {
        // Remove timed-out monitoring entries.
        let now = Instant::now();
        self.clients.retain(|_, mon_data| mon_data.timeout < now);
    }

    async fn log_client_error(&mut self, addr: IpAddr, error: ah::Error) {
        eprintln!("Client '{addr}' ERROR: {error}");

        // Remove timed-out monitoring entries.
        self.maintenance().await;

        // Get the monitoring state of this client.
        let mon_data = self.clients.entry(addr).or_insert_with(MonitorData::new);

        // Increment the error count.
        mon_data.errors = mon_data.errors.saturating_add(1);

        // If the error count is above a threshold, block the client.
        if mon_data.errors >= MON_ERROR_THRES {
            eprintln!("Monitor: Blocking client {addr}");

            // Connect to letmeinfwd unix socket.
            let mut fw = match FirewallClient::new(&self.rundir).await {
                Ok(fw) => fw,
                Err(e) => {
                    eprintln!("Monitor: Failed to connect to `letmeinfwd`: {e}");
                    return;
                }
            };

            // Block the IP address in the firewall.
            if let Err(e) = fw.block_addr(addr).await {
                eprintln!("Monitor: Failed block client {addr} via `letmeinfwd`: {e}");
                return;
            }

            // The client has been blocked in the firewall.
            // Do not track it in the monitoring any longer.
            self.clients.remove(&addr);
        }
    }

    async fn log_client_auth_ok(&mut self, addr: IpAddr) {
        // The client has successfully authenticated.
        // Do not track it in the monitoring any longer.
        self.clients.remove(&addr);

        // Remove timed-out monitoring entries.
        self.maintenance().await;
    }
}

pub struct Monitor {
    inner: Mutex<MonitorInner>,
}

impl Monitor {
    pub fn new(rundir: &Path) -> Self {
        Self {
            inner: Mutex::new(MonitorInner::new(rundir.to_path_buf())),
        }
    }

    pub async fn log_client_error(&self, addr: IpAddr, error: ah::Error) {
        self.inner.lock().await.log_client_error(addr, error).await;
    }

    pub async fn log_client_auth_ok(&self, addr: IpAddr) {
        self.inner.lock().await.log_client_auth_ok(addr).await;
    }
}

// vim: ts=4 sw=4 expandtab
