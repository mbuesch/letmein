// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::server::{Connection, ConnectionOps as _};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::yield_now,
};

#[derive(Debug)]
pub struct GlobalLimiter {
    sema: Arc<Semaphore>,
    conns: Mutex<BTreeMap<u64, Arc<Connection>>>,
}

impl GlobalLimiter {
    const MAX_ACQUIRE_TRIES: usize = 16;

    pub fn new(max_permits: usize) -> Self {
        Self {
            sema: Arc::new(Semaphore::new(max_permits)),
            conns: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn acquire_permit(
        self: Arc<Self>,
        conn: Arc<Connection>,
    ) -> Option<GlobalLimiterPermit> {
        for _ in 0..Self::MAX_ACQUIRE_TRIES {
            if let Ok(permit) = Arc::clone(&self.sema).try_acquire_owned() {
                self.conns
                    .lock()
                    .expect("Mutex poisoned")
                    .insert(conn.id(), Arc::clone(&conn));
                return Some(GlobalLimiterPermit {
                    permit,
                    lim: Arc::clone(&self),
                    conn,
                });
            }
            // If there are still unauthenticated connections, drop the oldest one.
            if !self.force_close_oldest_unauth_conn().await && self.sema.available_permits() == 0 {
                // No unauthenticated connections to drop and no available permits, give up.
                break;
            }
            // Let other connections and the possibly force-closed connection proceed.
            yield_now().await;
        }
        None
    }

    /// Drop the permit, but do not force-close the connection.
    /// The connection should have been closed already.
    fn drop_permit(&self, conn: &Connection) {
        self.conns
            .lock()
            .expect("Mutex poisoned")
            .remove(&conn.id());
    }

    /// Force-close the oldest unauthenticated connection, if any.
    /// And force-drop the permit, if any.
    async fn force_close_oldest_unauth_conn(&self) -> bool {
        let found = self
            .conns
            .lock()
            .expect("Mutex poisoned")
            .values()
            .find(|conn| !conn.is_authenticated())
            .map(Arc::clone);
        if let Some(conn) = found {
            // Force-close this connection on our end.
            // The force-closed connection will cause TX/RX to fail and
            // eventually the permit to be returned.
            conn.close().await;
            //TODO rate limit this message
            eprintln!(
                "WARNING: Force-closed oldest unauthenticated connection \
                {} \
                due to global limiter.",
                conn.peer_addr().ip(),
            );
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct GlobalLimiterPermit {
    permit: OwnedSemaphorePermit,
    lim: Arc<GlobalLimiter>,
    conn: Arc<Connection>,
}

impl Drop for GlobalLimiterPermit {
    fn drop(&mut self) {
        self.lim.drop_permit(&self.conn);
        let _ = self.permit;
    }
}

// vim: ts=4 sw=4 expandtab
