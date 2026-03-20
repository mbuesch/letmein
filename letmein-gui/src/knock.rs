// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use dioxus::prelude::*;
use letmein::{
    command::knock::{AddrMode, KnockResource, KnockServer, run_knock, run_revoke},
    resolver::{ResCrypt, ResSrv},
};
use letmein_conf::Config;
use letmein_proto::UserId;

#[derive(Clone, PartialEq, Eq)]
pub enum KnockStatus {
    Idle,
    InProgress,
    Success,
    Error(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KnockMode {
    Knock,
    Revoke,
}

impl std::fmt::Display for KnockMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnockMode::Knock => write!(f, "Knock"),
            KnockMode::Revoke => write!(f, "Revoke"),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn perform_knock(
    conf: Config,
    server: &str,
    resource: KnockResource,
    mode: KnockMode,
    key: &str,
    mut knock_states: Signal<std::collections::HashMap<String, KnockStatus>>,
    mut global_status: Signal<Option<(bool, String)>>,
    user_id_str: Option<&str>,
    port_override: Option<u16>,
) {
    if server.trim().is_empty() {
        global_status.set(Some((false, "Please add a server.".into())));
        return;
    }

    let resolve_srv = ResSrv::default().cloudflare(true).google(true).quad9(true);
    let resolve_crypt = ResCrypt::default();

    let user: Option<UserId> = match user_id_str {
        None => None,
        Some(s) => {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                match s.parse() {
                    Ok(uid) => Some(uid),
                    Err(e) => {
                        global_status.set(Some((
                            false,
                            format!("Invalid user ID '{s}' in server configuration: {e}"),
                        )));
                        return;
                    }
                }
            }
        }
    };

    knock_states
        .write()
        .insert(key.to_string(), KnockStatus::InProgress);
    global_status.set(None);

    spawn({
        let server = server.to_string();
        let key = key.to_string();

        async move {
            let knock_server = KnockServer {
                addr: &server,
                addr_mode: AddrMode::TryBoth,
                control_port_override: port_override,
                control_port_override_tcp: false,
                control_port_override_udp: false,
            };

            let result = if mode == KnockMode::Knock {
                run_knock(
                    &conf,
                    false,
                    knock_server,
                    resource,
                    user,
                    &resolve_srv,
                    &resolve_crypt,
                )
                .await
            } else {
                run_revoke(
                    &conf,
                    false,
                    knock_server,
                    resource,
                    user,
                    &resolve_srv,
                    &resolve_crypt,
                )
                .await
            };

            match result {
                Ok(()) => {
                    knock_states
                        .write()
                        .insert(key.clone(), KnockStatus::Success);
                    global_status.set(Some((true, format!("{mode} successful!"))));
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    knock_states
                        .write()
                        .insert(key.clone(), KnockStatus::Error(msg.clone()));
                    global_status.set(Some((false, msg)));
                }
            }
        }
    });
}

// vim: ts=4 sw=4 expandtab
