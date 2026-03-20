// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{Screen, top_bar::TopBar};
use crate::{
    config::{ServerEntry, resource_display_name},
    knock::{KnockMode, KnockStatus, perform_knock},
};
use dioxus::prelude::*;
use letmein::command::knock::KnockResource;
use letmein_conf::Config;
use std::collections::HashMap;

#[component]
pub(super) fn MainScreen(
    screen: Signal<Screen>,
    config: Signal<Config>,
    server_list: Signal<Vec<ServerEntry>>,
    mut selected_server_idx: Signal<usize>,
    knock_mode: Signal<KnockMode>,
) -> Element {
    let knock_states: Signal<std::collections::HashMap<String, KnockStatus>> =
        use_signal(HashMap::new);
    let mut global_status = use_signal(|| Option::<(bool, String)>::None);

    let mut error_gen = use_signal(|| 0_u64);
    use_effect(move || {
        if matches!(global_status(), Some((false, _))) {
            let egen = *error_gen.peek() + 1;
            error_gen.set(egen);
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                // Only clear if no newer error has arrived since we were spawned.
                if error_gen() == egen && matches!(global_status(), Some((false, _))) {
                    global_status.set(None);
                }
            });
        }
    });

    // Clamp selected_server_idx when the server list shrinks (e.g. after the user
    // removes entries on the Servers screen and navigates back here).
    use_effect(move || {
        let len = server_list().len();
        if len > 0 && selected_server_idx() >= len {
            selected_server_idx.set(len - 1);
        }
    });

    let resources = config().resources();

    rsx! {
        TopBar { title: "letmein", status: global_status(), show_logo: true,
            button {
                class: "topbar-btn",
                title: "Settings",
                onclick: move |_| screen.set(Screen::Settings),
                "\u{2699}\u{fe0f}"
            }
        }

        div { class: "content",
            div { class: "mode-toggle",
                button {
                    class: if knock_mode() == KnockMode::Knock { "mode-btn mode-btn-active" } else { "mode-btn" },
                    onclick: move |_| knock_mode.set(KnockMode::Knock),
                    "Knock"
                }
                button {
                    class: if knock_mode() == KnockMode::Revoke { "mode-btn mode-btn-active" } else { "mode-btn" },
                    onclick: move |_| knock_mode.set(KnockMode::Revoke),
                    "Revoke"
                }
            }

            div { class: "section-label", "Server" }
            div { class: "input-row",
                if server_list().is_empty() {
                    span {
                        class: "input-field",
                        style: "color: var(--text-muted); font-size: 14px;",
                        "No servers — add via Manage"
                    }
                } else {
                    select {
                        class: "input-field",
                        onchange: move |e| {
                            if let Ok(idx) = e.value().parse::<usize>() {
                                selected_server_idx.set(idx);
                            }
                        },
                        for (i , entry) in server_list().iter().enumerate() {
                            option {
                                value: "{i}",
                                selected: i == selected_server_idx(),
                                "{entry.name}"
                            }
                        }
                    }
                }
                button {
                    class: "btn btn-secondary btn-small",
                    style: "white-space: nowrap;",
                    onclick: move |_| screen.set(Screen::Servers),
                    "Manage"
                }
            }

            if !resources.is_empty() {
                div { class: "section-label", "Resources" }
                div { class: "resource-list",
                    for resource in resources.iter() {
                        {
                            let res_id = resource.id();
                            let key = format!("{res_id}");
                            let (name, detail) = resource_display_name(resource);
                            let status = knock_states().get(&key).cloned().unwrap_or(KnockStatus::Idle);
                            let btn_text = if knock_mode() == KnockMode::Knock { "Knock" } else { "Revoke" };
                            let is_busy = status == KnockStatus::InProgress;

                            rsx! {
                                div { class: "resource-card", key: "{key}",
                                    div { class: "resource-info",
                                        div { class: "resource-name", "{name}" }
                                        div { class: "resource-detail", "{detail}" }
                                    }
                                    button {
                                        class: "knock-btn",
                                        disabled: is_busy,
                                        onclick: move |_| {
                                            let selected = server_list()
                                                .get(selected_server_idx())
                                                .cloned()
                                                .unwrap_or_default();
                                            let conf = config();
                                            let port_override = selected.control_port.trim().parse::<u16>().ok();
                                            perform_knock(
                                                conf,
                                                &selected.addr,
                                                KnockResource::Resource(res_id),
                                                knock_mode(),
                                                &key,
                                                knock_states,
                                                global_status,
                                                if selected.user_id.trim().is_empty() {
                                                    None
                                                } else {
                                                    Some(selected.user_id.trim())
                                                },
                                                port_override,
                                            );
                                        },
                                        "{btn_text}"
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                div { class: "empty-state",
                    p { style: "font-size: 32px;", "\u{1f510}" }
                    p { "No resources configured." }
                    p { "Open Settings to add your configuration." }
                }
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
