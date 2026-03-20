// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{Screen, top_bar::TopBar};
use crate::config::{ServerEntry, save_server_list};
use dioxus::prelude::*;

#[allow(clippy::redundant_closure)]
#[component]
pub(super) fn ServersScreen(
    screen: Signal<Screen>,
    mut server_list: Signal<Vec<ServerEntry>>,
) -> Element {
    let mut local_servers = use_signal(|| server_list());
    let mut save_status = use_signal(|| Option::<(bool, String)>::None);

    rsx! {
        TopBar {
            title: "Servers",
            show_logo: false,
            status: save_status(),
            back_action: move |_| {
                let servers = local_servers();
                match save_server_list(&servers) {
                    Ok(()) => {
                        server_list.set(servers);
                        screen.set(Screen::Main);
                    }
                    Err(e) => {
                        save_status.set(Some((false, format!("{e:#}"))));
                    }
                }
            },
            // Explicit discard button (✕) in the TopBar right slot.
            button {
                class: "topbar-discard-btn",
                title: "Discard changes",
                onclick: move |_| {
                    screen.set(Screen::Main);
                },
                "\u{2715}"
            }
        }

        div { class: "content",
            div { class: "section-header",
                span { class: "section-label", style: "margin: 0;", "Server List" }
            }

            if local_servers().is_empty() {
                div { class: "empty-state",
                    p { "No servers configured." }
                    p { "Press + Add to add a server entry." }
                }
            }

            for (i , srv) in local_servers().iter().enumerate() {
                {
                    let sname = srv.name.clone();
                    let saddr = srv.addr.clone();
                    let suid = srv.user_id.clone();
                    let sport = srv.control_port.clone();
                    rsx! {
                        div { key: "{i}", class: "server-card",
                            div { class: "server-card-header",
                                span { class: "server-card-title", "Server #{i + 1}" }
                                button {
                                    class: "btn btn-small btn-secondary",
                                    title: "Remove server",
                                    onclick: move |_| {
                                        if i < local_servers().len() {
                                            local_servers.write().remove(i);
                                        }
                                    },
                                    "\u{00d7} Remove"
                                }
                            }
                            div { class: "server-card-field",
                                label { class: "field-label", "Name" }
                                input {
                                    class: "input-field",
                                    r#type: "text",
                                    placeholder: "My server",
                                    value: "{sname}",
                                    oninput: move |e| {
                                        if i < local_servers().len() {
                                            local_servers.write()[i].name = e.value();
                                        }
                                    },
                                }
                            }
                            div { class: "server-card-field",
                                label { class: "field-label", "Server address" }
                                input {
                                    class: "input-field",
                                    r#type: "text",
                                    placeholder: "hostname or IP",
                                    value: "{saddr}",
                                    oninput: move |e| {
                                        if i < local_servers().len() {
                                            local_servers.write()[i].addr = e.value();
                                        }
                                    },
                                }
                            }
                            div { class: "input-row",
                                div { class: "server-card-field",
                                    label { class: "field-label", "User ID" }
                                    input {
                                        class: "input-field",
                                        r#type: "text",
                                        placeholder: "00000000",
                                        value: "{suid}",
                                        oninput: move |e| {
                                            if i < local_servers().len() {
                                                local_servers.write()[i].user_id = e.value();
                                            }
                                        },
                                    }
                                }
                                div { class: "server-card-field",
                                    label { class: "field-label", "Control port" }
                                    input {
                                        class: "input-field",
                                        r#type: "number",
                                        placeholder: "5800",
                                        value: "{sport}",
                                        oninput: move |e| {
                                            if i < local_servers().len() {
                                                local_servers.write()[i].control_port = e.value();
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }

            button {
                class: "btn btn-small btn-secondary",
                onclick: move |_| local_servers.write().push(ServerEntry::default()),
                "+ Add"
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
