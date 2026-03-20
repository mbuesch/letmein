// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::{Screen, top_bar::TopBar};
use crate::{
    config::config_file_path,
    settings::{AppSettings, KeyEntry, ResourceEntry},
};
use dioxus::prelude::*;
use letmein_conf::Config;

/// Persist `settings` to disk and update the shared `config` signal.
/// On success, navigates `screen` to `Screen::Settings`.
/// On failure, stores an error message in `save_status`.
fn save_settings(
    settings: Signal<AppSettings>,
    mut config: Signal<Config>,
    mut screen: Signal<Screen>,
    mut save_status: Signal<Option<(bool, String)>>,
) {
    match settings().to_config() {
        Ok((conf, mut ini)) => match config_file_path() {
            Ok(path) => match ini.write_file(&path) {
                Ok(()) => {
                    config.set(conf);
                    screen.set(Screen::Settings);
                }
                Err(e) => save_status.set(Some((false, format!("{e:#}")))),
            },
            Err(e) => save_status.set(Some((false, format!("{e:#}")))),
        },
        Err(e) => save_status.set(Some((false, format!("{e:#}")))),
    }
}

/// Hub screen: navigate to Key Settings or Resource Settings.
#[component]
pub(super) fn SettingsScreen(screen: Signal<Screen>) -> Element {
    rsx! {
        TopBar {
            title: "Settings",
            show_logo: false,
            back_action: move |_| screen.set(Screen::Main),
        }

        div { class: "content",
            div { class: "settings-menu",
                button {
                    class: "settings-menu-card",
                    title: "Keys",
                    onclick: move |_| screen.set(Screen::KeySettings),
                    span { class: "settings-menu-icon", "\u{1f511}" }
                    span { class: "settings-menu-label", "Keys" }
                }
                button {
                    class: "settings-menu-card",
                    title: "Resources",
                    onclick: move |_| screen.set(Screen::ResourceSettings),
                    span { class: "settings-menu-icon", "\u{1f4bb}" }
                    span { class: "settings-menu-label", "Resources" }
                }
            }
        }
    }
}

/// Screen for managing cryptographic keys.
#[component]
pub(super) fn KeySettingsScreen(screen: Signal<Screen>, mut config: Signal<Config>) -> Element {
    let mut settings = use_signal(|| AppSettings::from_config(&config()));
    let save_status = use_signal(|| Option::<(bool, String)>::None);

    rsx! {
        TopBar {
            title: "Keys",
            show_logo: false,
            back_action: move |_| save_settings(settings, config, screen, save_status),
            button {
                class: "topbar-discard-btn",
                title: "Discard changes",
                onclick: move |_| screen.set(Screen::Settings),
                "\u{2715}"
            }
        }

        div { class: "content",
            if let Some((is_ok, msg)) = save_status() {
                div { class: if is_ok { "status-banner status-success" } else { "status-banner status-error" },
                    span { "{msg}" }
                }
            }

            if settings().keys.is_empty() {
                div { class: "empty-state",
                    p { "No keys configured." }
                    p { "Press + Add to add a key entry." }
                }
            }

            for (i , key) in settings().keys.iter().enumerate() {
                {
                    let uid = key.user_id.clone();
                    let khex = key.key_hex.clone();
                    let show_key = key.show_key;
                    rsx! {
                        div { key: "{i}", class: "server-card",
                            div { class: "server-card-header",
                                span { class: "server-card-title", "Key #{i + 1}" }
                                button {
                                    class: "btn btn-small btn-secondary",
                                    title: "Remove key",
                                    onclick: move |_| settings.write().remove(i),
                                    "\u{00d7} Remove"
                                }
                            }
                            div { class: "server-card-field",
                                label { class: "field-label", "User ID" }
                                input {
                                    class: "input-field",
                                    r#type: "text",
                                    placeholder: "User ID (up to 8 hex chars)",
                                    value: "{uid}",
                                    oninput: move |e| settings.write().set_user_id(i, e.value()),
                                }
                            }
                            div { class: "server-card-field",
                                label { class: "field-label", "Key" }
                                div { class: "input-row",
                                    input {
                                        class: "input-field",
                                        r#type: if show_key { "text" } else { "password" },
                                        placeholder: "Key (64 hex chars)",
                                        value: "{khex}",
                                        oninput: move |e| settings.write().set_key(i, e.value()),
                                    }
                                    button {
                                        class: "btn btn-icon btn-secondary",
                                        title: if show_key { "Hide key" } else { "Show key" },
                                        onclick: move |_| settings.write().toggle_key_visibility(i),
                                        if show_key {
                                            "\u{1f576}"
                                        } else {
                                            "\u{1f441}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            button {
                class: "btn btn-small btn-secondary",
                onclick: move |_| settings.write().keys.push(KeyEntry::default()),
                "+ Add"
            }
        }
    }
}

/// Screen for managing network resources (port / protocol entries).
#[component]
pub(super) fn ResourceSettingsScreen(
    screen: Signal<Screen>,
    mut config: Signal<Config>,
) -> Element {
    let mut settings = use_signal(|| AppSettings::from_config(&config()));
    let save_status = use_signal(|| Option::<(bool, String)>::None);

    rsx! {
        TopBar {
            title: "Resources",
            show_logo: false,
            back_action: move |_| save_settings(settings, config, screen, save_status),
            button {
                class: "topbar-discard-btn",
                title: "Discard changes",
                onclick: move |_| screen.set(Screen::Settings),
                "\u{2715}"
            }
        }

        div { class: "content",
            if let Some((is_ok, msg)) = save_status() {
                div { class: if is_ok { "status-banner status-success" } else { "status-banner status-error" },
                    span { "{msg}" }
                }
            }

            if settings().resources.is_empty() {
                div { class: "empty-state",
                    p { "No resources configured." }
                    p { "Press + Add to add a resource entry." }
                }
            }

            for (i , res) in settings().resources.iter().enumerate() {
                {
                    let rid = res.id.clone();
                    let rport = res.port.clone();
                    let rtcp = res.tcp;
                    let rudp = res.udp;
                    rsx! {
                        div { key: "{i}", class: "server-card",
                            div { class: "server-card-header",
                                span { class: "server-card-title", "Resource #{i + 1}" }
                                button {
                                    class: "btn btn-small btn-secondary",
                                    title: "Remove resource",
                                    onclick: move |_| settings.write().remove_resource(i),
                                    "\u{00d7} Remove"
                                }
                            }
                            div { class: "server-card-field",
                                label { class: "field-label", "Resource ID" }
                                input {
                                    class: "input-field",
                                    r#type: "text",
                                    placeholder: "Resource ID (up to 8 hex chars)",
                                    value: "{rid}",
                                    oninput: move |e| settings.write().set_resource_id(i, e.value()),
                                }
                            }
                            div { class: "input-row",
                                div { class: "server-card-field",
                                    label { class: "field-label", "Knocked Port" }
                                    input {
                                        class: "input-field",
                                        r#type: "number",
                                        placeholder: "Port",
                                        value: "{rport}",
                                        oninput: move |e| settings.write().set_resource_port(i, e.value()),
                                    }
                                }
                                div { class: "server-card-field",
                                    label { class: "field-label", "Knocked Port Type" }
                                    div { class: "proto-checks",
                                        label { class: "proto-label",
                                            input {
                                                r#type: "checkbox",
                                                checked: rtcp,
                                                oninput: move |e| settings.write().set_resource_tcp(i, e.checked()),
                                            }
                                            "TCP"
                                        }
                                        label { class: "proto-label",
                                            input {
                                                r#type: "checkbox",
                                                checked: rudp,
                                                oninput: move |e| settings.write().set_resource_udp(i, e.checked()),
                                            }
                                            "UDP"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            button {
                class: "btn btn-small btn-secondary",
                onclick: move |_| settings.write().add_resource(ResourceEntry::default()),
                "+ Add"
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
