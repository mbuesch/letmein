// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    config::{load_config, load_server_list},
    knock::KnockMode,
    ui::{
        main_screen::MainScreen,
        servers_screen::ServersScreen,
        settings_screen::{KeySettingsScreen, ResourceSettingsScreen, SettingsScreen},
    },
};
use dioxus::prelude::*;
use letmein_conf::{Config, ConfigVariant};

mod main_screen;
mod servers_screen;
mod settings_screen;
mod top_bar;

const CSS: &str = include_str!("style.css");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Main,
    Settings,
    KeySettings,
    ResourceSettings,
    Servers,
}

#[component]
fn FatalErrorScreen(message: String) -> Element {
    rsx! {
        style { {CSS} }

        div { class: "fatal-error",
            div { class: "fatal-error-icon", "\u{26a0}" }
            div { class: "fatal-error-title", "Failed to start" }
            div { class: "fatal-error-message", "{message}" }
        }
    }
}

#[component]
pub fn App() -> Element {
    let (config_init, config_err) = use_hook(|| match load_config() {
        Ok(c) => (c, None),
        Err(e) => (Config::new(ConfigVariant::Client), Some(format!("{e}"))),
    });
    let (server_list_init, server_list_err) = use_hook(|| match load_server_list() {
        Ok(l) => (l, None),
        Err(e) => (vec![], Some(format!("{e}"))),
    });

    let screen = use_signal(|| Screen::Main);
    let selected_server_idx = use_signal(|| 0_usize);
    let knock_mode = use_signal(|| KnockMode::Knock);
    let config = use_signal(move || config_init);
    let server_list = use_signal(move || server_list_init);

    if let Some(msg) = config_err {
        return rsx! {
            FatalErrorScreen { message: msg }
        };
    }
    if let Some(msg) = server_list_err {
        return rsx! {
            FatalErrorScreen { message: msg }
        };
    }

    rsx! {
        style { {CSS} }

        div { class: "app",
            match screen() {
                Screen::Main => rsx! {
                    MainScreen {
                        screen,
                        config,
                        server_list,
                        selected_server_idx,
                        knock_mode,
                    }
                },
                Screen::Settings => rsx! {
                    SettingsScreen { screen }
                },
                Screen::KeySettings => rsx! {
                    KeySettingsScreen { screen, config }
                },
                Screen::ResourceSettings => rsx! {
                    ResourceSettingsScreen { screen, config }
                },
                Screen::Servers => rsx! {
                    ServersScreen { screen, server_list }
                },
            }

            div { class: "version-badge", "v{env!(\"CARGO_PKG_VERSION\")}" }
        }
    }
}

// vim: ts=4 sw=4 expandtab
