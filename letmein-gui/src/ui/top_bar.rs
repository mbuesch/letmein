// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use base64::prelude::*;
use dioxus::prelude::*;
use std::sync::LazyLock;

const LOGO_SVG: &[u8] = include_bytes!("../../../assets/letmein-logo.svg");
static LOGO_DATA_URL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "data:image/svg+xml;base64,{}",
        BASE64_STANDARD.encode(LOGO_SVG)
    )
});

#[component]
pub(super) fn TopBar(
    back_action: Option<EventHandler<MouseEvent>>,
    title: String,
    status: Option<(bool, String)>,
    show_logo: bool,
    children: Option<Element>,
) -> Element {
    rsx! {
        div { class: "topbar",
            if let Some(handler) = back_action {
                button {
                    class: "topbar-back-btn",
                    onclick: move |e| handler.call(e),
                    "\u{2190}"
                }
            } else {
                div { style: "width: 40px;" }
            }

            div { class: "topbar-title",
                if show_logo {
                    img {
                        class: "topbar-logo-img",
                        src: LOGO_DATA_URL.as_str(),
                        alt: "letmein logo",
                    }
                }
                h1 { "{title}" }
            }

            div { class: "topbar-status",
                if let Some((is_ok, msg)) = status {
                    if is_ok {
                        span { class: "topbar-status-ok", "{msg}" }
                    } else {
                        div { class: "topbar-status-error",
                            div { class: "topbar-status-error-prefix", "Error:" }
                            div { "{msg}" }
                        }
                    }
                }
            }

            if let Some(ch) = children {
                {ch}
            } else {
                div { style: "width: 40px;" }
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
