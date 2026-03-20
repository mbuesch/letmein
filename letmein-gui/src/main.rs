// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

fn main() {
    #[cfg(feature = "desktop")]
    {
        use dioxus::desktop::tao::window::Icon;
        use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

        let icon = {
            let icon_bytes: &[u8] = include_bytes!("../../assets/letmein-logo-64.png");
            let img = image::load_from_memory(icon_bytes)
                .expect("Failed to load window icon")
                .into_rgba8();
            let (w, h) = img.dimensions();
            Icon::from_rgba(img.into_raw(), w, h).expect("Failed to create window icon")
        };

        let win = WindowBuilder::new()
            .with_inner_size(LogicalSize::new(520.0_f64, 700.0_f64))
            .with_title("letmein")
            .with_window_icon(Some(icon));
        dioxus::LaunchBuilder::desktop()
            .with_cfg(Config::new().with_menu(None).with_window(win))
            .launch(letmein_gui::App);
    }

    #[cfg(not(feature = "desktop"))]
    dioxus::launch(letmein_gui::App);
}

// vim: ts=4 sw=4 expandtab
