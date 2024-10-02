// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use std::str::FromStr;

pub enum MapItem {
    KeyValue(String, String),
    KeyValues(String, Vec<String>),
    Values(Vec<String>),
}

pub struct Map {
    items: Vec<MapItem>,
}

impl FromStr for Map {
    type Err = ah::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut items = Vec::with_capacity(8);

        for item in s.split('/') {
            let item = if let Some(idx) = item.find(':') {
                let chlen = ':'.len_utf8();
                if idx < chlen {
                    return Err(err!("Invalid item key."));
                }
                let key = item[..=(idx - chlen)].trim();
                if key.is_empty() {
                    return Err(err!("Invalid item key."));
                }
                let value = &item[idx + chlen..];
                if value.find(',').is_some() {
                    MapItem::KeyValues(
                        key.to_string(),
                        value.split(',').map(|v| v.trim().to_string()).collect(),
                    )
                } else {
                    MapItem::KeyValue(key.to_string(), value.trim().to_string())
                }
            } else {
                let values = item.split(',');
                let values: Vec<String> = values.map(|s| s.trim().to_string()).collect();
                MapItem::Values(values)
            };
            items.push(item);
        }

        Ok(Map { items })
    }
}

impl Map {
    pub fn items(&self) -> &[MapItem] {
        &self.items
    }
}

// vim: ts=4 sw=4 expandtab
