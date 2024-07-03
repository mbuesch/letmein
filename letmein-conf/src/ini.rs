// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err, Context as _};
use std::{
    collections::{hash_map, HashMap},
    io::Read as _,
    path::Path,
};

pub type IniSectionIter<'a> = hash_map::Iter<'a, String, String>;

/// All options from a `.ini` file section.
struct IniSection {
    options: HashMap<String, String>,
}

impl IniSection {
    fn new() -> Self {
        Self {
            options: HashMap::new(),
        }
    }

    fn options(&self) -> &HashMap<String, String> {
        &self.options
    }

    fn options_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.options
    }

    fn iter(&self) -> IniSectionIter {
        self.options.iter()
    }
}

/// Simple `.ini` file parser.
pub struct Ini {
    sections: HashMap<String, IniSection>,
}

impl Ini {
    pub fn new() -> Self {
        Self {
            sections: HashMap::new(),
        }
    }

    pub fn new_from_file(path: &Path) -> ah::Result<Self> {
        let mut this = Self::new();
        this.read_file(path)?;
        Ok(this)
    }

    pub fn read_file(&mut self, path: &Path) -> ah::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .context("Open configuration file")?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)
            .context("Read configuration file")?;
        self.parse_bytes(buf)
    }

    pub fn parse_bytes(&mut self, content: Vec<u8>) -> ah::Result<()> {
        self.parse_str(
            &String::from_utf8(content)
                .context("Configuration content file to UTF-8 conversion")?,
        )
    }

    pub fn parse_str(&mut self, content: &str) -> ah::Result<()> {
        let mut sections = HashMap::new();
        let mut in_section = None;
        for line in content.lines() {
            let line = line.trim_start();
            if line.is_empty() {
                continue; // This is an empty line.
            }
            if line.starts_with('#') {
                continue; // This is a comment.
            }
            // Section start?
            if line.starts_with('[') {
                let line = line.trim_end();
                if line.ends_with(']') {
                    let begin_chlen = '['.len_utf8();
                    let end_chlen = ']'.len_utf8();
                    let sname = &line[begin_chlen..line.len() - end_chlen];
                    if sname.is_empty() {
                        return Err(err!("Section name is empty: '{line}'"));
                    }
                    if sections.contains_key(sname) {
                        return Err(err!("Duplicate section name: '{line}'"));
                    }
                    sections.insert(sname.to_string(), IniSection::new());
                    in_section = Some(sname.to_string());
                    continue;
                } else {
                    return Err(err!("Invalid section name: '{line}'"));
                }
            }
            // Are we inside of a section?
            if let Some(section) = &in_section {
                if let Some(idx) = line.find('=') {
                    // We have an option
                    let chlen = '='.len_utf8();
                    let opt_name = line[..=(idx - chlen)].trim_end().to_string();
                    let opt_value = line[idx + chlen..].to_string();
                    sections
                        .get_mut(section)
                        .unwrap()
                        .options_mut()
                        .insert(opt_name, opt_value);
                } else {
                    return Err(err!("Option has no equal sign '=': '{line}'"));
                }
            } else {
                return Err(err!("Option is not inside of a section: '{line}'"));
            }
        }
        self.sections = sections;
        Ok(())
    }

    /// Get the value of an option from the given section.
    pub fn get(&self, section: &str, option: &str) -> Option<&str> {
        if let Some(sect) = self.sections.get(section) {
            if let Some(opt) = sect.options().get(option) {
                return Some(opt);
            }
        }
        None
    }

    /// Get an iterator over all options from a section.
    pub fn options_iter(&self, section: &str) -> Option<IniSectionIter> {
        self.sections.get(section).map(|s| s.iter())
    }
}

// vim: ts=4 sw=4 expandtab
