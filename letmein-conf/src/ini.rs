// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::ConfigChecksum;
use anyhow::{self as ah, format_err as err, Context as _};
use std::{
    collections::{hash_map, HashMap},
    io::Read as _,
    path::Path,
};

/// An iterator over all option name-value tuples from a section.
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

    fn iter(&self) -> IniSectionIter<'_> {
        self.options.iter()
    }
}

/// Simple `.ini`-style file parser.
pub struct Ini {
    checksum: ConfigChecksum,
    sections: HashMap<String, IniSection>,
}

impl Ini {
    /// Create a new empty parser state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checksum: Default::default(),
            sections: HashMap::new(),
        }
    }

    /// Create a new parser state and parse the specified `.ini`-style file.
    pub fn new_from_file(path: &Path) -> ah::Result<Self> {
        let mut this = Self::new();
        this.read_file(path)?;
        Ok(this)
    }

    /// Read the specified `.ini`-style file into an existing parser.
    ///
    /// Note that the parser state will be cleared before adding new items
    /// from the file.
    pub fn read_file(&mut self, path: &Path) -> ah::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .context("Open configuration file")?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)
            .context("Read configuration file")?;
        self.parse_bytes(&buf)
    }

    /// Read the `.ini`-style formatted byte stream into an existing parser.
    ///
    /// Note that the parser state will be cleared before adding new items
    /// from the byte stream.
    pub fn parse_bytes(&mut self, content: &[u8]) -> ah::Result<()> {
        self.parse_str(
            std::str::from_utf8(content)
                .context("Configuration content file to UTF-8 conversion")?,
        )
    }

    /// Read the `.ini`-style formatted string into an existing parser.
    ///
    /// Note that the parser state will be cleared before adding new items
    /// from the string.
    pub fn parse_str(&mut self, content: &str) -> ah::Result<()> {
        let mut sections: HashMap<String, IniSection> = HashMap::new();
        let mut in_section = None;
        let mut cur_opt_name = None;

        for line in content.lines() {
            // Check if this is an option content multi-line continuation.
            if let Some(opt_name) = &cur_opt_name {
                if let Some(section) = &in_section {
                    if line.starts_with([' ', '\t']) && !line.trim().is_empty() {
                        // Append to the value.
                        let opt_value = sections
                            .get_mut(section)
                            .unwrap()
                            .options_mut()
                            .get_mut(opt_name)
                            .unwrap();
                        opt_value.push(' ');
                        opt_value.push_str(line.trim_start());
                        continue;
                    }
                }
                cur_opt_name = None;
            }

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
                    let chlen = '='.len_utf8();
                    if idx >= chlen {
                        // We have an option
                        let opt_name = line[..=(idx - chlen)].trim_end().to_string();
                        let opt_value = line[idx + chlen..].to_string();
                        sections
                            .get_mut(section)
                            .unwrap()
                            .options_mut()
                            .insert(opt_name.to_string(), opt_value);
                        cur_opt_name = Some(opt_name);
                    } else {
                        return Err(err!("Option has no name before equal sign '=': '{line}'"));
                    }
                } else {
                    return Err(err!("Option has no equal sign '=': '{line}'"));
                }
            } else {
                return Err(err!("Option is not inside of a section: '{line}'"));
            }
        }

        self.checksum = ConfigChecksum::calculate(content.as_bytes());
        self.sections = sections;
        Ok(())
    }

    /// Get the value of an option from the given section.
    #[must_use]
    pub fn get(&self, section: &str, option: &str) -> Option<&str> {
        if let Some(sect) = self.sections.get(section) {
            if let Some(opt) = sect.options().get(option) {
                return Some(opt);
            }
        }
        None
    }

    /// Get an iterator over all option name-value tuples from a section.
    #[must_use]
    pub fn options_iter(&self, section: &str) -> Option<IniSectionIter<'_>> {
        self.sections.get(section).map(|s| s.iter())
    }

    /// Get the content checksum.
    #[must_use]
    pub fn checksum(&self) -> &ConfigChecksum {
        &self.checksum
    }
}

impl Default for Ini {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parser_base() {
        let text = "
# Comment

[SECTION]
# Another comment

# An option.
# Yes, really an option.
foo = bar

biz-baz=1.0
bzzzzz =brrrrrr\t

[ANOTHER-SECTION]
#option = commented out
        ";

        let mut ini = Ini::new();
        ini.parse_str(text).unwrap();
        for (name, value) in ini.options_iter("SECTION").unwrap() {
            match name.as_str() {
                "foo" => assert_eq!(value, " bar"),
                "biz-baz" => assert_eq!(value, "1.0"),
                "bzzzzz" => assert_eq!(value, "brrrrrr\t"),
                _ => unreachable!(),
            }
        }
        assert!(ini
            .options_iter("ANOTHER-SECTION")
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn test_parser_continuation() {
        let text = "
[SECT1]
opt = abc
  def

withtab =
\tcontwithtab
\t\tand another
\t
\t

[SECT2]
this = that
  cont = oh no!
nocont = ok
\t
  also-not-cont = :P

not-comment =
 # really not a comment
        ";

        let mut ini = Ini::new();
        ini.parse_str(text).unwrap();
        for (name, value) in ini.options_iter("SECT1").unwrap() {
            match name.as_str() {
                "opt" => assert_eq!(value, " abc def"),
                "withtab" => assert_eq!(value, " contwithtab and another"),
                _ => unreachable!(),
            }
        }
        for (name, value) in ini.options_iter("SECT2").unwrap() {
            match name.as_str() {
                "this" => assert_eq!(value, " that cont = oh no!"),
                "nocont" => assert_eq!(value, " ok"),
                "also-not-cont" => assert_eq!(value, " :P"),
                "not-comment" => assert_eq!(value, " # really not a comment"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    #[should_panic(expected = "Option has no equal sign '=': 'invalid'")]
    fn test_parser_continuation_bad() {
        let text = "
[S]
opt=val

 invalid
        ";

        let mut ini = Ini::new();
        ini.parse_str(text).unwrap();
    }
}

// vim: ts=4 sw=4 expandtab
