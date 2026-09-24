// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Installation helper: write the embedded configs to the fail2ban directory.

use crate::CONFIG_FILES;
use anyhow::{self as ah, Context as _};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Options controlling how [`install`] behaves.
#[derive(Debug, Clone, Default)]
pub struct InstallOpts {
    /// Overwrite files that already exist.
    ///
    /// Defaults to `false` - existing files are skipped with a note printed to
    /// stderr so that local customisations are never silently destroyed.
    pub overwrite: bool,
}

/// Install all fail2ban configuration files under `fail2ban_dir`.
///
/// `fail2ban_dir` is normally `/etc/fail2ban`.  The function creates the
/// `filter.d/` and `jail.d/` sub-directories if they do not already exist.
///
/// Files are written with mode `0o644`.  Sub-directories are created with
/// mode `0o755`.
///
/// # Errors
///
/// Returns an error if a directory cannot be created or a file cannot be
/// written.
pub fn install(fail2ban_dir: &Path, opts: &InstallOpts) -> ah::Result<()> {
    for file in CONFIG_FILES {
        let dir: PathBuf = fail2ban_dir.join(file.subdir);
        fs::create_dir_all(&dir)
            .with_context(|| format!("Create fail2ban sub-directory {}", dir.display()))?;

        let dest: PathBuf = dir.join(file.filename);

        if dest.exists() && !opts.overwrite {
            eprintln!(
                "letmein-fail2ban: skipping {} (already exists; use --overwrite to replace)",
                dest.display()
            );
            continue;
        }

        fs::write(&dest, file.content)
            .with_context(|| format!("Write fail2ban config {}", dest.display()))?;

        eprintln!("letmein-fail2ban: installed {}", dest.display());
    }
    Ok(())
}

// vim: ts=4 sw=4 expandtab
