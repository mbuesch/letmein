// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server and letmeinfwd do not support non-Linux platforms.");

mod firewall;
mod server;
mod uid_gid;

use crate::{
    firewall::{nftables::NftFirewall, FirewallMaintain as _},
    server::FirewallServer,
    uid_gid::{os_get_gid, os_get_uid},
};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::Parser;
use letmein_conf::{Config, ConfigVariant, Seccomp};
use letmein_seccomp::{include_precompiled_filters, seccomp_supported, Filter as SeccompFilter};
use std::{
    fs::{create_dir_all, metadata, set_permissions, OpenOptions},
    io::Write as _,
    os::unix::fs::{chown, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};
use tokio::{
    runtime,
    signal::unix::{signal, SignalKind},
    sync::{self, Mutex, RwLock, Semaphore},
    task, time,
};

const FW_MAINTAIN_PERIOD: Duration = Duration::from_millis(5000);

static LETMEIND_UID: AtomicU32 = AtomicU32::new(u32::MAX);
static LETMEIND_GID: AtomicU32 = AtomicU32::new(u32::MAX);

/// Create a directory, if it does not exist already.
fn create_dir_if_not_exists(path: &Path) -> ah::Result<()> {
    match metadata(path) {
        Err(_) => {
            create_dir_all(path)?;
        }
        Ok(meta) => {
            const S_IFMT: u32 = libc::S_IFMT as _;
            const S_IFDIR: u32 = libc::S_IFDIR as _;
            if (meta.mode() & S_IFMT) != S_IFDIR {
                return Err(err!("Path '{path:?}' exists, but is not a directory."));
            }
        }
    }
    Ok(())
}

/// Set the uid, gid and the mode of a filesystem element.
pub fn set_owner_mode(path: &Path, uid: u32, gid: u32, mode: u32) -> ah::Result<()> {
    let meta = metadata(path).context("Stat path")?;
    chown(path, Some(uid), Some(gid)).context("Set path owner")?;
    let mut perm = meta.permissions();
    perm.set_mode(mode);
    set_permissions(path, perm).context("Set path mode")?;
    Ok(())
}

/// Create the /run subdirectory.
fn make_run_subdir(rundir: &Path) -> ah::Result<()> {
    let runsubdir = rundir.join("letmeinfwd");
    create_dir_if_not_exists(&runsubdir).context("Create /run subdirectory")?;
    set_owner_mode(
        &runsubdir,
        0, /* root */
        LETMEIND_GID.load(Relaxed),
        0o750,
    )
    .context("Set /run subdirectory owner and mode")?;
    Ok(())
}

/// Get UIDs and GIDs.
fn read_etc_passwd() -> ah::Result<()> {
    LETMEIND_UID.store(os_get_uid("letmeind")?, Relaxed);
    LETMEIND_GID.store(os_get_gid("letmeind")?, Relaxed);
    Ok(())
}

fn make_pidfile(rundir: &Path) -> ah::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(rundir.join("letmeinfwd/letmeinfwd.pid"))
        .context("Open PID-file")?
        .write_all(format!("{}\n", std::process::id()).as_bytes())
        .context("Write to PID-file")
}

include_precompiled_filters!(SECCOMP_FILTER_KILL, SECCOMP_FILTER_LOG);

fn install_seccomp_rules(seccomp: Seccomp) -> ah::Result<()> {
    // See build.rs for the filter definition.
    let filter_bytes = match seccomp {
        Seccomp::Log => SECCOMP_FILTER_LOG,
        Seccomp::Kill => SECCOMP_FILTER_KILL,
        Seccomp::Off => return Ok(()),
    };

    // Install seccomp filter.
    if seccomp_supported() {
        println!("Seccomp mode: {}", seccomp);
        SeccompFilter::deserialize(filter_bytes)
            .install()
            .context("Install seccomp filter")?;
    } else {
        eprintln!(
            "WARNING: Not using seccomp. \
            Letmein does not support seccomp on this architecture, yet."
        );
    }

    Ok(())
}

/// Handle SIGHUP:
/// Try to reload the configuration and try to re-apply the firewall rules.
async fn handle_sighup(
    conf: Arc<RwLock<Config>>,
    opts: &Opts,
    fw: Arc<Mutex<NftFirewall>>,
    seccomp: Seccomp,
) {
    match seccomp {
        Seccomp::Log | Seccomp::Kill => {
            // Can't open the config file. The open() syscall is restricted.
            eprintln!(
                "SIGHUP: Error: Reloading not possible with --seccomp enabled. \
                Please restart letmeinfwd instead."
            );
        }
        Seccomp::Off => {
            println!("SIGHUP: Reloading.");
            {
                let mut conf = conf.write().await;
                if let Err(e) = conf.load(&opts.get_config()) {
                    eprintln!("Failed to load configuration file: {e}");
                }
            }
            {
                let conf = conf.read().await;
                let mut fw = fw.lock().await;
                if let Err(e) = fw.reload(&conf).await {
                    eprintln!("Failed to reload filewall rules: {e}");
                }
                if conf.seccomp() != Seccomp::Off {
                    eprintln!(
                        "WARNING: Seccomp has been turned ON in \
                        the configuration file, but SIGHUP reloading \
                        does not actually enable seccomp. \
                        Please restart letmeinfwd."
                    );
                }
            }
        }
    }
}

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Override the default path to the configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// The run directory for runtime data.
    #[arg(long, default_value = "/run")]
    rundir: PathBuf,

    /// Maximum number of simultaneous connections.
    #[arg(short, long, default_value = "8")]
    num_connections: usize,

    /// Force-disable use of systemd socket.
    ///
    /// Do not use systemd socket,
    /// even if a systemd socket has been passed to the application.
    #[arg(long, default_value = "false")]
    no_systemd: bool,

    /// Override the `seccomp` setting from the configuration file.
    ///
    /// If this option is not given, then the value
    /// from the configuration file is used instead.
    #[arg(long)]
    seccomp: Option<Seccomp>,
}

impl Opts {
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            Config::get_default_path(ConfigVariant::Server)
        }
    }
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    read_etc_passwd()?;
    make_run_subdir(&opts.rundir)?;

    let mut conf = Config::new(ConfigVariant::Server);
    conf.load(&opts.get_config())
        .context("Configuration file")?;
    let conf = Arc::new(RwLock::new(conf));

    let fw = Arc::new(Mutex::new(NftFirewall::new(&*conf.read().await).await?));

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    let (exit_sock_tx, mut exit_sock_rx) = sync::mpsc::channel(1);
    let (exit_fw_tx, mut exit_fw_rx) = sync::mpsc::channel(1);

    let srv = FirewallServer::new(opts.no_systemd, &opts.rundir)
        .await
        .context("Firewall server init")?;

    make_pidfile(&opts.rundir)?;

    let seccomp = opts.seccomp.unwrap_or(conf.read().await.seccomp());
    install_seccomp_rules(seccomp)?;

    // Task: Unix socket handler.
    task::spawn({
        let conf = Arc::clone(&conf);
        let opts = Arc::clone(&opts);
        let fw = Arc::clone(&fw);

        async move {
            let conn_semaphore = Semaphore::new(opts.num_connections);
            loop {
                let conf = Arc::clone(&conf);
                let fw = Arc::clone(&fw);
                match srv.accept().await {
                    Ok(mut conn) => {
                        // Socket connection handler.
                        if let Ok(_permit) = conn_semaphore.acquire().await {
                            task::spawn(async move {
                                let conf = conf.read().await;
                                if let Err(e) = conn.handle_message(&conf, fw).await {
                                    eprintln!("Client error: {e}");
                                }
                            });
                        }
                    }
                    Err(e) => {
                        let _ = exit_sock_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        }
    });

    // Task: Firewall.
    task::spawn({
        let conf = Arc::clone(&conf);
        let fw = Arc::clone(&fw);

        async move {
            let mut interval = time::interval(FW_MAINTAIN_PERIOD);
            loop {
                interval.tick().await;
                let conf = conf.read().await;
                let mut fw = fw.lock().await;
                if let Err(e) = fw.maintain(&conf).await {
                    let _ = exit_fw_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Task: Main loop.
    let mut exitcode;
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                eprintln!("SIGTERM: Terminating.");
                exitcode = Ok(());
                break;
            }
            _ = sigint.recv() => {
                exitcode = Err(err!("Interrupted by SIGINT."));
                break;
            }
            _ = sighup.recv() => {
                handle_sighup(Arc::clone(&conf), &opts, Arc::clone(&fw), seccomp).await;
            }
            code = exit_sock_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
            code = exit_fw_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
        }
    }

    // Exiting...
    // Try to remove all firewall rules.
    {
        let conf = conf.read().await;
        let mut fw = fw.lock().await;
        if let Err(e) = fw.clear(&conf).await {
            eprintln!("WARNING: Failed to remove firewall rules: {e}");
            if exitcode.is_ok() {
                exitcode = Err(err!("Failed to remove firewall rules"));
            }
        }
    }

    exitcode
}

fn main() -> ah::Result<()> {
    let opts = Arc::new(Opts::parse());
    runtime::Builder::new_current_thread()
        .thread_keep_alive(Duration::from_millis(0))
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
