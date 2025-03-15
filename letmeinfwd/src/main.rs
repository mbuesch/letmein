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
mod seccomp;
mod server;
mod uid_gid;
mod verify;

use crate::{
    firewall::{nftables::NftFirewall, FirewallMaintain},
    seccomp::install_seccomp_rules,
    server::FirewallServer,
    uid_gid::{os_get_gid, os_get_uid},
};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::{Parser, Subcommand};
use letmein_conf::{Config, ConfigVariant, Seccomp};
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
    sync::{self, Mutex, Semaphore},
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
fn make_run_subdir(opts: &Opts) -> ah::Result<()> {
    let runsubdir = opts.rundir.join("letmeinfwd");
    create_dir_if_not_exists(&runsubdir).context("Create /run subdirectory")?;

    if !opts.test_mode() {
        set_owner_mode(
            &runsubdir,
            0, /* root */
            LETMEIND_GID.load(Relaxed),
            0o750,
        )
        .context("Set /run subdirectory owner and mode")?;
    }
    Ok(())
}

/// Get UIDs and GIDs.
fn read_etc_passwd(opts: &Opts) -> ah::Result<()> {
    if !opts.test_mode() {
        LETMEIND_UID.store(os_get_uid("letmeind")?, Relaxed);
        LETMEIND_GID.store(os_get_gid("letmeind")?, Relaxed);
    }
    Ok(())
}

/// Create the PID-file in the /run subdirectory.
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

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,

    /// Enable development test mode. Do not use this option. Ever.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    test_mode: bool,

    /// Subcommands for additional functionality
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Subcommands for letmeinfwd
#[derive(Debug, Clone, Subcommand)]
enum Commands {
    /// Verify if a firewall rule exists for testing
    Verify {
        /// IP address to check
        #[arg(long)]
        address: String,
        
        /// Port to check
        #[arg(long)]
        port: u16,
        
        /// Protocol (tcp/udp)
        #[arg(long, default_value = "tcp")]
        protocol: String,
        
        /// Check if rule should exist (true) or be missing (false)
        #[arg(long)]
        should_exist: bool,
    }
}

impl Opts {
    /// Get the configuration path from command line or default.
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            Config::get_default_path(ConfigVariant::Server)
        }
    }

    /// Check if development test mode is enabled.
    /// This always returns `false` for release builds and only ever
    /// returns `true` if the option `--test-mode` is passed to a debug executable.
    pub fn test_mode(&self) -> bool {
        #[cfg(debug_assertions)]
        let test_mode = self.test_mode;

        #[cfg(not(debug_assertions))]
        let test_mode = false;

        test_mode
    }
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    // Read and parse /etc/passwd and /etc/group.
    read_etc_passwd(&opts)?;

    // Create directories in /run
    make_run_subdir(&opts)?;

    // Read the letmeind.conf configuration file.
    let mut conf = Config::new(ConfigVariant::Server);
    conf.load(&opts.get_config())
        .context("Configuration file")?;
    let conf = Arc::new(conf);

    // Initialize access to the firewall.
    let fw = Arc::new(Mutex::new(NftFirewall::new(&conf).await?));

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    // Create async IPC channels.
    let (exit_sock_tx, mut exit_sock_rx) = sync::mpsc::channel(1);
    let (exit_fw_tx, mut exit_fw_rx) = sync::mpsc::channel(1);

    // Start the firewall unix domain socket listener.
    let srv = FirewallServer::new(opts.no_systemd, &opts)
        .await
        .context("Firewall server init")?;

    // Create the PID-file.
    make_pidfile(&opts.rundir)?;

    // Install `seccomp` rules, if required.
    let seccomp = opts.seccomp.unwrap_or(conf.seccomp());
    install_seccomp_rules(seccomp)?;

    // Spawn task: Unix socket handler.
    task::spawn({
        let conf = Arc::clone(&conf);
        let opts = Arc::clone(&opts);
        let fw = Arc::clone(&fw);

        async move {
            let conn_semaphore = Semaphore::new(opts.num_connections);
            loop {
                let conf = Arc::clone(&conf);
                let fw = Arc::clone(&fw);
                match srv.accept(&opts).await {
                    Ok(mut conn) => {
                        // Socket connection handler.
                        if let Ok(_permit) = conn_semaphore.acquire().await {
                            task::spawn(async move {
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
                eprintln!("SIGHUP: Reloading is not supported. Please restart letmeinfwd instead.");
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
        let mut fw = fw.lock().await;
        if let Err(e) = fw.shutdown(&conf).await {
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

    if opts.version {
        println!("letmeinfwd version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    
    // Process verify command if specified
    if let Some(Commands::Verify { address, port, protocol, should_exist }) = &opts.command {
        // Read the configuration file
        let mut conf = Config::new(ConfigVariant::Server);
        conf.load(&opts.get_config())
            .context("Configuration file")?;
        
        // Call the verification function
        let result = runtime::Builder::new_current_thread()
            .thread_keep_alive(Duration::from_millis(0))
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .context("Tokio runtime builder")?
            .block_on(crate::verify::verify_nft_rule(
                &conf,
                address,
                *port,
                protocol,
                *should_exist
            ));
            
        match result {
            Ok(true) => {
                println!("Verification successful: rule {} found as expected", 
                    if *should_exist { "was" } else { "was not" });
                return Ok(());
            },
            Ok(false) => {
                eprintln!("Verification failed: rule {} found, which was not expected", 
                    if *should_exist { "was not" } else { "was" });
                std::process::exit(1);
            },
            Err(e) => {
                eprintln!("Error during verification: {}", e);
                std::process::exit(1);
            }
        }
    }

    // For other commands, proceed with normal server operation
    runtime::Builder::new_current_thread()
        .thread_keep_alive(Duration::from_millis(0))
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
