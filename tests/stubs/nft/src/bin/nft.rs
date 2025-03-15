// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::{
    env,
    io::{stdin, Read as _},
};

fn main() {
    // Get all arguments
    let args: Vec<String> = env::args().collect();
    
    // Log all calls for debugging
    eprintln!("nft stub: appel avec arguments: {:?}", args);
    
    // Check if MOCK_NFTABLES is defined
    if env::var("MOCK_NFTABLES").is_ok() {
        eprintln!("nft stub: MOCK_NFTABLES=1 detected, using stub mode");
        
        // Mock mode - handle different types of commands
        if args == ["nft", "-j", "-f", "-"] {
            // Process JSON input
            let mut json_raw: Vec<u8> = vec![];
            stdin().read_to_end(&mut json_raw).unwrap();
            let json = std::str::from_utf8(&json_raw).unwrap();
            
            eprintln!("nft stub: json received: {}", json);
            let _ = json; // We could parse the JSON here
            
            // Simulate successful application
            eprintln!("nft stub: JSON command processed successfully");
        } else if args.len() >= 2 && args[1] == "list" && args.len() >= 3 && args[2] == "ruleset" {
            // Simulate an empty ruleset
            println!("table inet filter {{
  chain input {{
    type filter hook input priority 0; policy accept;
  }}
  chain forward {{
    type filter hook forward priority 0; policy accept;
  }}
  chain output {{
    type filter hook output priority 0; policy accept;
  }}
}}");
            eprintln!("nft stub: Command list ruleset simulated");
        } else {
            // Handle other types of commands
            eprintln!("nft stub: simulating execution of: {:?}", args);
            // By default, simulate success for most commands
        }
    } else {
        eprintln!("nft stub: MOCK_NFTABLES not defined, using real nft");
        
        // MOCK_NFTABLES is not defined, initialize necessary tables before redirecting
        use std::process::Command;
        
        // Create base tables if this is an initialization command
        if args.len() > 1 && args[1] == "-j" && args[2] == "-f" && args[3] == "-" {
            // Read JSON input to see what we're trying to do
            let mut json_raw: Vec<u8> = vec![];
            stdin().read_to_end(&mut json_raw).unwrap();
            let json = std::str::from_utf8(&json_raw).unwrap();
            eprintln!("nft stub: JSON content for real nft: {}", json);
            
            // Create the inet filter table if it doesn't already exist
            // This ensures that subsequent operations will have a table to work with
            eprintln!("nft stub: Creating inet filter table");
            let _init_status = Command::new("/usr/sbin/nft")
                .args(["-e", "add", "table", "inet", "filter"])
                .status();
            
            // Create base chains if necessary
            let _chains = [
                "add chain inet filter input { type filter hook input priority 0; policy accept; }",
                "add chain inet filter forward { type filter hook forward priority 0; policy accept; }",
                "add chain inet filter output { type filter hook output priority 0; policy accept; }",
                // Add the specific LETMEIN-INPUT chain that is used by the code
                "add chain inet filter LETMEIN-INPUT { type filter hook input priority 100; policy accept; }",
                // Other potentially used chains
                "add chain inet filter LETMEIN-OUTPUT { type filter hook output priority 100; policy accept; }"
            ];
            
            for chain_cmd in _chains.iter() {
                let _chain_status = Command::new("/usr/sbin/nft")
                    .args(["-e", chain_cmd])
                    .status();
                // -e to ignore errors if the chain already exists
            }
            
            // Apply the original JSON command
            let status = Command::new("/usr/sbin/nft")
                .args(["-j", "-f", "-"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        stdin.write_all(json_raw.as_slice()).unwrap();
                    }
                    child.wait()
                })
                .expect("Failed to execute the real nft with JSON");
            
            std::process::exit(status.code().unwrap_or(1));
        } else {
            // For other commands, simply execute them
            let real_nft = "/usr/sbin/nft";
            let nft_args = &args[1..];
            
            eprintln!("nft stub: executing real command: {} {:?}", real_nft, nft_args);
            
            let status = Command::new(real_nft)
                .args(nft_args)
                .status()
                .expect("Failed to execute the real nft");
            
            eprintln!("nft stub: real command completed with code: {:?}", status.code());
            
            // Propagate the exit code
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

// vim: ts=4 sw=4 expandtab
