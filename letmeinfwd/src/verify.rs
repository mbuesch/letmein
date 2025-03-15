// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Rule verification functionality for testing

use anyhow::{self as ah};
use letmein_conf::Config;
use nftables::{
    helper::get_current_ruleset_with_args_async,
    schema::{NfListObject, NfObject},
};
use std::net::IpAddr;

/// Verify if a rule exists or is missing in the nftables ruleset
/// 
/// This function is used in tests to verify if a rule exists or not.
/// It returns true if the verification passed, false otherwise.
#[allow(dead_code)]
pub async fn verify_nft_rule(
    _config: &Config,
    addr_str: &str,
    port: u16,
    proto: &str,
    should_exist: bool,
) -> ah::Result<bool> {
    // Parse the IP address
    let addr: IpAddr = match addr_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Error parsing IP address {}: {}", addr_str, e);
            return Ok(false);
        }
    };

    // Generate the comment string that identifies the rule
    // Format: "letmein_{addr}-{port}/{proto}"
    let comment = format!("letmein_{}-{}/{}", addr, port, proto);
    
    // Get current ruleset using the nftables crate
    let ruleset = get_current_ruleset_with_args_async(None::<&str>, None::<&str>).await?;
    
    // Print the ruleset for debugging
    println!("Current nftables ruleset:");
    for obj in ruleset.objects.to_vec().iter() {
        println!("{:?}", obj);
    }
    
    // Check if rule exists by looking for our comment identifier
    let rule_exists = ruleset.objects.to_vec().iter().any(|obj| {
        match obj {
            NfObject::ListObject(NfListObject::Rule(rule)) => {
                // Use debug formatting since Rule doesn't implement Display
                format!("{:?}", rule).contains(&comment)
            },
            _ => false
        }
    });
    
    let result = match should_exist {
        true => {
            if rule_exists {
                println!("✓ OK: Rule found for {} port {}/{}", addr, port, proto);
                true
            } else {
                eprintln!("✗ ERROR: Rule not found for {} port {}/{}", addr, port, proto);
                false
            }
        },
        false => {
            if !rule_exists {
                println!("✓ OK: Rule successfully removed for {} port {}/{}", addr, port, proto);
                true
            } else {
                eprintln!("✗ ERROR: Rule still present for {} port {}/{}", addr, port, proto);
                false
            }
        }
    };
    
    Ok(result)
}
