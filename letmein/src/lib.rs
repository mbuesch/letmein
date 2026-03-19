// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

/// Letmein client implementation.
pub mod client;

/// Letmein commands.
pub mod command;

/// Resolving hostnames into their corresponding IP addresses.
pub mod resolver;

/// Setting up seccomp filters on Linux and Android platforms.
pub mod seccomp;

// vim: ts=4 sw=4 expandtab
