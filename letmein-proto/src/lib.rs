// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err};
use bincode::Options as _;
use getrandom::getrandom;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use subtle::ConstantTimeEq as _;

pub const PORT: u16 = 5800;
pub const MSG_SIZE: usize = 4 + 4 + 4 + 4 + AUTH_SIZE;
const MAGIC: u32 = 0x3B1BB719;

const AUTH_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
pub type Key = [u8; KEY_SIZE];
pub type Auth = [u8; AUTH_SIZE];
pub type Challenge = Auth;
const ZERO_AUTH: Auth = [0; AUTH_SIZE];

pub fn secure_random<const SZ: usize>() -> [u8; SZ] {
    let mut buf: [u8; SZ] = [0; SZ];
    getrandom(&mut buf).unwrap();
    assert_ne!(buf, [0; SZ]);
    assert_ne!(buf, [0xFF; SZ]);
    buf
}

#[derive(Clone, Debug)]
pub enum DeserializeResult<M> {
    Ok(M),
    Pending(usize),
}

#[inline]
fn bincode_config() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_limit(MSG_SIZE.try_into().unwrap())
        .with_big_endian()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Operation {
    Knock,
    Challenge,
    Response,
    ComeIn,
    GoAway,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    magic: u32,
    operation: Operation,
    user: u32,
    resource: u32,
    auth: Auth,
}

impl Message {
    pub fn new(operation: Operation, user: u32, resource: u32) -> Self {
        let msg = Self {
            magic: MAGIC,
            operation,
            user,
            resource,
            auth: ZERO_AUTH,
        };
        debug_assert_eq!(
            MSG_SIZE,
            bincode_config()
                .serialized_size(&msg)
                .unwrap()
                .try_into()
                .unwrap()
        );
        msg
    }

    pub fn operation(&self) -> Operation {
        self.operation
    }

    pub fn user(&self) -> u32 {
        self.user
    }

    pub fn resource(&self) -> u32 {
        self.resource
    }

    #[must_use]
    fn authenticate(&self, shared_key: &[u8], challenge: &[u8]) -> Auth {
        assert_eq!(shared_key.len(), KEY_SIZE);
        assert_eq!(challenge.len(), AUTH_SIZE);

        let mut mac = Hmac::<Sha3_256>::new_from_slice(shared_key)
            .expect("HMAC<SHA3-256> initialization failed");
        mac.update(&(self.operation as u32).to_be_bytes());
        mac.update(&self.user.to_be_bytes());
        mac.update(&self.resource.to_be_bytes());
        mac.update(challenge);
        let mac_bytes = mac.finalize().into_bytes();

        let mut auth: Auth = ZERO_AUTH;
        auth.copy_from_slice(mac_bytes.as_slice());
        assert_ne!(auth, ZERO_AUTH);

        auth
    }

    #[must_use]
    fn authenticate_no_challenge(&self, shared_key: &[u8]) -> Auth {
        self.authenticate(shared_key, &ZERO_AUTH)
    }

    #[must_use]
    pub fn check_auth_ok(&self, shared_key: &[u8], challenge: &[u8]) -> bool {
        assert_eq!(self.operation(), Operation::Response);
        self.auth
            .ct_eq(&self.authenticate(shared_key, challenge))
            .into()
    }

    #[must_use]
    pub fn check_auth_ok_no_challenge(&self, shared_key: &[u8]) -> bool {
        assert_eq!(self.operation(), Operation::Knock);
        self.auth
            .ct_eq(&self.authenticate_no_challenge(shared_key))
            .into()
    }

    pub fn generate_auth(&mut self, shared_key: &[u8], challenge: Message) {
        assert_eq!(challenge.operation(), Operation::Challenge);
        assert_eq!(self.operation(), Operation::Response);
        self.auth = self.authenticate(shared_key, &challenge.auth);
    }

    pub fn generate_auth_no_challenge(&mut self, shared_key: &[u8]) {
        assert_eq!(self.operation(), Operation::Knock);
        self.auth = self.authenticate_no_challenge(shared_key);
    }

    pub fn generate_challenge(&mut self) -> Challenge {
        assert_eq!(self.operation(), Operation::Challenge);
        self.auth = secure_random();
        self.auth
    }

    pub fn msg_serialize(&self) -> ah::Result<Vec<u8>> {
        Ok(bincode_config().serialize(self)?)
    }

    pub fn try_msg_deserialize(buf: &[u8]) -> ah::Result<DeserializeResult<Message>> {
        if buf.len() < MSG_SIZE {
            Ok(DeserializeResult::Pending(MSG_SIZE - buf.len()))
        } else {
            let msg: Message = bincode_config().deserialize(&buf[0..MSG_SIZE])?;
            if msg.magic != MAGIC {
                return Err(err!("Deserialize: Invalid magic code."));
            }
            Ok(DeserializeResult::Ok(msg))
        }
    }
}

// vim: ts=4 sw=4 expandtab
