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

/// Default letmeind port number.
pub const PORT: u16 = 5800;

/// letmeind message size, in bytes.
/// All message types have the same size.
pub const MSG_SIZE: usize = 4 + 4 + 4 + 4 + SALT_SIZE + AUTH_SIZE;

/// Magic code in the message header.
const MAGIC: u32 = 0x3B1BB719;

/// Size of the message salt, in bytes.
const SALT_SIZE: usize = 8;

/// Size of the authentication/challenge token, in bytes.
const AUTH_SIZE: usize = 32;

/// Size of the authentication key, in bytes.
const KEY_SIZE: usize = 32;

/// Type of the message salt.
pub type Salt = [u8; SALT_SIZE];

/// Type of the authentication token.
pub type Auth = [u8; AUTH_SIZE];

/// Type of the authentication key.
pub type Key = [u8; KEY_SIZE];

/// Type of the challenge token.
pub type Challenge = Auth;

/// Invalid all-zero salt.
const ZERO_SALT: Salt = [0; SALT_SIZE];

/// Invalid all-zero authentication token.
const ZERO_AUTH: Auth = [0; AUTH_SIZE];

/// Generate a cryptographically secure random token.
/// Returns an array of random bytes.
pub fn secure_random<const SZ: usize>() -> [u8; SZ] {
    assert!(SZ >= 8);
    let mut buf: [u8; SZ] = [0; SZ];
    // Get secure random bytes from the operating system.
    if getrandom(&mut buf).is_err() {
        panic!("Failed to read secure random bytes from the operating system. (getrandom failed)");
    }
    // Sanity check if getrandom implementation
    // is a no-op or otherwise trivially broken.
    assert_ne!(buf, [0; SZ]);
    assert_ne!(buf, [0xFF; SZ]);
    let first = buf[0];
    assert!(!buf.iter().all(|x| *x == first));
    buf
}

/// Result of a message deserialization.
#[derive(Clone, Debug)]
pub enum DeserializeResult<M> {
    /// Deserialization was successful.
    Ok(M),
    /// The byte stream is too short.
    /// The argument 0 is the number of missing bytes.
    Pending(usize),
}

/// Create a `bincode` instance that is used to serialize/deserialize the messages.
///
/// This serializer writes all integers as big-endian fixed-width ints.
#[inline]
fn bincode_config() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_limit(MSG_SIZE.try_into().unwrap())
        .with_big_endian()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

/// The operation the message shall perform.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Operation {
    /// The `Knock` message is the initial message from the client
    /// to the server in a knock sequence.
    ///
    /// This message is not replay-safe by design.
    Knock,

    /// The `Challenge` is the server response to a `Knock`.
    ///
    /// The server provides a random challenge nonce.
    ///
    /// This message is MiM-safe.
    /// It is replay-safe, because the challenge is a nonce.
    Challenge,

    /// The `Response` is the client's response to a `Challenge`.
    ///
    /// It proves the client's possession of the shared key to the server in a
    /// replay-safe and MiM-safe way.
    Response,

    /// `ComeIn` is the server's Ok-response after a successful authentication.
    ///
    /// This message is not MiM-safe and not replay-safe by design.
    ComeIn,

    /// `GoAway` is the server's rejection response that can be sent at any
    /// time in the sequence.
    ///
    /// This message is not MiM-safe and not replay-safe by design.
    GoAway,
}

/// The message data type.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    magic: u32,
    operation: Operation,
    user: u32,
    resource: u32,
    salt: Salt,
    auth: Auth,
}

impl Message {
    /// Create a new message instance.
    pub fn new(operation: Operation, user: u32, resource: u32) -> Self {
        let msg = Self {
            magic: MAGIC,
            operation,
            user,
            resource,
            salt: secure_random(),
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

    /// Get the [Operation] of this message.
    pub fn operation(&self) -> Operation {
        self.operation
    }

    /// Get the user identification of this message.
    pub fn user(&self) -> u32 {
        self.user
    }

    /// Get the resource identification of this message.
    pub fn resource(&self) -> u32 {
        self.resource
    }

    /// Generate an authentication token.
    #[must_use]
    fn authenticate(&self, shared_key: &[u8], challenge: &[u8]) -> Auth {
        assert_eq!(shared_key.len(), KEY_SIZE);
        assert_eq!(challenge.len(), AUTH_SIZE);
        assert_ne!(self.salt, ZERO_SALT);

        let mut mac = Hmac::<Sha3_256>::new_from_slice(shared_key)
            .expect("HMAC<SHA3-256> initialization failed");
        mac.update(&(self.operation as u32).to_be_bytes());
        mac.update(&self.user.to_be_bytes());
        mac.update(&self.resource.to_be_bytes());
        mac.update(&self.salt);
        mac.update(challenge);
        let mac_bytes = mac.finalize().into_bytes();

        let mut auth: Auth = ZERO_AUTH;
        auth.copy_from_slice(mac_bytes.as_slice());
        assert_ne!(auth, ZERO_AUTH);

        auth
    }

    /// Generate an authentication token without a challenge token.
    #[must_use]
    fn authenticate_no_challenge(&self, shared_key: &[u8]) -> Auth {
        self.authenticate(shared_key, &ZERO_AUTH)
    }

    /// Check if the authentication token in this message is valid
    /// given the provided `shared_key` and `challenge`.
    #[must_use]
    pub fn check_auth_ok(&self, shared_key: &[u8], challenge: &[u8]) -> bool {
        assert_eq!(self.operation(), Operation::Response);
        self.auth
            .ct_eq(&self.authenticate(shared_key, challenge))
            .into()
    }

    /// Check if the no-challenge-authentication token in this message is valid
    /// given the provided `shared_key`.
    #[must_use]
    pub fn check_auth_ok_no_challenge(&self, shared_key: &[u8]) -> bool {
        assert_eq!(self.operation(), Operation::Knock);
        self.auth
            .ct_eq(&self.authenticate_no_challenge(shared_key))
            .into()
    }

    /// Generate a new authentication token
    /// with the provided `shared_key` and `challenge`
    /// and store it in this message.
    pub fn generate_auth(&mut self, shared_key: &[u8], challenge: Message) {
        assert_eq!(challenge.operation(), Operation::Challenge);
        assert_eq!(self.operation(), Operation::Response);
        self.auth = self.authenticate(shared_key, &challenge.auth);
    }

    /// Generate a new no-challenge-authentication token
    /// with the provided `shared_key`
    /// and store it in this message.
    pub fn generate_auth_no_challenge(&mut self, shared_key: &[u8]) {
        assert_eq!(self.operation(), Operation::Knock);
        self.auth = self.authenticate_no_challenge(shared_key);
    }

    /// Generate a new random challenge nonce and store it in
    /// the authentication field of this message.
    pub fn generate_challenge(&mut self) -> Challenge {
        assert_eq!(self.operation(), Operation::Challenge);
        self.auth = secure_random();
        self.auth
    }

    /// Serialize this message into a byte stream.
    pub fn msg_serialize(&self) -> ah::Result<Vec<u8>> {
        Ok(bincode_config().serialize(self)?)
    }

    /// Try to deserialize a byte stream into a message.
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
