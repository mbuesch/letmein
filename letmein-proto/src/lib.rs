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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
    pub fn check_auth_ok(&self, shared_key: &[u8], challenge: Message) -> bool {
        assert_eq!(challenge.operation(), Operation::Challenge);
        assert_eq!(self.operation(), Operation::Response);
        self.auth
            .ct_eq(&self.authenticate(shared_key, &challenge.auth))
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
    pub fn generate_challenge(&mut self) {
        assert_eq!(self.operation(), Operation::Challenge);
        self.auth = secure_random();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random() {
        // secure_random has always-on assertions internally.
        let _buf: [u8; 8] = secure_random();
    }

    #[test]
    #[should_panic(expected = "SZ >= 8")]
    fn test_secure_random_too_small() {
        let _buf: [u8; 7] = secure_random();
    }

    fn check_ser_de(msg: &Message) {
        let bytes = msg.msg_serialize().unwrap();
        let DeserializeResult::Ok(msg_de) = Message::try_msg_deserialize(&bytes).unwrap() else {
            panic!("try_msg_deserialize not Ok");
        };
        assert_eq!(*msg, msg_de);
    }

    #[test]
    #[rustfmt::skip]
    fn test_msg_knock() {
        let key = [0x9E; 32];

        let mut msg = Message::new(Operation::Knock, 0xA423DDA7, 0xBC5D8077);
        assert_ne!(msg.salt, [0; 8]);
        msg.salt = [0x4A; 8]; // override random salt
        msg.generate_auth_no_challenge(&key);
        assert_eq!(msg.operation(), Operation::Knock);
        assert_eq!(msg.user(), 0xA423DDA7);
        assert_eq!(msg.resource(), 0xBC5D8077);
        assert_eq!(
            msg.auth,
            [
                99, 153, 229, 224, 255, 22, 33, 154, 94, 191, 98, 153, 196, 29, 202, 24, 154, 47,
                118, 25, 189, 10, 178, 234, 95, 129, 184, 174, 249, 254, 6, 0
            ]
        );
        assert!(msg.check_auth_ok_no_challenge(&key));

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x3B, 0x1B, 0xB7, 0x19, // magic
                0x00, 0x00, 0x00, 0x00, // operation
                0xA4, 0x23, 0xDD, 0xA7, // user
                0xBC, 0x5D, 0x80, 0x77, // resource
                0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, 0x4A, // salt
                msg.auth[0], msg.auth[1], msg.auth[2], msg.auth[3], // auth
                msg.auth[4], msg.auth[5], msg.auth[6], msg.auth[7], // auth
                msg.auth[8], msg.auth[9], msg.auth[10], msg.auth[11], // auth
                msg.auth[12], msg.auth[13], msg.auth[14], msg.auth[15], // auth
                msg.auth[16], msg.auth[17], msg.auth[18], msg.auth[19], // auth
                msg.auth[20], msg.auth[21], msg.auth[22], msg.auth[23], // auth
                msg.auth[24], msg.auth[25], msg.auth[26], msg.auth[27], // auth
                msg.auth[28], msg.auth[29], msg.auth[30], msg.auth[31], // auth
            ]
        );
        check_ser_de(&msg);
    }

    #[test]
    fn test_msg_challenge_response() {
        let key = [0x6B; 32];

        let mut challenge = Message::new(Operation::Challenge, 0x280D04F3, 0xE2EE7397);
        assert_ne!(challenge.salt, [0; 8]);
        challenge.salt = [0x91; 8]; // override random salt
        challenge.generate_challenge();
        assert_eq!(challenge.operation(), Operation::Challenge);
        assert_eq!(challenge.user(), 0x280D04F3);
        assert_eq!(challenge.resource(), 0xE2EE7397);
        assert_ne!(challenge.auth, [0; 32]);
        challenge.auth = [0xB8; 32]; // override random challenge
        check_ser_de(&challenge);

        let mut response =
            Message::new(Operation::Response, challenge.user(), challenge.resource());
        assert_ne!(response.salt, [0; 8]);
        response.salt = [0x62; 8]; // override salt
        response.generate_auth(&key, challenge.clone());
        assert_eq!(response.operation(), Operation::Response);
        assert_eq!(response.user(), 0x280D04F3);
        assert_eq!(response.resource(), 0xE2EE7397);
        assert_eq!(
            response.auth,
            [
                172, 65, 151, 51, 129, 213, 147, 73, 88, 172, 2, 136, 153, 251, 144, 161, 48, 188,
                148, 235, 110, 140, 84, 128, 141, 33, 147, 29, 235, 185, 202, 42
            ]
        );
        assert!(response.check_auth_ok(&key, challenge.clone()));
        check_ser_de(&response);
    }

    #[test]
    fn test_msg_comein() {
        let mut msg = Message::new(Operation::ComeIn, 0xF90201B2, 0xB3E46B6C);
        assert_ne!(msg.salt, [0; 8]);
        msg.salt = [0xEB; 8]; // override random salt
        assert_eq!(msg.operation(), Operation::ComeIn);
        assert_eq!(msg.user(), 0xF90201B2);
        assert_eq!(msg.resource(), 0xB3E46B6C);
        assert_eq!(msg.auth, [0; 32]);

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x3B, 0x1B, 0xB7, 0x19, // magic
                0x00, 0x00, 0x00, 0x03, // operation
                0xF9, 0x02, 0x01, 0xB2, // user
                0xB3, 0xE4, 0x6B, 0x6C, // resource
                0xEB, 0xEB, 0xEB, 0xEB, 0xEB, 0xEB, 0xEB, 0xEB, // salt
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            ]
        );
        check_ser_de(&msg);
    }

    #[test]
    fn test_msg_goaway() {
        let mut msg = Message::new(Operation::GoAway, 0x0F52E045, 0x9AF4EFA0);
        assert_ne!(msg.salt, [0; 8]);
        msg.salt = [0x8C; 8]; // override random salt
        assert_eq!(msg.operation(), Operation::GoAway);
        assert_eq!(msg.user(), 0x0F52E045);
        assert_eq!(msg.resource(), 0x9AF4EFA0);
        assert_eq!(msg.auth, [0; 32]);
        check_ser_de(&msg);
    }
}

// vim: ts=4 sw=4 expandtab
