// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This crate implements the `letmein` wire protocol.
//!
//! Serializing messages to a raw byte stream and
//! deserializing raw byte stream to a message is implemented here.
//!
//! The `letmein` authentication algorithm primitives are implemented here.

#![forbid(unsafe_code)]

mod socket;

use anyhow::{self as ah, format_err as err};
use hmac::{Hmac, Mac as _};
use sha3::Sha3_256;
use subtle::ConstantTimeEq as _;

pub use crate::socket::{NetSocket, UdpDispatcher};

/// Internal debugging.
const DEBUG: bool = false;

/// Default letmeind port number.
pub const PORT: u16 = 5800;

/// Magic code in the message header.
const MAGIC: u32 = 0x3B1BB719;

/// Size of the message salt, in bytes.
const SALT_SIZE: usize = 8;

/// Size of the authentication/challenge token, in bytes.
const AUTH_SIZE: usize = 32;

/// Size of the authentication key, in bytes.
const KEY_SIZE: usize = 32;

/// Type of the message salt.
type Salt = [u8; SALT_SIZE];

/// Type of the authentication token.
pub type Auth = [u8; AUTH_SIZE];

/// Type of the authentication key.
pub type Key = [u8; KEY_SIZE];

/// Invalid all-zero authentication token.
const ZERO_AUTH: Auth = [0; AUTH_SIZE];

/// Identification number of a resource.
///
/// Used in the wire protocol and in the configuration file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResourceId(u32);

/// Identification number of a user (and a key).
///
/// Used in the wire protocol and in the configuration file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct UserId(u32);

macro_rules! impl_id {
    ($ty:ident) => {
        impl From<$ty> for u32 {
            fn from(id: $ty) -> u32 {
                id.0
            }
        }

        impl From<u32> for $ty {
            fn from(id: u32) -> $ty {
                $ty(id)
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                write!(f, "{:08X}", self.0)
            }
        }

        impl std::str::FromStr for $ty {
            type Err = ah::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(u32::from_str_radix(s.trim(), 16)?.into())
            }
        }
    };
}

impl_id!(ResourceId);
impl_id!(UserId);

/// Maximum size of the UDP receive queue.
const UDP_RX_QUEUE_SIZE: usize = 4;

/// [NetSocket] for sending and receiving a [Message] over TCP or UDP.
pub type MsgNetSocket = NetSocket<MSG_SIZE, UDP_RX_QUEUE_SIZE>;

/// [UdpDispatcher] for sending and receiving a [Message] over UDP.
pub type MsgUdpDispatcher = UdpDispatcher<MSG_SIZE, UDP_RX_QUEUE_SIZE>;

/// Generate a cryptographically secure random token.
///
/// This function can only generate tokens longer than 7 bytes.
/// Returns an array of random bytes.
pub fn secure_random<const SZ: usize>() -> [u8; SZ] {
    // For lengths bigger than 8 bytes the likelyhood of the sanity checks below
    // triggering on good generator is low enough.
    assert!(SZ >= 8);

    // Get secure random bytes from the operating system.
    let mut buf: [u8; SZ] = [0; SZ];
    if getrandom::fill(&mut buf).is_err() {
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

/// The operation the message shall perform.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

    /// The `Close` message is sent by the client to request closing
    /// a previously opened port.
    ///
    /// This message follows the same authentication sequence as Knock.
    Close,
}

impl TryFrom<u32> for Operation {
    type Error = ah::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        const OPERATION_KNOCK: u32 = Operation::Knock as u32;
        const OPERATION_CHALLENGE: u32 = Operation::Challenge as u32;
        const OPERATION_RESPONSE: u32 = Operation::Response as u32;
        const OPERATION_COMEIN: u32 = Operation::ComeIn as u32;
        const OPERATION_GOAWAY: u32 = Operation::GoAway as u32;
        const OPERATION_CLOSE: u32 = Operation::Close as u32;
        match value {
            OPERATION_KNOCK => Ok(Self::Knock),
            OPERATION_CHALLENGE => Ok(Self::Challenge),
            OPERATION_RESPONSE => Ok(Self::Response),
            OPERATION_COMEIN => Ok(Self::ComeIn),
            OPERATION_GOAWAY => Ok(Self::GoAway),
            OPERATION_CLOSE => Ok(Self::Close),
            _ => Err(err!("Invalid Message/Operation value")),
        }
    }
}

impl From<Operation> for u32 {
    fn from(operation: Operation) -> u32 {
        operation as _
    }
}

/// letmeind message size, in bytes.
/// All message types have the same size.
pub const MSG_SIZE: usize = 4 + 4 + 4 + 4 + SALT_SIZE + AUTH_SIZE;

/// Byte offset of the `magic` field.
const MSG_OFFS_MAGIC: usize = 0;

/// Byte offset of the `operation` field.
const MSG_OFFS_OPERATION: usize = 4;

/// Byte offset of the `user` field.
const MSG_OFFS_USER: usize = 8;

/// Byte offset of the `resource` field.
const MSG_OFFS_RESOURCE: usize = 12;

/// Byte offset of the `salt` field.
const MSG_OFFS_SALT: usize = 16;

/// Byte offset of the `auth` field.
const MSG_OFFS_AUTH: usize = 24;

/// The message data type.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    magic: u32,
    operation: Operation,
    user: UserId,
    resource: ResourceId,
    salt: Salt,
    auth: Auth,
}

impl Message {
    /// Create a new message instance.
    pub fn new(operation: Operation, user: UserId, resource: ResourceId) -> Self {
        Self {
            magic: MAGIC,
            operation,
            user,
            resource,
            salt: secure_random(),
            auth: ZERO_AUTH,
        }
    }

    /// Get the [Operation] of this message.
    pub fn operation(&self) -> Operation {
        self.operation
    }

    /// Get the user identification of this message.
    pub fn user(&self) -> UserId {
        self.user
    }

    /// Get the resource identification of this message.
    pub fn resource(&self) -> ResourceId {
        self.resource
    }

    /// Generate an authentication token.
    #[must_use]
    fn authenticate(&self, shared_key: &[u8], challenge: &[u8]) -> Auth {
        assert_eq!(shared_key.len(), KEY_SIZE);
        assert_eq!(challenge.len(), AUTH_SIZE);

        let operation: u32 = self.operation.into();
        let user: u32 = self.user.into();
        let resource: u32 = self.resource.into();

        let mut mac = Hmac::<Sha3_256>::new_from_slice(shared_key)
            .expect("HMAC<SHA3-256> initialization failed");
        mac.update(&operation.to_be_bytes());
        mac.update(&user.to_be_bytes());
        mac.update(&resource.to_be_bytes());
        mac.update(&self.salt);
        mac.update(challenge);
        let mac_bytes = mac.finalize().into_bytes();

        let auth: Auth = mac_bytes.into();
        debug_assert_ne!(auth, ZERO_AUTH);

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
        #[cfg(not(test))]
        assert_eq!(self.operation(), Operation::Response);
        self.auth
            .ct_eq(&self.authenticate(shared_key, &challenge.auth))
            .into()
    }

    /// Check if the no-challenge-authentication token in this message is valid
    /// given the provided `shared_key`.
    #[must_use]
    pub fn check_auth_ok_no_challenge(&self, shared_key: &[u8]) -> bool {
        #[cfg(not(test))]
        assert!(self.operation() == Operation::Knock || self.operation() == Operation::Close, "Operation must be Knock or Close, got {:?}", self.operation());
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
        assert!(self.operation() == Operation::Knock || self.operation() == Operation::Close, "Operation must be Knock or Close, got {:?}", self.operation());
        self.auth = self.authenticate_no_challenge(shared_key);
    }

    /// Generate a new random challenge nonce and store it in
    /// the authentication field of this message.
    pub fn generate_challenge(&mut self) {
        assert_eq!(self.operation(), Operation::Challenge);
        self.auth = secure_random();
    }

    /// Serialize this message into a byte stream.
    pub fn msg_serialize(&self) -> ah::Result<[u8; MSG_SIZE]> {
        // The serialization is simple enough to do manually.
        // Therefore, we don't use the `serde` crate here.

        #[inline]
        fn serialize_u32(buf: &mut [u8], value: u32) {
            buf[0..4].copy_from_slice(&value.to_be_bytes());
        }

        let mut buf = [0; MSG_SIZE];
        serialize_u32(&mut buf[MSG_OFFS_MAGIC..], self.magic);
        serialize_u32(&mut buf[MSG_OFFS_OPERATION..], self.operation.into());
        serialize_u32(&mut buf[MSG_OFFS_USER..], self.user.into());
        serialize_u32(&mut buf[MSG_OFFS_RESOURCE..], self.resource.into());
        buf[MSG_OFFS_SALT..MSG_OFFS_SALT + SALT_SIZE].copy_from_slice(&self.salt);
        buf[MSG_OFFS_AUTH..MSG_OFFS_AUTH + AUTH_SIZE].copy_from_slice(&self.auth);

        Ok(buf)
    }

    /// Try to deserialize a byte stream into a message.
    pub fn try_msg_deserialize(buf: &[u8]) -> ah::Result<Self> {
        if buf.len() != MSG_SIZE {
            return Err(err!("Deserialize: Raw message size mismatch."));
        }

        // The deserialization is simple enough to do manually.
        // Therefore, we don't use the `serde` crate here.

        #[inline]
        fn deserialize_u32(buf: &[u8]) -> ah::Result<u32> {
            Ok(u32::from_be_bytes(buf[0..4].try_into()?))
        }

        let magic = deserialize_u32(&buf[MSG_OFFS_MAGIC..])?;
        let operation = deserialize_u32(&buf[MSG_OFFS_OPERATION..])?;
        let user = deserialize_u32(&buf[MSG_OFFS_USER..])?;
        let resource = deserialize_u32(&buf[MSG_OFFS_RESOURCE..])?;
        let salt = &buf[MSG_OFFS_SALT..MSG_OFFS_SALT + SALT_SIZE];
        let auth = &buf[MSG_OFFS_AUTH..MSG_OFFS_AUTH + AUTH_SIZE];

        if magic != MAGIC {
            return Err(err!("Deserialize: Invalid magic code."));
        }

        Ok(Self {
            magic,
            operation: operation.try_into()?,
            user: user.into(),
            resource: resource.into(),
            salt: salt.try_into()?,
            auth: auth.try_into()?,
        })
    }

    /// Send this message over a [MsgNetSocket].
    pub async fn send(&self, sock: &MsgNetSocket) -> ah::Result<()> {
        sock.send(self.msg_serialize()?).await?;
        if DEBUG {
            println!("TX: {self:?}");
        }
        Ok(())
    }

    /// Try to receive a message from a [MsgNetSocket].
    pub async fn recv(sock: &MsgNetSocket) -> ah::Result<Option<Self>> {
        let buf: Option<[u8; MSG_SIZE]> = sock.recv().await?;
        if let Some(buf) = buf {
            let msg = Self::try_msg_deserialize(&buf)?;
            if DEBUG {
                println!("RX: {msg:?}");
            }
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random() {
        // secure_random() has always-on assertions internally.
        // They must not trigger.
        let _buf: [u8; 8] = secure_random();
    }

    #[test]
    #[should_panic(expected = "SZ >= 8")]
    fn test_secure_random_too_small() {
        let _buf: [u8; 7] = secure_random();
    }

    fn check_ser_de(msg: &Message) {
        // Serialize a message and then deserialize the byte stream
        // and check if the resulting message is the same.
        let bytes = msg.msg_serialize().unwrap();
        let msg_de = Message::try_msg_deserialize(&bytes).unwrap();
        assert_eq!(*msg, msg_de);
    }

    #[test]
    #[rustfmt::skip]
    fn test_msg_knock() {
        let key = [0x9E; 32];

        let make_knock = || -> Message {
            let mut msg = Message::new(Operation::Knock, 0xA423DDA7.into(), 0xBC5D8077.into());
            assert_ne!(msg.salt, [0; 8]);
            msg.salt = [0x4A; 8]; // override random salt
            msg.generate_auth_no_challenge(&key);
            msg
        };

        // Create a knock message and check the authentication.
        let msg = make_knock();
        assert_eq!(msg.operation(), Operation::Knock);
        assert_eq!(msg.user(), 0xA423DDA7.into());
        assert_eq!(msg.resource(), 0xBC5D8077.into());
        assert_eq!(
            msg.auth,
            [
                99, 153, 229, 224, 255, 22, 33, 154, 94, 191, 98, 153, 196, 29, 202, 24, 154, 47,
                118, 25, 189, 10, 178, 234, 95, 129, 184, 174, 249, 254, 6, 0
            ]
        );
        assert!(msg.check_auth_ok_no_challenge(&key));

        // Serialize the knock message and check the raw bytes.
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

        // A modified `operation` field causes an authentication failure.
        let mut msg = make_knock();
        msg.operation = Operation::Response;
        assert!(!msg.check_auth_ok_no_challenge(&key));

        // A modified `user` field causes an authentication failure.
        let mut msg = make_knock();
        msg.user.0 += 1;
        assert!(!msg.check_auth_ok_no_challenge(&key));

        // A modified `resource` field causes an authentication failure.
        let mut msg = make_knock();
        msg.resource.0 += 1;
        assert!(!msg.check_auth_ok_no_challenge(&key));

        // A modified `salt` field causes an authentication failure.
        let mut msg = make_knock();
        msg.salt[4] = 0;
        assert!(!msg.check_auth_ok_no_challenge(&key));

        // A modified `auth` field causes an authentication failure.
        let mut msg = make_knock();
        msg.auth[20] = 0;
        assert!(!msg.check_auth_ok_no_challenge(&key));
    }

    #[test]
    fn test_msg_challenge_response() {
        let key = [0x6B; 32];

        let make_challenge = || -> Message {
            let mut challenge =
                Message::new(Operation::Challenge, 0x280D04F3.into(), 0xE2EE7397.into());
            assert_ne!(challenge.salt, [0; 8]);
            challenge.salt = [0x91; 8]; // override random salt
            challenge.generate_challenge();
            assert_ne!(challenge.auth, [0; 32]);
            challenge.auth = [0xB8; 32]; // override random challenge
            challenge
        };

        let make_response = || -> Message {
            let challenge = make_challenge();
            let mut response =
                Message::new(Operation::Response, challenge.user(), challenge.resource());
            assert_ne!(response.salt, [0; 8]);
            response.salt = [0x62; 8]; // override random salt
            response.generate_auth(&key, challenge);
            response
        };

        // Create a challenge.
        let challenge = make_challenge();
        assert_eq!(challenge.operation(), Operation::Challenge);
        assert_eq!(challenge.user(), 0x280D04F3.into());
        assert_eq!(challenge.resource(), 0xE2EE7397.into());
        check_ser_de(&challenge);

        // Create a response and authenticate it against the challenge.
        let challenge = make_challenge();
        let response = make_response();
        assert_eq!(response.operation(), Operation::Response);
        assert_eq!(response.user(), 0x280D04F3.into());
        assert_eq!(response.resource(), 0xE2EE7397.into());
        assert_eq!(
            response.auth,
            [
                172, 65, 151, 51, 129, 213, 147, 73, 88, 172, 2, 136, 153, 251, 144, 161, 48, 188,
                148, 235, 110, 140, 84, 128, 141, 33, 147, 29, 235, 185, 202, 42
            ]
        );
        assert!(response.check_auth_ok(&key, challenge));
        check_ser_de(&response);

        // A modified `operation` field causes an authentication failure.
        let challenge = make_challenge();
        let mut msg = make_response();
        msg.operation = Operation::Knock;
        assert!(!msg.check_auth_ok(&key, challenge));

        // A modified `user` field causes an authentication failure.
        let challenge = make_challenge();
        let mut msg = make_response();
        msg.user.0 += 1;
        assert!(!msg.check_auth_ok(&key, challenge));

        // A modified `resource` field causes an authentication failure.
        let challenge = make_challenge();
        let mut msg = make_response();
        msg.resource.0 += 1;
        assert!(!msg.check_auth_ok(&key, challenge));

        // A modified `salt` field causes an authentication failure.
        let challenge = make_challenge();
        let mut msg = make_response();
        msg.salt[4] = 0;
        assert!(!msg.check_auth_ok(&key, challenge));

        // A modified `auth` field causes an authentication failure.
        let challenge = make_challenge();
        let mut msg = make_response();
        msg.auth[20] = 0;
        assert!(!msg.check_auth_ok(&key, challenge));
    }

    #[test]
    fn test_msg_comein() {
        let mut msg = Message::new(Operation::ComeIn, 0xF90201B2.into(), 0xB3E46B6C.into());
        assert_ne!(msg.salt, [0; 8]);
        msg.salt = [0xEB; 8]; // override random salt
        assert_eq!(msg.operation(), Operation::ComeIn);
        assert_eq!(msg.user(), 0xF90201B2.into());
        assert_eq!(msg.resource(), 0xB3E46B6C.into());
        assert_eq!(msg.auth, [0; 32]);
        check_ser_de(&msg);
    }

    #[test]
    fn test_msg_goaway() {
        let mut msg = Message::new(Operation::GoAway, 0x0F52E045.into(), 0x9AF4EFA0.into());
        assert_ne!(msg.salt, [0; 8]);
        msg.salt = [0x8C; 8]; // override random salt
        assert_eq!(msg.operation(), Operation::GoAway);
        assert_eq!(msg.user(), 0x0F52E045.into());
        assert_eq!(msg.resource(), 0x9AF4EFA0.into());
        assert_eq!(msg.auth, [0; 32]);
        check_ser_de(&msg);
    }

    #[test]
    fn test_msg_raw() {
        let mut msg = Message::new(Operation::ComeIn, 0xF90201B2.into(), 0xB3E46B6C.into());
        msg.salt = [0x9A; 8]; // override random salt
        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x3B, 0x1B, 0xB7, 0x19, // magic
                0x00, 0x00, 0x00, 0x03, // operation
                0xF9, 0x02, 0x01, 0xB2, // user
                0xB3, 0xE4, 0x6B, 0x6C, // resource
                0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, // salt
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            ]
        );
    }

    #[test]
    #[should_panic(expected = "Invalid magic code")]
    fn test_msg_raw_invalid_magic_0() {
        let bytes = [
            0x0B, 0x1B, 0xB7, 0x19, // magic
            0x00, 0x00, 0x00, 0x03, // operation
            0xF9, 0x02, 0x01, 0xB2, // user
            0xB3, 0xE4, 0x6B, 0x6C, // resource
            0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, // salt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
        ];
        Message::try_msg_deserialize(&bytes).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid magic code")]
    fn test_msg_raw_invalid_magic_1() {
        let bytes = [
            0x3B, 0x1B, 0xB7, 0x10, // magic
            0x00, 0x00, 0x00, 0x03, // operation
            0xF9, 0x02, 0x01, 0xB2, // user
            0xB3, 0xE4, 0x6B, 0x6C, // resource
            0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, // salt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
        ];
        Message::try_msg_deserialize(&bytes).unwrap();
    }

    #[test]
    #[should_panic(expected = "Invalid Message/Operation value")]
    fn test_msg_raw_invalid_operation() {
        let bytes = [
            0x3B, 0x1B, 0xB7, 0x19, // magic
            0x00, 0x00, 0x00, 0x06, // operation (6 - valeur invalide, Close est maintenant 5)
            0xF9, 0x02, 0x01, 0xB2, // user
            0xB3, 0xE4, 0x6B, 0x6C, // resource
            0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, 0x9A, // salt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth
        ];
        Message::try_msg_deserialize(&bytes).unwrap();
    }

    #[test]
    fn test_userid() {
        let a: UserId = 0x12345678.into();
        assert_eq!(a.0, 0x12345678);
        assert_eq!(a, UserId(0x12345678));
        let b: u32 = a.into();
        assert_eq!(b, 0x12345678);
        assert_eq!(format!("{}", a), "12345678");
        let c: UserId = Default::default();
        assert_eq!(c.0, 0);
    }

    #[test]
    fn test_resourceid() {
        let a: ResourceId = 0x12345678.into();
        assert_eq!(a.0, 0x12345678);
        assert_eq!(a, ResourceId(0x12345678));
        let b: u32 = a.into();
        assert_eq!(b, 0x12345678);
        assert_eq!(format!("{}", a), "12345678");
    }
}

// vim: ts=4 sw=4 expandtab
