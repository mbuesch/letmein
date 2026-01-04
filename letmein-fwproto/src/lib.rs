// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This crate implements the firewall socket protocol
//! for communication between the `letmeind` and `letmeinfwd` daemons.
//!
//! Serializing messages to a raw byte stream and
//! deserializing raw byte stream to a message is implemented here.

#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::ConfigChecksum;
use letmein_proto::{ResourceId, UserId};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
};
use tokio::io::ErrorKind;

#[cfg(any(target_os = "linux", target_os = "android"))]
use tokio::net::UnixStream;

#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};

/// Firewall daemon Unix socket file name.
pub const SOCK_FILE: &str = "letmeinfwd.sock";

/// The operation to perform on the firewall.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
pub enum FirewallOperation {
    /// Not-Acknowledge message.
    #[default]
    Nack,
    /// Acknowledge message.
    Ack,
    /// Open a port.
    Open,
    /// Add a jump rule.
    Jump,
    /// Revoke rules.
    Revoke,
}

impl TryFrom<u16> for FirewallOperation {
    type Error = ah::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const OPERATION_NACK: u16 = FirewallOperation::Nack as u16;
        const OPERATION_ACK: u16 = FirewallOperation::Ack as u16;
        const OPERATION_OPEN: u16 = FirewallOperation::Open as u16;
        const OPERATION_JUMP: u16 = FirewallOperation::Jump as u16;
        const OPERATION_REVOKE: u16 = FirewallOperation::Revoke as u16;
        match value {
            OPERATION_NACK => Ok(Self::Nack),
            OPERATION_ACK => Ok(Self::Ack),
            OPERATION_OPEN => Ok(Self::Open),
            OPERATION_JUMP => Ok(Self::Jump),
            OPERATION_REVOKE => Ok(Self::Revoke),
            _ => Err(err!("Invalid FirewallMessage/Operation value")),
        }
    }
}

impl From<FirewallOperation> for u16 {
    fn from(operation: FirewallOperation) -> u16 {
        operation as _
    }
}

/// The type of address to open in the firewall.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
pub enum AddrType {
    /// IPv6 address.
    #[default]
    Ipv6,
    /// IPv4 address.
    Ipv4,
}

impl TryFrom<u16> for AddrType {
    type Error = ah::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const ADDRTYPE_IPV6: u16 = AddrType::Ipv6 as u16;
        const ADDRTYPE_IPV4: u16 = AddrType::Ipv4 as u16;
        match value {
            ADDRTYPE_IPV6 => Ok(Self::Ipv6),
            ADDRTYPE_IPV4 => Ok(Self::Ipv4),
            _ => Err(err!("Invalid FirewallMessage/AddrType value")),
        }
    }
}

impl From<AddrType> for u16 {
    fn from(addr_type: AddrType) -> u16 {
        addr_type as _
    }
}

/// Size of the `addr` field in the message.
const ADDR_SIZE: usize = 16;

/// Size of the `conf_cs` field in the message.
const CONF_CS_SIZE: usize = ConfigChecksum::SIZE;

/// Size of the firewall control message.
const FWMSG_SIZE: usize = 2 + 4 + 4 + 2 + ADDR_SIZE + CONF_CS_SIZE;

/// Byte offset of the `operation` field in the firewall control message.
const FWMSG_OFFS_OPERATION: usize = 0;

/// Byte offset of the `user` field in the firewall control message.
const FWMSG_OFFS_USER: usize = 2;

/// Byte offset of the `resource` field in the firewall control message.
const FWMSG_OFFS_RESOURCE: usize = 6;

/// Byte offset of the `addr_type` field in the firewall control message.
const FWMSG_OFFS_ADDR_TYPE: usize = 10;

/// Byte offset of the `addr` field in the firewall control message.
const FWMSG_OFFS_ADDR: usize = 12;

/// Byte offset of the `conf_cs` field in the firewall control message.
const FWMSG_OFFS_CONF_CS: usize = 28;

/// A message to control the firewall.
#[derive(PartialEq, Eq, Debug, Default)]
pub struct FirewallMessage {
    operation: FirewallOperation,
    user: UserId,
    resource: ResourceId,
    addr_type: AddrType,
    addr: [u8; ADDR_SIZE],
    conf_cs: ConfigChecksum,
}

/// Convert an `IpAddr` to the `operation` and `addr` fields of a firewall control message.
fn addr_to_octets(addr: IpAddr) -> (AddrType, [u8; ADDR_SIZE]) {
    match addr {
        IpAddr::V4(addr) => {
            let o = addr.octets();
            (
                AddrType::Ipv4,
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, o[0], o[1], o[2], o[3]],
            )
        }
        IpAddr::V6(addr) => (AddrType::Ipv6, addr.octets()),
    }
}

/// Convert a firewall control message `operation` and `addr` fields to an `IpAddr`.
fn octets_to_addr(addr_type: AddrType, addr: &[u8; ADDR_SIZE]) -> IpAddr {
    match addr_type {
        AddrType::Ipv4 => Ipv4Addr::new(addr[12], addr[13], addr[14], addr[15]).into(),
        AddrType::Ipv6 => (*addr).into(),
    }
}

impl FirewallMessage {
    /// Construct a new message that requests installing a firewall-port-open rule.
    pub fn new_open(
        user: UserId,
        resource: ResourceId,
        addr: IpAddr,
        conf_cs: &ConfigChecksum,
    ) -> Self {
        let (addr_type, addr) = addr_to_octets(addr);
        Self {
            operation: FirewallOperation::Open,
            user,
            resource,
            addr_type,
            addr,
            conf_cs: conf_cs.clone(),
        }
    }

    pub fn new_jump(
        user: UserId,
        resource: ResourceId,
        addr: IpAddr,
        conf_cs: &ConfigChecksum,
    ) -> Self {
        let (addr_type, addr) = addr_to_octets(addr);
        Self {
            operation: FirewallOperation::Jump,
            user,
            resource,
            addr_type,
            addr,
            conf_cs: conf_cs.clone(),
        }
    }

    pub fn new_revoke(
        user: UserId,
        resource: ResourceId,
        addr: IpAddr,
        conf_cs: &ConfigChecksum,
    ) -> Self {
        let (addr_type, addr) = addr_to_octets(addr);
        Self {
            operation: FirewallOperation::Revoke,
            user,
            resource,
            addr_type,
            addr,
            conf_cs: conf_cs.clone(),
        }
    }

    /// Construct a new acknowledge message.
    pub fn new_ack() -> Self {
        Self {
            operation: FirewallOperation::Ack,
            ..Default::default()
        }
    }

    /// Construct a new not-acknowledge message.
    pub fn new_nack() -> Self {
        Self {
            operation: FirewallOperation::Nack,
            ..Default::default()
        }
    }

    /// Get the operation type from this message.
    pub fn operation(&self) -> FirewallOperation {
        self.operation
    }

    /// Get the user ID from this message.
    pub fn user(&self) -> UserId {
        self.user
    }

    /// Get the resource ID from this message.
    pub fn resource(&self) -> ResourceId {
        self.resource
    }

    /// Get the `IpAddr` from this message.
    pub fn addr(&self) -> Option<IpAddr> {
        match self.operation {
            FirewallOperation::Open | FirewallOperation::Jump | FirewallOperation::Revoke => {
                Some(octets_to_addr(self.addr_type, &self.addr))
            }
            FirewallOperation::Ack | FirewallOperation::Nack => None,
        }
    }

    /// Get the configuration checksum from this message.
    pub fn conf_checksum(&self) -> Option<&ConfigChecksum> {
        match self.operation {
            FirewallOperation::Open | FirewallOperation::Jump | FirewallOperation::Revoke => {
                Some(&self.conf_cs)
            }
            FirewallOperation::Ack | FirewallOperation::Nack => None,
        }
    }

    /// Serialize this message into a byte stream.
    pub fn msg_serialize(&self) -> ah::Result<[u8; FWMSG_SIZE]> {
        // The serialization is simple enough to do manually.
        // Therefore, we don't use the `serde` crate here.

        #[inline]
        fn serialize_u16(buf: &mut [u8], value: u16) {
            buf[0..2].copy_from_slice(&value.to_be_bytes());
        }

        #[inline]
        fn serialize_u32(buf: &mut [u8], value: u32) {
            buf[0..4].copy_from_slice(&value.to_be_bytes());
        }

        let mut buf = [0; FWMSG_SIZE];
        serialize_u16(&mut buf[FWMSG_OFFS_OPERATION..], self.operation.into());
        serialize_u32(&mut buf[FWMSG_OFFS_USER..], self.user.into());
        serialize_u32(&mut buf[FWMSG_OFFS_RESOURCE..], self.resource.into());
        serialize_u16(&mut buf[FWMSG_OFFS_ADDR_TYPE..], self.addr_type.into());
        buf[FWMSG_OFFS_ADDR..FWMSG_OFFS_ADDR + ADDR_SIZE].copy_from_slice(&self.addr);
        buf[FWMSG_OFFS_CONF_CS..FWMSG_OFFS_CONF_CS + CONF_CS_SIZE]
            .copy_from_slice(self.conf_cs.as_bytes());

        Ok(buf)
    }

    /// Try to deserialize a byte stream into a message.
    pub fn try_msg_deserialize(buf: &[u8]) -> ah::Result<Self> {
        if buf.len() != FWMSG_SIZE {
            return Err(err!("Deserialize: Raw message size mismatch."));
        }

        // The deserialization is simple enough to do manually.
        // Therefore, we don't use the `serde` crate here.

        #[inline]
        fn deserialize_u16(buf: &[u8]) -> ah::Result<u16> {
            Ok(u16::from_be_bytes(buf[0..2].try_into()?))
        }

        #[inline]
        fn deserialize_u32(buf: &[u8]) -> ah::Result<u32> {
            Ok(u32::from_be_bytes(buf[0..4].try_into()?))
        }

        let operation = deserialize_u16(&buf[FWMSG_OFFS_OPERATION..])?;
        let user = deserialize_u32(&buf[FWMSG_OFFS_USER..])?;
        let resource = deserialize_u32(&buf[FWMSG_OFFS_RESOURCE..])?;
        let addr_type = deserialize_u16(&buf[FWMSG_OFFS_ADDR_TYPE..])?;
        let addr = &buf[FWMSG_OFFS_ADDR..FWMSG_OFFS_ADDR + ADDR_SIZE];
        let conf_cs = &buf[FWMSG_OFFS_CONF_CS..FWMSG_OFFS_CONF_CS + CONF_CS_SIZE];

        Ok(Self {
            operation: operation.try_into()?,
            resource: resource.into(),
            user: user.into(),
            addr_type: addr_type.try_into()?,
            addr: addr.try_into()?,
            conf_cs: conf_cs.try_into()?,
        })
    }

    /// Send this message over a [Stream].
    pub async fn send(&self, stream: &mut impl Stream) -> ah::Result<()> {
        let txbuf = self.msg_serialize()?;
        let mut txcount = 0;
        loop {
            stream.writable().await.context("Socket polling (tx)")?;
            match stream.try_write(&txbuf[txcount..]) {
                Ok(n) => {
                    txcount += n;
                    assert!(txcount <= txbuf.len());
                    if txcount == txbuf.len() {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(err!("Socket write: {e}"));
                }
            }
        }
    }

    /// Try to receive a message from a [Stream].
    pub async fn recv(stream: &mut impl Stream) -> ah::Result<Option<Self>> {
        let mut rxbuf = [0; FWMSG_SIZE];
        let mut rxcount = 0;
        loop {
            stream.readable().await.context("Socket polling (rx)")?;
            match stream.try_read(&mut rxbuf[rxcount..]) {
                Ok(n) => {
                    if n == 0 {
                        return Ok(None);
                    }
                    rxcount += n;
                    assert!(rxcount <= FWMSG_SIZE);
                    if rxcount == FWMSG_SIZE {
                        return Ok(Some(Self::try_msg_deserialize(&rxbuf)?));
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(err!("Socket read: {e}"));
                }
            }
        }
    }
}

/// Communication stream abstraction.
pub trait Stream {
    fn readable(&self) -> impl Future<Output = std::io::Result<()>> + Send;
    fn try_read(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn writable(&self) -> impl Future<Output = std::io::Result<()>> + Send;
    fn try_write(&self, buf: &[u8]) -> std::io::Result<usize>;
}

macro_rules! impl_stream_for {
    ($ty:ty) => {
        impl Stream for $ty {
            fn readable(&self) -> impl Future<Output = std::io::Result<()>> + Send {
                self.readable()
            }
            fn try_read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.try_read(buf)
            }
            fn writable(&self) -> impl Future<Output = std::io::Result<()>> + Send {
                self.writable()
            }
            fn try_write(&self, buf: &[u8]) -> std::io::Result<usize> {
                self.try_write(buf)
            }
        }
    };
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl_stream_for!(UnixStream);
#[cfg(target_os = "windows")]
impl_stream_for!(NamedPipeClient);
#[cfg(target_os = "windows")]
impl_stream_for!(NamedPipeServer);

#[cfg(test)]
mod tests {
    use super::*;

    fn check_ser_de(msg: &FirewallMessage) {
        // Serialize a message and then deserialize the byte stream
        // and check if the resulting message is the same.
        let bytes = msg.msg_serialize().unwrap();
        let msg_de = FirewallMessage::try_msg_deserialize(&bytes).unwrap();
        assert_eq!(*msg, msg_de);
    }

    #[test]
    fn test_msg_open_v6() {
        let msg = FirewallMessage::new_open(
            0x66773322.into(),
            0xAABB9988.into(),
            "::1".parse().unwrap(),
            &ConfigChecksum::calculate(b"foo"),
        );
        assert_eq!(msg.operation(), FirewallOperation::Open);
        assert_eq!(msg.addr(), Some("::1".parse().unwrap()));
        check_ser_de(&msg);

        let msg = FirewallMessage::new_open(
            0x66773322.into(),
            0xAABB9988.into(),
            "0102:0304:0506:0708:090A:0B0C:0D0E:0F10".parse().unwrap(),
            &ConfigChecksum::calculate(b"foo"),
        );
        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x66, 0x77, 0x33, 0x22, // user
                0xAA, 0xBB, 0x99, 0x88, // resource
                0x00, 0x00, // addr_type
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // addr
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // addr
                0xA9, 0x14, 0x20, 0xEB, 0x27, 0x9B, 0xD1, 0x96, // conf_cs
                0x15, 0x04, 0x9D, 0x00, 0xD6, 0x07, 0x07, 0x35, // conf_cs
                0xAF, 0xF1, 0xE9, 0x28, 0xC1, 0xBF, 0x9C, 0x65, // conf_cs
                0x3F, 0x29, 0x22, 0x33, 0x11, 0xDD, 0x4C, 0xAA, // conf_cs
            ]
        );

        let msg = FirewallMessage::new_open(
            0x66773322.into(),
            0xAABB9988.into(),
            "0102:0304:0506:0708:090A:0B0C:0D0E:0F10".parse().unwrap(),
            &ConfigChecksum::calculate(b"foo"),
        );
        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x66, 0x77, 0x33, 0x22, // user
                0xAA, 0xBB, 0x99, 0x88, // resource
                0x00, 0x00, // addr_type
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // addr
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // addr
                0xA9, 0x14, 0x20, 0xEB, 0x27, 0x9B, 0xD1, 0x96, // conf_cs
                0x15, 0x04, 0x9D, 0x00, 0xD6, 0x07, 0x07, 0x35, // conf_cs
                0xAF, 0xF1, 0xE9, 0x28, 0xC1, 0xBF, 0x9C, 0x65, // conf_cs
                0x3F, 0x29, 0x22, 0x33, 0x11, 0xDD, 0x4C, 0xAA, // conf_cs
            ]
        );

        let msg = FirewallMessage::new_open(
            0x66773322.into(),
            0xAABB9988.into(),
            "0102:0304:0506:0708:090A:0B0C:0D0E:0F10".parse().unwrap(),
            &ConfigChecksum::calculate(b"bar"),
        );
        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x66, 0x77, 0x33, 0x22, // user
                0xAA, 0xBB, 0x99, 0x88, // resource
                0x00, 0x00, // addr_type
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // addr
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // addr
                0xFB, 0x58, 0xE5, 0x1D, 0x34, 0xB5, 0x6B, 0x33, // conf_cs
                0x78, 0xF6, 0xEC, 0x2D, 0x4A, 0x54, 0x96, 0xC2, // conf_cs
                0xAF, 0x00, 0xF2, 0x75, 0x02, 0x00, 0x0F, 0xD5, // conf_cs
                0x98, 0xED, 0x31, 0x09, 0x73, 0x68, 0x50, 0x79, // conf_cs
            ]
        );
    }

    #[test]
    fn test_msg_open_v4() {
        let msg = FirewallMessage::new_open(
            0x66773322.into(),
            0xAABB9988.into(),
            "1.2.3.4".parse().unwrap(),
            &ConfigChecksum::calculate(b"foo"),
        );
        assert_eq!(msg.operation(), FirewallOperation::Open);
        assert_eq!(msg.addr(), Some("1.2.3.4".parse().unwrap()));
        check_ser_de(&msg);

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x66, 0x77, 0x33, 0x22, // user
                0xAA, 0xBB, 0x99, 0x88, // resource
                0x00, 0x01, // addr_type
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, // addr
                0xA9, 0x14, 0x20, 0xEB, 0x27, 0x9B, 0xD1, 0x96, // conf_cs
                0x15, 0x04, 0x9D, 0x00, 0xD6, 0x07, 0x07, 0x35, // conf_cs
                0xAF, 0xF1, 0xE9, 0x28, 0xC1, 0xBF, 0x9C, 0x65, // conf_cs
                0x3F, 0x29, 0x22, 0x33, 0x11, 0xDD, 0x4C, 0xAA, // conf_cs
            ]
        );
    }

    #[test]
    fn test_msg_ack() {
        let msg = FirewallMessage::new_ack();
        assert_eq!(msg.operation(), FirewallOperation::Ack);
        assert_eq!(msg.addr(), None);
        check_ser_de(&msg);

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x01, // operation
                0x00, 0x00, 0x00, 0x00, // user
                0x00, 0x00, 0x00, 0x00, // resource
                0x00, 0x00, // addr_type
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
            ]
        );
    }

    #[test]
    fn test_msg_nack() {
        let msg = FirewallMessage::new_nack();
        assert_eq!(msg.operation(), FirewallOperation::Nack);
        assert_eq!(msg.addr(), None);
        check_ser_de(&msg);

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x00, // operation
                0x00, 0x00, 0x00, 0x00, // user
                0x00, 0x00, 0x00, 0x00, // resource
                0x00, 0x00, // addr_type
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // conf_cs
            ]
        );
    }
}

// vim: ts=4 sw=4 expandtab
