// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
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
    /// Close a port.
    Close,
}

impl TryFrom<u16> for FirewallOperation {
    type Error = ah::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const OPERATION_OPEN: u16 = FirewallOperation::Open as u16;
        const OPERATION_ACK: u16 = FirewallOperation::Ack as u16;
        const OPERATION_NACK: u16 = FirewallOperation::Nack as u16;
        const OPERATION_CLOSE: u16 = FirewallOperation::Close as u16;
        match value {
            OPERATION_OPEN => Ok(Self::Open),
            OPERATION_ACK => Ok(Self::Ack),
            OPERATION_NACK => Ok(Self::Nack),
            OPERATION_CLOSE => Ok(Self::Close),
            _ => Err(err!("Invalid FirewallMessage/Operation value")),
        }
    }
}

impl From<FirewallOperation> for u16 {
    fn from(operation: FirewallOperation) -> u16 {
        operation as _
    }
}

/// The type of port to open in the firewall.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u16)]
pub enum PortType {
    /// TCP port only.
    #[default]
    Tcp,
    /// UDP port only.
    Udp,
    /// TCP and UDP port.
    TcpUdp,
}

impl TryFrom<u16> for PortType {
    type Error = ah::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        const PORTTYPE_TCP: u16 = PortType::Tcp as u16;
        const PORTTYPE_UDP: u16 = PortType::Udp as u16;
        const PORTTYPE_TCPUDP: u16 = PortType::TcpUdp as u16;
        match value {
            PORTTYPE_TCP => Ok(Self::Tcp),
            PORTTYPE_UDP => Ok(Self::Udp),
            PORTTYPE_TCPUDP => Ok(Self::TcpUdp),
            _ => Err(err!("Invalid FirewallMessage/PortType value")),
        }
    }
}

impl From<PortType> for u16 {
    fn from(port_type: PortType) -> u16 {
        port_type as _
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

/// Size of the firewall control message.
const FWMSG_SIZE: usize = 2 + 2 + 2 + 2 + ADDR_SIZE;

/// Byte offset of the `operation` field in the firewall control message.
const FWMSG_OFFS_OPERATION: usize = 0;

/// Byte offset of the `port_type` field in the firewall control message.
const FWMSG_OFFS_PORT_TYPE: usize = 2;

/// Byte offset of the `port` field in the firewall control message.
const FWMSG_OFFS_PORT: usize = 4;

/// Byte offset of the `addr_type` field in the firewall control message.
const FWMSG_OFFS_ADDR_TYPE: usize = 6;

/// Byte offset of the `addr` field in the firewall control message.
const FWMSG_OFFS_ADDR: usize = 8;

/// A message to control the firewall.
#[derive(PartialEq, Eq, Debug, Default)]
pub struct FirewallMessage {
    operation: FirewallOperation,
    port_type: PortType,
    port: u16,
    addr_type: AddrType,
    addr: [u8; ADDR_SIZE],
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
    pub fn new_open(addr: IpAddr, port_type: PortType, port: u16) -> Self {
        let (addr_type, addr) = addr_to_octets(addr);
        Self {
            operation: FirewallOperation::Open,
            port_type,
            port,
            addr_type,
            addr,
        }
    }

    /// Construct a new message that requests removing a firewall-port-open rule.
    pub fn new_close(addr: IpAddr, port_type: PortType, port: u16) -> Self {
        let (addr_type, addr) = addr_to_octets(addr);
        Self {
            operation: FirewallOperation::Close,
            port_type,
            port,
            addr_type,
            addr,
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

    /// Get the port number from this message.
    pub fn port(&self) -> Option<(PortType, u16)> {
        match self.operation {
            FirewallOperation::Open | FirewallOperation::Close => Some((self.port_type, self.port)),
            FirewallOperation::Ack | FirewallOperation::Nack => None,
        }
    }

    /// Get the `IpAddr` from this message.
    pub fn addr(&self) -> Option<IpAddr> {
        match self.operation {
            FirewallOperation::Open | FirewallOperation::Close => Some(octets_to_addr(self.addr_type, &self.addr)),
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

        let mut buf = [0; FWMSG_SIZE];
        serialize_u16(&mut buf[FWMSG_OFFS_OPERATION..], self.operation.into());
        serialize_u16(&mut buf[FWMSG_OFFS_PORT_TYPE..], self.port_type.into());
        serialize_u16(&mut buf[FWMSG_OFFS_PORT..], self.port);
        serialize_u16(&mut buf[FWMSG_OFFS_ADDR_TYPE..], self.addr_type.into());
        buf[FWMSG_OFFS_ADDR..FWMSG_OFFS_ADDR + ADDR_SIZE].copy_from_slice(&self.addr);

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

        let operation = deserialize_u16(&buf[FWMSG_OFFS_OPERATION..])?;
        let port_type = deserialize_u16(&buf[FWMSG_OFFS_PORT_TYPE..])?;
        let port = deserialize_u16(&buf[FWMSG_OFFS_PORT..])?;
        let addr_type = deserialize_u16(&buf[FWMSG_OFFS_ADDR_TYPE..])?;
        let addr = &buf[FWMSG_OFFS_ADDR..FWMSG_OFFS_ADDR + ADDR_SIZE];

        Ok(Self {
            operation: operation.try_into()?,
            port_type: port_type.try_into()?,
            port,
            addr_type: addr_type.try_into()?,
            addr: addr.try_into()?,
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
        let msg = FirewallMessage::new_open("::1".parse().unwrap(), PortType::Tcp, 0x9876);
        assert_eq!(msg.operation(), FirewallOperation::Open);
        assert_eq!(msg.port(), Some((PortType::Tcp, 0x9876)));
        assert_eq!(msg.addr(), Some("::1".parse().unwrap()));
        check_ser_de(&msg);

        let msg = FirewallMessage::new_open(
            "0102:0304:0506:0708:090A:0B0C:0D0E:0F10".parse().unwrap(),
            PortType::Tcp,
            0x9876,
        );
        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x00, 0x00, // port_type
                0x98, 0x76, // port
                0x00, 0x00, // addr_type
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // addr
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // addr
            ]
        );

        let msg = FirewallMessage::new_open(
            "0102:0304:0506:0708:090A:0B0C:0D0E:0F10".parse().unwrap(),
            PortType::Udp,
            0x9876,
        );
        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x00, 0x01, // port_type
                0x98, 0x76, // port
                0x00, 0x00, // addr_type
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // addr
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // addr
            ]
        );

        let msg = FirewallMessage::new_open(
            "0102:0304:0506:0708:090A:0B0C:0D0E:0F10".parse().unwrap(),
            PortType::TcpUdp,
            0x9876,
        );
        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x00, 0x02, // port_type
                0x98, 0x76, // port
                0x00, 0x00, // addr_type
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // addr
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // addr
            ]
        );
    }

    #[test]
    fn test_msg_open_v4() {
        let msg = FirewallMessage::new_open("1.2.3.4".parse().unwrap(), PortType::Tcp, 0x9876);
        assert_eq!(msg.operation(), FirewallOperation::Open);
        assert_eq!(msg.port(), Some((PortType::Tcp, 0x9876)));
        assert_eq!(msg.addr(), Some("1.2.3.4".parse().unwrap()));
        check_ser_de(&msg);

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x02, // operation
                0x00, 0x00, // port_type
                0x98, 0x76, // port
                0x00, 0x01, // addr_type
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, // addr
            ]
        );
    }

    #[test]
    fn test_msg_ack() {
        let msg = FirewallMessage::new_ack();
        assert_eq!(msg.operation(), FirewallOperation::Ack);
        assert_eq!(msg.port(), None);
        assert_eq!(msg.addr(), None);
        check_ser_de(&msg);

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x01, // operation
                0x00, 0x00, // port_type
                0x00, 0x00, // port
                0x00, 0x00, // addr_type
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
            ]
        );
    }

    #[test]
    fn test_msg_nack() {
        let msg = FirewallMessage::new_nack();
        assert_eq!(msg.operation(), FirewallOperation::Nack);
        assert_eq!(msg.port(), None);
        assert_eq!(msg.addr(), None);
        check_ser_de(&msg);

        let bytes = msg.msg_serialize().unwrap();
        assert_eq!(
            bytes,
            [
                0x00, 0x00, // operation
                0x00, 0x00, // port_type
                0x00, 0x00, // port
                0x00, 0x00, // addr_type
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr
            ]
        );
    }
}

// vim: ts=4 sw=4 expandtab
