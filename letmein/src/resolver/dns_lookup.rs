use crate::resolver::{ResConf, ResMode};
use anyhow::{self as ah, format_err as err};
use dns_lookup::{AddrFamily, AddrInfoHints, getaddrinfo};
use std::net::IpAddr;

/// Resolve a host name into an address.
#[allow(clippy::unused_async)]
pub async fn resolve(host: &str, cfg: &ResConf) -> ah::Result<IpAddr> {
    /* getaddrinfo is blocking.
     * We don't use spawn_blocking here, because it doesn't really matter
     * and we want to avoid spawning a thread.
     * Spawning a thread is disabled by seccomp. */

    let hints = AddrInfoHints {
        address: if cfg.mode == ResMode::Ipv4 {
            AddrFamily::Inet.into()
        } else {
            AddrFamily::Inet6.into()
        },
        ..AddrInfoHints::default()
    };

    let sockets = getaddrinfo(Some(host), None, Some(hints))
        .map_err(|e| err!("Failed to perform DNS lookup: {e:?}"))?;

    for sock in sockets {
        if let Ok(sock) = sock
            && ((cfg.mode == ResMode::Ipv4 && sock.sockaddr.is_ipv4())
                || (cfg.mode == ResMode::Ipv6 && sock.sockaddr.is_ipv6()))
        {
            return Ok(sock.sockaddr.ip());
        }
    }

    Err(err!(
        "DNS lookup of host '{host}' failed. No '{}' record found.",
        if cfg.mode == ResMode::Ipv4 {
            "A"
        } else {
            "AAAA"
        }
    ))
}
