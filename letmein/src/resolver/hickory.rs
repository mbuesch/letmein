use crate::resolver::{ResConf, ResMode};
use anyhow::{self as ah, format_err as err};
use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig},
    lookup::Lookup,
    net::runtime::TokioRuntimeProvider,
    proto::rr::{RData, RecordType},
};
use std::net::IpAddr;

/// Determine the DNS record type from the address resolution mode.
fn get_record_type(mode: ResMode) -> (RecordType, &'static str, &'static str) {
    match mode {
        ResMode::Ipv6 => (RecordType::AAAA, "AAAA", "IPv6"),
        ResMode::Ipv4 => (RecordType::A, "A", "IPv4"),
    }
}

/// Return the first address that matches the requested address resolution mode.
fn get_first_result(lookup: &Lookup, host: &str, mode: ResMode) -> ah::Result<IpAddr> {
    for answer in lookup.answers() {
        match (mode, &answer.data) {
            (ResMode::Ipv6, RData::AAAA(addr)) => return Ok(addr.0.into()),
            (ResMode::Ipv4, RData::A(addr)) => return Ok(addr.0.into()),
            _ => (),
        }
    }
    let (_, record_type_str, _) = get_record_type(mode);
    Err(err!(
        "No IP address found for host '{host}'. No '{record_type_str}' record found."
    ))
}

/// Resolve a host name into an address.
pub async fn resolve(host: &str, cfg: &ResConf) -> ah::Result<IpAddr> {
    let (record_type, record_type_str, addr_type_str) = get_record_type(cfg.mode);

    macro_rules! lookup_and_return {
        ($conf:expr) => {
            if let Ok(resolver) =
                TokioResolver::builder_with_config($conf, TokioRuntimeProvider::default()).build()
                && let Ok(lookup) = resolver.lookup(host, record_type).await
            {
                return get_first_result(&lookup, host, cfg.mode);
            }
        };
    }

    if cfg.srv.system {
        if let Ok(builder) = TokioResolver::builder_tokio()
            && let Ok(resolver) = builder.build()
            && let Ok(lookup) = resolver.lookup(host, record_type).await
        {
            return get_first_result(&lookup, host, cfg.mode);
        }

        #[cfg(not(target_os = "android"))]
        let print_warning = true;
        #[cfg(target_os = "android")]
        let print_warning = false;

        if print_warning && !cfg.suppress_warnings {
            #[cfg(target_os = "windows")]
            let os_info = "Is your DNS resolver configured correctly in network settings?";

            #[cfg(not(target_os = "windows"))]
            let os_info = "Is /etc/resolv.conf present and configured correctly?";

            eprintln!(
                "Warning: Could not resolve {addr_type_str} address with the system DNS resolver. \
                 {os_info} \
                 Falling back to other DNS servers."
            );
        }
    }

    if cfg.crypt.tls {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::tls(&QUAD9));
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::tls(&GOOGLE));
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::tls(&CLOUDFLARE));
        }
    }

    if cfg.crypt.https {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::https(&QUAD9));
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::https(&GOOGLE));
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::https(&CLOUDFLARE));
        }
    }

    if cfg.crypt.unencrypted {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::udp_and_tcp(&QUAD9));
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::udp_and_tcp(&GOOGLE));
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::udp_and_tcp(&CLOUDFLARE));
        }
    }

    Err(err!(
        "DNS lookup of host '{host}' failed. No '{record_type_str}' record found."
    ))
}
