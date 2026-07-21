// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Integration test for auth_rate_limiter module
// Since letmeind is a binary crate, we need to include the module directly

#[path = "../src/auth_rate_limiter.rs"]
mod auth_rate_limiter;

#[cfg(test)]
mod tests {
    use super::auth_rate_limiter::AuthRateLimiter;
    use std::{
        net::{IpAddr, Ipv4Addr},
        thread,
        time::Duration,
    };

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = AuthRateLimiter::new(
            3,                          // max 3 attempts
            Duration::from_secs(60),    // within 60 seconds
            Duration::from_millis(100), // base delay 100ms
            Duration::from_secs(10),    // max delay 10s
        );

        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First attempt should be allowed
        assert!(limiter.check_attempt_allowed(addr).is_ok());
        limiter.record_failed_attempt(addr);

        // After first failure, need to wait for backoff
        thread::sleep(Duration::from_millis(110));
        assert!(limiter.check_attempt_allowed(addr).is_ok());
        limiter.record_failed_attempt(addr);

        // After second failure, need to wait for backoff
        thread::sleep(Duration::from_millis(210));
        assert!(limiter.check_attempt_allowed(addr).is_ok());
        limiter.record_failed_attempt(addr);

        // 4th attempt should be blocked (max attempts reached)
        thread::sleep(Duration::from_millis(410));
        assert!(limiter.check_attempt_allowed(addr).is_err());
    }

    #[test]
    fn test_exponential_backoff() {
        let limiter = AuthRateLimiter::new(
            10, // high max to test backoff
            Duration::from_secs(60),
            Duration::from_millis(50), // 50ms base delay
            Duration::from_secs(10),
        );

        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // First failure
        limiter.record_failed_attempt(addr);
        assert!(limiter.check_attempt_allowed(addr).is_err());
        thread::sleep(Duration::from_millis(60)); // Wait for backoff
        assert!(limiter.check_attempt_allowed(addr).is_ok());

        // Second failure - should have longer backoff
        limiter.record_failed_attempt(addr);
        assert!(limiter.check_attempt_allowed(addr).is_err());
    }

    #[test]
    fn test_success_clears_state() {
        let limiter = AuthRateLimiter::new(
            3,
            Duration::from_secs(60),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );

        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        // Record failures
        limiter.record_failed_attempt(addr);
        limiter.record_failed_attempt(addr);
        assert_eq!(limiter.get_failed_attempts(addr), 2);

        // Success should clear
        limiter.record_success(addr);
        assert_eq!(limiter.get_failed_attempts(addr), 0);
        assert!(limiter.check_attempt_allowed(addr).is_ok());
    }

    #[test]
    fn test_ipv6_prefix_masking() {
        let limiter = AuthRateLimiter::new(
            2,
            Duration::from_secs(60),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );

        // Two IPv6 addresses in the same /56 subnet
        let addr1 = "2001:db8:1234:5600::1".parse::<IpAddr>().unwrap();
        let addr2 = "2001:db8:1234:5600::2".parse::<IpAddr>().unwrap();

        // Failures from addr1 should affect addr2
        limiter.record_failed_attempt(addr1);
        limiter.record_failed_attempt(addr1);

        // addr2 should also be rate limited
        assert!(limiter.check_attempt_allowed(addr2).is_err());
    }

    #[test]
    fn test_time_window_expiry() {
        let limiter = AuthRateLimiter::new(
            2,
            Duration::from_millis(100), // Short window for testing
            Duration::from_millis(50),
            Duration::from_secs(10),
        );

        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));

        // Max out attempts
        limiter.record_failed_attempt(addr);
        limiter.record_failed_attempt(addr);
        assert!(limiter.check_attempt_allowed(addr).is_err());

        // Wait for time window to expire
        thread::sleep(Duration::from_millis(150));

        // Should be allowed again
        assert!(limiter.check_attempt_allowed(addr).is_ok());
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = AuthRateLimiter::new(
            2,
            Duration::from_secs(60),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );

        let addr1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        let addr2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Max out addr1
        limiter.record_failed_attempt(addr1);
        limiter.record_failed_attempt(addr1);
        assert!(limiter.check_attempt_allowed(addr1).is_err());

        // addr2 should still be allowed
        assert!(limiter.check_attempt_allowed(addr2).is_ok());
    }

    #[test]
    fn test_max_delay_cap() {
        let limiter = AuthRateLimiter::new(
            20, // high max to test many failures
            Duration::from_secs(60),
            Duration::from_secs(1), // 1 second base delay
            Duration::from_secs(5), // 5 second max delay
        );

        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6));

        // Record many failures to trigger exponential backoff
        for _ in 0..10 {
            limiter.record_failed_attempt(addr);
        }

        // Check that delay is capped
        if let Err(wait_time) = limiter.check_attempt_allowed(addr) {
            // Should be capped at max_delay (5 seconds)
            assert!(wait_time <= Duration::from_secs(5));
        } else {
            panic!("Expected rate limit error");
        }
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let limiter = Arc::new(AuthRateLimiter::new(
            5,
            Duration::from_secs(60),
            Duration::from_millis(100),
            Duration::from_secs(10),
        ));

        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7));

        // Spawn multiple threads accessing the same limiter
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                thread::spawn(move || {
                    limiter.record_failed_attempt(addr);
                    limiter.check_attempt_allowed(addr)
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            let _ = handle.join();
        }

        // Verify state is consistent
        assert_eq!(limiter.get_failed_attempts(addr), 3);
    }
}
