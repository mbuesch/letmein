// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

/// Entry tracking authentication attempts for a single IP address.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Number of failed authentication attempts.
    failed_attempts: u32,
    /// Timestamp of the last failed attempt.
    last_attempt: Instant,
    /// Timestamp when the IP can attempt again (for exponential backoff).
    next_allowed: Instant,
}

/// Rate limiter for authentication attempts based on client IP addresses.
/// This prevents brute-force attacks by implementing:
/// - Maximum failed attempts within a time window
/// - Exponential backoff after repeated failures
/// - Automatic cleanup of old entries
pub struct AuthRateLimiter {
    map: Mutex<HashMap<IpAddr, RateLimitEntry>>,
    max_attempts: u32,
    time_window: Duration,
    base_delay: Duration,
    max_delay: Duration,
}

impl AuthRateLimiter {
    /// Create a new `AuthRateLimiter` with the specified parameters.
    ///
    /// # Arguments
    /// * `max_attempts` - Maximum failed attempts allowed within the time window
    /// * `time_window` - Time window for counting failed attempts (e.g., 60 seconds)
    /// * `base_delay` - Initial delay after first failure (e.g., 1 second)
    /// * `max_delay` - Maximum delay after repeated failures (e.g., 300 seconds)
    #[must_use]
    pub fn new(
        max_attempts: u32,
        time_window: Duration,
        base_delay: Duration,
        max_delay: Duration,
    ) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max_attempts,
            time_window,
            base_delay,
            max_delay,
        }
    }

    /// Normalize an IP address to a rate-limiting key.
    ///
    /// IPv4 addresses are used as-is.
    /// IPv6 addresses are masked to a /56 prefix to prevent evasion by rotating the interface identifier.
    fn rate_limit_key(addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V4(_) => addr,
            IpAddr::V6(v6) => {
                IpAddr::V6(v6 & Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFF00, 0, 0, 0, 0))
            }
        }
    }

    /// Check if an authentication attempt is allowed for the given IP address.
    ///
    /// Returns `Ok(())` if the attempt is allowed, or `Err(Duration)` with the
    /// remaining wait time if the attempt should be blocked.
    pub fn check_attempt_allowed(&self, addr: IpAddr) -> Result<(), Duration> {
        let key = Self::rate_limit_key(addr);
        let now = Instant::now();
        let mut map = self.map.lock().expect("Mutex poisoned");

        // Clean up old entries (older than time_window)
        map.retain(|_, entry| now.duration_since(entry.last_attempt) < self.time_window * 2);

        if let Some(entry) = map.get(&key) {
            // Check if we're still in the backoff period
            if now < entry.next_allowed {
                let wait_time = entry.next_allowed.duration_since(now);
                return Err(wait_time);
            }

            // Check if we're within the time window and have exceeded max attempts
            if now.duration_since(entry.last_attempt) < self.time_window
                && entry.failed_attempts >= self.max_attempts
            {
                // Still within time window and max attempts exceeded
                let wait_time = self
                    .time_window
                    .saturating_sub(now.duration_since(entry.last_attempt));
                return Err(wait_time);
            }
        }
        Ok(())
    }

    /// Record a failed authentication attempt for the given IP address.
    ///
    /// This updates the failure count and calculates the next allowed attempt time
    /// using exponential backoff.
    pub fn record_failed_attempt(&self, addr: IpAddr) {
        let key = Self::rate_limit_key(addr);
        let now = Instant::now();
        let mut map = self.map.lock().expect("Mutex poisoned");

        let entry = map.entry(key).or_insert_with(|| RateLimitEntry {
            failed_attempts: 0,
            last_attempt: now,
            next_allowed: now,
        });

        // Reset counter if outside the time window
        if now.duration_since(entry.last_attempt) >= self.time_window {
            entry.failed_attempts = 1;
        } else {
            entry.failed_attempts = entry.failed_attempts.saturating_add(1);
        }
        entry.last_attempt = now;

        // Calculate exponential backoff: base_delay * 2^(attempts-1)
        // Capped at max_delay
        let delay = if entry.failed_attempts > 0 {
            let exponent = (entry.failed_attempts - 1).min(10); // Cap exponent to prevent overflow
            let multiplier = 1_u32 << exponent; // 2^exponent
            let calculated_delay = self.base_delay.saturating_mul(multiplier);
            calculated_delay.min(self.max_delay)
        } else {
            self.base_delay
        };
        entry.next_allowed = now + delay;
    }

    /// Record a successful authentication for the given IP address.
    ///
    /// This clears any rate limiting state for the IP.
    pub fn record_success(&self, addr: IpAddr) {
        let key = Self::rate_limit_key(addr);
        let mut map = self.map.lock().expect("Mutex poisoned");
        map.remove(&key);
    }

    /// Get the current number of failed attempts for an IP address.
    ///
    /// Returns 0 if the IP has no recorded failures or if the time window has expired.
    #[must_use]
    #[allow(dead_code)] // Used in tests
    pub fn get_failed_attempts(&self, addr: IpAddr) -> u32 {
        let key = Self::rate_limit_key(addr);
        let now = Instant::now();
        let map = self.map.lock().expect("Mutex poisoned");

        if let Some(entry) = map.get(&key)
            && now.duration_since(entry.last_attempt) < self.time_window
        {
            return entry.failed_attempts;
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, thread, time::Duration};

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
}
