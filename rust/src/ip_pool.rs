use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// IP address pool that efficiently manages allocation and deallocation
/// with automatic reuse of freed addresses
#[derive(Debug)]
pub struct IpPool {
    /// Starting IP address for the pool
    base_ip: u32,
    /// Maximum IP address (inclusive)
    max_ip: u32,
    /// Next IP to try when allocating (optimization)
    next_ip: u32,
    /// Set of currently allocated IPs
    allocated: BTreeSet<u32>,
    /// Pool of freed IPs ready for reuse (sorted for deterministic behavior)
    free_pool: BTreeSet<u32>,
}

impl IpPool {
    /// Create a new IP pool starting from the given address
    /// The pool will allocate IPs from base_ip to base_ip + pool_size - 1
    pub fn new(base_ip: Ipv4Addr, pool_size: u32) -> Self {
        // Convert to host byte order for arithmetic
        let base = u32::from(base_ip);
        Self {
            base_ip: base,
            max_ip: base.saturating_add(pool_size - 1),
            next_ip: base,
            allocated: BTreeSet::new(),
            free_pool: BTreeSet::new(),
        }
    }

    /// Allocate a new IP address, preferring reused IPs from the free pool
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // First, try to reuse a freed IP
        if let Some(&ip) = self.free_pool.iter().next() {
            self.free_pool.remove(&ip);
            self.allocated.insert(ip);
            log::info!("Allocated IP from free pool: {}", Ipv4Addr::from(ip));
            return Some(Ipv4Addr::from(ip));
        }

        // Try to allocate from next_ip onwards
        let mut candidate = self.next_ip;
        let start = candidate;
        let mut first_iteration = true;

        loop {
            if candidate > self.max_ip {
                candidate = self.base_ip;
            }

            if !self.allocated.contains(&candidate) {
                self.allocated.insert(candidate);
                self.next_ip = if candidate < self.max_ip { candidate + 1 } else { self.base_ip };
                log::info!("Allocated new IP: {}", Ipv4Addr::from(candidate));
                return Some(Ipv4Addr::from(candidate));
            }

            candidate = if candidate < self.max_ip { candidate + 1 } else { self.base_ip };

            // Wrap-around detection - exhausted the pool
            if candidate == start && !first_iteration {
                log::warn!("IP pool exhausted! Allocated: {}, Free pool: {}",
                          self.allocated.len(), self.free_pool.len());
                return None;
            }

            first_iteration = false;
        }
    }

    /// Free an IP address and return it to the pool for reuse
    pub fn free(&mut self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);

        if self.allocated.remove(&ip_u32) {
            self.free_pool.insert(ip_u32);
            log::info!("Freed IP: {} (free pool size: {})", ip, self.free_pool.len());
            true
        } else {
            log::warn!("Attempted to free unallocated IP: {}", ip);
            false
        }
    }

    /// Check if an IP is currently allocated
    #[allow(dead_code)]
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        self.allocated.contains(&ip_u32)
    }

    /// Get statistics about the pool
    pub fn stats(&self) -> PoolStats {
        let total = (self.max_ip - self.base_ip + 1) as usize;
        PoolStats {
            total_size: total,
            allocated: self.allocated.len(),
            free_pool_size: self.free_pool.len(),
            available: total - self.allocated.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_size: usize,
    pub allocated: usize,
    pub free_pool_size: usize,
    #[allow(dead_code)]
    pub available: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_allocation() {
        let mut pool = IpPool::new(Ipv4Addr::new(172, 31, 0, 2), 10);

        let ip1 = pool.allocate().unwrap();
        assert_eq!(ip1, Ipv4Addr::new(172, 31, 0, 2));

        let ip2 = pool.allocate().unwrap();
        assert_eq!(ip2, Ipv4Addr::new(172, 31, 0, 3));
    }

    #[test]
    fn test_free_and_reuse() {
        let mut pool = IpPool::new(Ipv4Addr::new(172, 31, 0, 2), 10);

        let ip1 = pool.allocate().unwrap();
        let ip2 = pool.allocate().unwrap();
        let ip3 = pool.allocate().unwrap();

        // Free the first IP
        pool.free(ip1);

        // Next allocation should reuse ip1
        let ip4 = pool.allocate().unwrap();
        assert_eq!(ip4, ip1);

        // Verify others are still different
        assert_ne!(ip4, ip2);
        assert_ne!(ip4, ip3);
    }

    #[test]
    fn test_exhaustion() {
        let mut pool = IpPool::new(Ipv4Addr::new(172, 31, 0, 2), 3);

        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_some());
        assert!(pool.allocate().is_none()); // Exhausted

        // Free one and try again
        pool.free(Ipv4Addr::new(172, 31, 0, 2));
        assert!(pool.allocate().is_some());
    }
}
