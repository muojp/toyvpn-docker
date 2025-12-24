use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use crate::ip_pool::IpPool;

/// Unique identifier for a client session
/// Uses client's physical address (IP:port) as the key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    addr: SocketAddr,
}

impl SessionKey {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    #[allow(dead_code)]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

/// Information about an active VPN session
#[derive(Debug, Clone)]
pub struct Session {
    /// Physical address (IP:port) of the client
    pub addr: SocketAddr,
    /// Virtual IP address assigned to this client
    pub virtual_ip: Ipv4Addr,
    /// Last time we received any packet from this client
    pub last_active: Instant,
}

/// Manages all active VPN sessions
pub struct SessionManager {
    /// All active sessions, keyed by client address
    sessions: HashMap<SessionKey, Session>,
    /// Reverse mapping: virtual IP -> session key (for routing)
    routing_table: HashMap<Ipv4Addr, SessionKey>,
    /// IP address pool
    ip_pool: IpPool,
    /// Timeout duration for inactive sessions
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new(base_ip: Ipv4Addr, pool_size: u32, session_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            routing_table: HashMap::new(),
            ip_pool: IpPool::new(base_ip, pool_size),
            session_timeout,
        }
    }

    /// Handle a handshake from a client
    /// Returns the assigned virtual IP and whether this is a new session
    pub fn handle_handshake(&mut self, client_addr: SocketAddr) -> Option<(Ipv4Addr, bool)> {
        let key = SessionKey::new(client_addr);
        let now = Instant::now();

        // Check if session already exists
        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_active = now;
            log::info!(
                "Reconnecting client from {} - Keeping virtual IP: {}",
                client_addr,
                session.virtual_ip
            );
            return Some((session.virtual_ip, false));
        }

        // New session - allocate IP
        let virtual_ip = self.ip_pool.allocate()?;

        let session = Session {
            addr: client_addr,
            virtual_ip,
            last_active: now,
        };

        self.sessions.insert(key.clone(), session);
        self.routing_table.insert(virtual_ip, key);

        log::info!(
            "New client handshake from {} - Assigned virtual IP: {}",
            client_addr,
            virtual_ip
        );

        Some((virtual_ip, true))
    }

    /// Update last active time for a session
    pub fn update_activity(&mut self, client_addr: SocketAddr) {
        let key = SessionKey::new(client_addr);
        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_active = Instant::now();
        }
    }

    /// Update last active time for a session by virtual IP
    #[allow(dead_code)]
    pub fn update_activity_by_vip(&mut self, virtual_ip: Ipv4Addr) {
        if let Some(key) = self.routing_table.get(&virtual_ip).cloned() {
            if let Some(session) = self.sessions.get_mut(&key) {
                session.last_active = Instant::now();
            }
        }
    }

    /// Look up the physical address for a virtual IP (for routing)
    pub fn lookup_route(&self, virtual_ip: Ipv4Addr) -> Option<SocketAddr> {
        self.routing_table
            .get(&virtual_ip)
            .and_then(|key| self.sessions.get(key))
            .map(|session| session.addr)
    }

    /// Get session by client address
    pub fn get_session(&self, client_addr: SocketAddr) -> Option<&Session> {
        let key = SessionKey::new(client_addr);
        self.sessions.get(&key)
    }

    /// Verify that a packet's source IP matches the session's assigned IP
    pub fn verify_source_ip(&self, client_addr: SocketAddr, source_ip: Ipv4Addr) -> bool {
        let key = SessionKey::new(client_addr);
        if let Some(session) = self.sessions.get(&key) {
            session.virtual_ip == source_ip
        } else {
            false
        }
    }

    /// Remove a session explicitly (e.g., on disconnect message)
    pub fn remove_session(&mut self, client_addr: SocketAddr) -> bool {
        let key = SessionKey::new(client_addr);
        if let Some(session) = self.sessions.remove(&key) {
            self.routing_table.remove(&session.virtual_ip);
            self.ip_pool.free(session.virtual_ip);
            log::info!("Client disconnected: {} (freed IP: {})", client_addr, session.virtual_ip);
            true
        } else {
            false
        }
    }

    /// Prune inactive sessions based on timeout
    /// Returns the number of sessions pruned
    pub fn prune_inactive(&mut self) -> usize {
        let now = Instant::now();
        let timeout = self.session_timeout;

        let to_remove: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter_map(|(key, session)| {
                if now.duration_since(session.last_active) > timeout {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        let count = to_remove.len();
        for key in to_remove {
            if let Some(session) = self.sessions.remove(&key) {
                self.routing_table.remove(&session.virtual_ip);
                self.ip_pool.free(session.virtual_ip);
                log::info!(
                    "Pruning inactive session: {} (idle for {:?}, freed IP: {})",
                    key,
                    now.duration_since(session.last_active),
                    session.virtual_ip
                );
            }
        }

        count
    }

    /// Get statistics about sessions and IP pool
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            active_sessions: self.sessions.len(),
            ip_pool_stats: self.ip_pool.stats(),
        }
    }

    /// Get all active sessions (for debugging)
    #[allow(dead_code)]
    pub fn all_sessions(&self) -> impl Iterator<Item = (&SessionKey, &Session)> {
        self.sessions.iter()
    }
}

#[derive(Debug, Clone)]
pub struct SessionStats {
    pub active_sessions: usize,
    pub ip_pool_stats: crate::ip_pool::PoolStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mut mgr = SessionManager::new(
            Ipv4Addr::new(172, 31, 0, 2),
            10,
            Duration::from_secs(60),
        );

        let addr1: SocketAddr = "192.0.2.1:50000".parse().unwrap();

        // New handshake
        let (vip1, is_new) = mgr.handle_handshake(addr1).unwrap();
        assert!(is_new);
        assert_eq!(vip1, Ipv4Addr::new(172, 31, 0, 2));

        // Reconnect same client
        let (vip2, is_new) = mgr.handle_handshake(addr1).unwrap();
        assert!(!is_new);
        assert_eq!(vip2, vip1);

        // Routing lookup
        assert_eq!(mgr.lookup_route(vip1), Some(addr1));

        // Remove session
        assert!(mgr.remove_session(addr1));
        assert_eq!(mgr.lookup_route(vip1), None);
    }

    #[test]
    fn test_ip_reuse_after_disconnect() {
        let mut mgr = SessionManager::new(
            Ipv4Addr::new(172, 31, 0, 2),
            10,
            Duration::from_secs(60),
        );

        let addr1: SocketAddr = "192.0.2.1:50000".parse().unwrap();
        let addr2: SocketAddr = "192.0.2.2:50001".parse().unwrap();

        let (vip1, _) = mgr.handle_handshake(addr1).unwrap();
        mgr.remove_session(addr1);

        // New client should reuse the freed IP
        let (vip2, _) = mgr.handle_handshake(addr2).unwrap();
        assert_eq!(vip1, vip2);
    }
}
