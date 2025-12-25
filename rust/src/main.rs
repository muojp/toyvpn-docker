mod ip_pool;
mod protocol;
mod session;
mod tun;

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;

use protocol::{build_client_parameters, IpPacket};
use session::SessionManager;
use tun::TunDevice;

const DISCONNECT_MSG: u8 = 0xFF;

struct ServerConfig {
    tun_name: String,
    port: u16,
    secret: String,
    base_ip: Ipv4Addr,
    pool_size: u32,
    session_timeout: Duration,
    prune_interval: Duration,
    parameters: Vec<String>,
}

impl ServerConfig {
    fn from_args(args: Vec<String>) -> Result<Self> {
        if args.len() < 5 {
            anyhow::bail!(
                "Usage: {} <tunN> <port> <secret> options...",
                args.get(0).unwrap_or(&"toyvpn-server".to_string())
            );
        }

        let tun_name = args[1].clone();
        let port = args[2]
            .parse()
            .context("Invalid port number")?;
        let secret = args[3].clone();

        // Parse base IP from parameters
        let mut base_ip = Ipv4Addr::new(172, 31, 0, 2);
        for arg in args.iter().skip(4) {
            if let Some(stripped) = arg.strip_prefix("a,") {
                if let Some(comma_pos) = stripped.find(',') {
                    let ip_str = &stripped[..comma_pos];
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        base_ip = ip;
                        log::info!("Starting IP allocation from: {}", ip);
                        break;
                    }
                }
            }
        }

        Ok(Self {
            tun_name,
            port,
            secret,
            base_ip,
            pool_size: 250, // 172.31.0.2 to 172.31.0.251
            session_timeout: Duration::from_secs(300), // 5 minutes
            prune_interval: Duration::from_secs(10),
            parameters: args,
        })
    }
}

async fn handle_tun_to_clients(
    tun: Arc<TunDevice>,
    socket: Arc<UdpSocket>,
    sessions: Arc<Mutex<SessionManager>>,
) -> Result<()> {
    let mut buffer = vec![0u8; 32768];

    loop {
        let len = tun.read_packet(&mut buffer).await?;

        if let Some(ip) = IpPacket::parse(&buffer[..len]) {
            let sessions = sessions.lock().await;
            if let Some(client_addr) = sessions.lookup_route(ip.dst) {
                log::info!(
                    "[TUN->Client] Routing packet: {} -> {} ({} bytes)",
                    ip.src,
                    ip.dst,
                    len
                );

                if let Err(e) = socket.send_to(&buffer[..len], client_addr).await {
                    log::error!("Failed to send to client {}: {}", client_addr, e);
                }
            } else {
                log::debug!(
                    "[TUN->Client] No route found for destination: {} (dropped)",
                    ip.dst
                );
            }
        }
    }
}

async fn handle_clients_to_tun(
    tun: Arc<TunDevice>,
    socket: Arc<UdpSocket>,
    sessions: Arc<Mutex<SessionManager>>,
    config: Arc<ServerConfig>,
) -> Result<()> {
    let mut buffer = vec![0u8; 32768];

    loop {
        let (len, client_addr) = socket.recv_from(&mut buffer).await?;

        if len == 0 {
            continue;
        }

        // Control message (starts with 0x00)
        if buffer[0] == 0 {
            if len > 1 && buffer[1] == DISCONNECT_MSG {
                // Disconnect message
                let mut sessions = sessions.lock().await;
                sessions.remove_session(client_addr);
                continue;
            }

            // Handshake message
            let received_secret = std::str::from_utf8(&buffer[1..len])
                .unwrap_or("")
                .trim_end_matches('\0')
                .trim();

            if received_secret.is_empty() {
                // Keep-alive request (empty secret)
                let mut sessions = sessions.lock().await;
                if let Some(session) = sessions.get_session(client_addr) {
                    let virtual_ip = session.virtual_ip;

                    // Send ACK with current parameters
                    let params = build_client_parameters(virtual_ip, &config.parameters[4..]);

                    if let Err(e) = socket.send_to(&params, client_addr).await {
                        log::error!("Failed to send keep-alive ACK to {}: {}", client_addr, e);
                    } else {
                        log::debug!("Keep-alive ACK sent to {} (VIP: {})", client_addr, virtual_ip);
                    }

                    // Update activity timestamp
                    sessions.update_activity(client_addr);
                } else {
                    log::debug!("Keep-alive from unknown client {} (ignored)", client_addr);
                }
            } else if received_secret == config.secret {
                let mut sessions = sessions.lock().await;
                if let Some((virtual_ip, _is_new)) = sessions.handle_handshake(client_addr) {
                    // Build client-specific parameters
                    let params = build_client_parameters(virtual_ip, &config.parameters[4..]);

                    // Send parameters 3 times for reliability
                    for _ in 0..3 {
                        if let Err(e) = socket.send_to(&params, client_addr).await {
                            log::error!("Failed to send parameters to {}: {}", client_addr, e);
                            break;
                        }
                    }
                    // Logging is done in handle_handshake()
                } else {
                    log::error!("Failed to allocate IP for client {}", client_addr.ip());
                }
            } else {
                log::warn!(
                    "Handshake with invalid secret from {} (expected: '{}', got: '{}')",
                    client_addr,
                    config.secret,
                    received_secret
                );
            }
            continue;
        }

        // Data packet
        let mut sessions = sessions.lock().await;
        if sessions.get_session(client_addr).is_some() {
            if let Some(ip) = IpPacket::parse(&buffer[..len]) {
                // Verify source IP matches assigned virtual IP
                if !sessions.verify_source_ip(client_addr, ip.src) {
                    if let Some(session) = sessions.get_session(client_addr) {
                        log::warn!(
                            "[Client->TUN] WARNING: Source IP mismatch! Expected {}, got {} (dropped)",
                            session.virtual_ip,
                            ip.src
                        );
                    }
                    continue;
                }

                sessions.update_activity(client_addr);

                log::debug!(
                    "[Client->TUN] Forwarding packet: {} -> {} ({} bytes)",
                    ip.src,
                    ip.dst,
                    len
                );

                drop(sessions); // Release lock before writing

                if let Err(e) = tun.write_packet(&buffer[..len]).await {
                    log::error!("Failed to write to TUN: {}", e);
                }
            }
        } else {
            log::debug!("[Client->TUN] Packet from unknown session {} (dropped)", client_addr);
        }
    }
}

async fn session_pruner(
    sessions: Arc<Mutex<SessionManager>>,
    interval: Duration,
) -> Result<()> {
    let mut ticker = time::interval(interval);

    loop {
        ticker.tick().await;

        let mut sessions = sessions.lock().await;
        let pruned = sessions.prune_inactive();

        if pruned > 0 {
            log::info!("Pruned {} inactive session(s)", pruned);
        }

        // Log statistics periodically
        let stats = sessions.stats();
        log::info!(
            "Sessions: {} active, IP pool: {}/{} allocated, {} in free pool",
            stats.active_sessions,
            stats.ip_pool_stats.allocated,
            stats.ip_pool_stats.total_size,
            stats.ip_pool_stats.free_pool_size
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let config = Arc::new(ServerConfig::from_args(args)?);

    log::info!("Starting ToyVPN Server");
    log::info!("  TUN device: {}", config.tun_name);
    log::info!("  UDP port: {}", config.port);
    log::info!("  Base IP: {}", config.base_ip);
    log::info!("  Pool size: {}", config.pool_size);
    log::info!("  Session timeout: {:?}", config.session_timeout);

    // Create TUN device
    let tun = Arc::new(TunDevice::new(&config.tun_name)?);
    log::info!("TUN device '{}' created", tun.name());

    // Create UDP socket
    let bind_addr: SocketAddr = format!("[::]:{}", config.port).parse()?;
    let socket = UdpSocket::bind(bind_addr)
        .await
        .context("Failed to bind UDP socket")?;
    let socket = Arc::new(socket);
    log::info!("UDP socket bound to {}", bind_addr);

    // Create session manager
    let sessions = Arc::new(Mutex::new(SessionManager::new(
        config.base_ip,
        config.pool_size,
        config.session_timeout,
    )));

    // Spawn tasks
    let tun_clone = tun.clone();
    let socket_clone = socket.clone();
    let sessions_clone = sessions.clone();
    let handle1 = tokio::spawn(async move {
        if let Err(e) = handle_tun_to_clients(tun_clone, socket_clone, sessions_clone).await {
            log::error!("TUN->Clients handler error: {}", e);
        }
    });

    let tun_clone = tun.clone();
    let socket_clone = socket.clone();
    let sessions_clone = sessions.clone();
    let config_clone = config.clone();
    let handle2 = tokio::spawn(async move {
        if let Err(e) = handle_clients_to_tun(tun_clone, socket_clone, sessions_clone, config_clone).await {
            log::error!("Clients->TUN handler error: {}", e);
        }
    });

    let sessions_clone = sessions.clone();
    let handle3 = tokio::spawn(async move {
        if let Err(e) = session_pruner(sessions_clone, config.prune_interval).await {
            log::error!("Session pruner error: {}", e);
        }
    });

    log::info!("Server running. Press Ctrl+C to stop.");

    // Wait for any task to complete (or fail)
    tokio::select! {
        _ = handle1 => log::error!("TUN->Clients handler stopped"),
        _ = handle2 => log::error!("Clients->TUN handler stopped"),
        _ = handle3 => log::error!("Session pruner stopped"),
        _ = tokio::signal::ctrl_c() => log::info!("Received Ctrl+C, shutting down"),
    }

    Ok(())
}
