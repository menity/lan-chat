use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, sync::watch, time::Instant};
use uuid::Uuid;

use crate::protocol::{DiscoveryBeacon, PROTOCOL_MAX, PROTOCOL_MIN};
use crate::security::{is_valid_fingerprint, sanitize_group_name};

pub const DISCOVERY_PORT: u16 = 37_373;
pub const DISCOVERY_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 73);
const MAX_BEACON_SIZE: usize = 2048;

#[derive(Debug, Clone)]
pub struct DiscoveredGateway {
    pub gateway_id: Uuid,
    pub gateway_name: String,
    pub endpoint: SocketAddr,
    pub server_fingerprint: String,
    pub protocol_min: u16,
    pub protocol_max: u16,
}

pub async fn advertise(beacon: DiscoveryBeacon, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("failed to bind discovery sender")?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(true)?;
    let destination = SocketAddrV4::new(DISCOVERY_GROUP, DISCOVERY_PORT);
    let payload = serde_json::to_vec(&beacon)?;
    let mut interval = tokio::time::interval(Duration::from_millis(1500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                socket.send_to(&payload, destination).await
                    .context("failed to send discovery beacon")?;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    Ok(())
}

pub async fn discover(duration: Duration) -> Result<Vec<DiscoveredGateway>> {
    let socket = bind_discovery_receiver()?;
    socket
        .join_multicast_v4(DISCOVERY_GROUP, Ipv4Addr::UNSPECIFIED)
        .context("failed to join the LAN discovery multicast group")?;

    let deadline = Instant::now() + duration;
    let mut buffer = vec![0u8; MAX_BEACON_SIZE];
    let mut found: HashMap<(Uuid, IpAddr, u16), DiscoveredGateway> = HashMap::new();

    loop {
        let received = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await;
        let Ok(Ok((length, source))) = received else {
            break;
        };
        if length == 0 || length == buffer.len() {
            continue;
        }

        let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(&buffer[..length]) else {
            continue;
        };
        if beacon.app != "lan-chat-gateway"
            || beacon.port == 0
            || beacon.protocol_min > PROTOCOL_MAX
            || beacon.protocol_max < PROTOCOL_MIN
            || !is_valid_fingerprint(&beacon.server_fingerprint)
        {
            continue;
        }
        let Ok(gateway_name) = sanitize_group_name(&beacon.gateway_name) else {
            continue;
        };

        let endpoint = SocketAddr::new(source.ip(), beacon.port);
        found.insert(
            (beacon.gateway_id, source.ip(), beacon.port),
            DiscoveredGateway {
                gateway_id: beacon.gateway_id,
                gateway_name,
                endpoint,
                server_fingerprint: beacon.server_fingerprint,
                protocol_min: beacon.protocol_min,
                protocol_max: beacon.protocol_max,
            },
        );
    }

    let mut gateways: Vec<_> = found.into_values().collect();
    gateways.sort_by(|left, right| left.gateway_name.cmp(&right.gateway_name));
    Ok(gateways)
}

fn bind_discovery_receiver() -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create discovery receiver")?;
    socket
        .set_reuse_address(true)
        .context("failed to enable shared multicast discovery")?;
    socket
        .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT).into())
        .context("failed to bind discovery receiver")?;
    socket.set_nonblocking(true)?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket).context("failed to attach discovery receiver to the runtime")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn multiple_local_tuis_can_share_the_discovery_port() {
        let first = bind_discovery_receiver().unwrap();
        let second = bind_discovery_receiver().unwrap();
        drop((first, second));
    }
}
