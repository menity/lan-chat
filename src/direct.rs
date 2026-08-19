use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{RwLock, Semaphore, mpsc, watch},
};
use uuid::Uuid;

use crate::{
    client::ClientEvent,
    crypto::{
        NoiseKeypair, client_handshake, generate_keypair, public_key_fingerprint,
        server_handshake_with_remote, split_secure_stream,
    },
    protocol::{DirectRecord, Peer, PrivateConversationStatus, ServerMessage},
    security::sanitize_chat_text,
};

const DIRECT_QUEUE_CAPACITY: usize = 64;
const MAX_DIRECT_CONNECTIONS: usize = 32;
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DIRECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const DIRECT_HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DIRECT_MESSAGES_PER_SECOND: u32 = 32;

pub(crate) struct DirectSetup {
    listener: TcpListener,
    keypair: Arc<NoiseKeypair>,
    pub port: u16,
    pub fingerprint: String,
}

impl DirectSetup {
    pub async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .context("failed to open the peer-to-peer private chat listener")?;
        let port = listener.local_addr()?.port();
        let keypair = Arc::new(generate_keypair()?);
        let fingerprint = public_key_fingerprint(&keypair.public);
        Ok(Self {
            listener,
            keypair,
            port,
            fingerprint,
        })
    }
}

pub(crate) struct DirectManager {
    commands: mpsc::Sender<DirectCommand>,
    members: Arc<RwLock<HashMap<Uuid, Peer>>>,
    shutdown: watch::Sender<bool>,
}

impl DirectManager {
    pub fn start(
        setup: DirectSetup,
        group_id: Uuid,
        local_peer: Peer,
        members: Vec<Peer>,
        events: mpsc::Sender<ClientEvent>,
    ) -> Self {
        let members = Arc::new(RwLock::new(
            members
                .into_iter()
                .map(|peer| (peer.session_id, peer))
                .collect(),
        ));
        let (commands_tx, commands_rx) = mpsc::channel(DIRECT_QUEUE_CAPACITY);
        let (links_tx, links_rx) = mpsc::channel(DIRECT_QUEUE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        tokio::spawn(accept_direct_connections(
            setup.listener,
            Arc::clone(&setup.keypair),
            group_id,
            local_peer.session_id,
            Arc::clone(&members),
            links_tx.clone(),
            shutdown_rx,
        ));
        tokio::spawn(run_direct_hub(
            commands_rx,
            links_rx,
            links_tx,
            setup.keypair,
            group_id,
            local_peer,
            Arc::clone(&members),
            events,
        ));

        Self {
            commands: commands_tx,
            members,
            shutdown: shutdown_tx,
        }
    }

    pub async fn send(&self, peer_session_id: Uuid, message_id: Uuid, text: String) -> Result<()> {
        self.commands
            .send(DirectCommand::Send {
                peer_session_id,
                message_id,
                text,
            })
            .await
            .context("private chat manager stopped")
    }

    pub async fn upsert_member(&self, peer: Peer) {
        self.members.write().await.insert(peer.session_id, peer);
    }

    pub async fn remove_member(&self, peer_session_id: Uuid) {
        self.members.write().await.remove(&peer_session_id);
        let _ = self
            .commands
            .send(DirectCommand::PeerLeft(peer_session_id))
            .await;
    }
}

impl Drop for DirectManager {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

enum DirectCommand {
    Send {
        peer_session_id: Uuid,
        message_id: Uuid,
        text: String,
    },
    PeerLeft(Uuid),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DirectWireMessage {
    Hello {
        group_id: Uuid,
        sender_session_id: Uuid,
        recipient_session_id: Uuid,
    },
    Chat {
        message_id: Uuid,
        sent_at_ms: u64,
        text: String,
    },
}

enum LinkEvent {
    Connected {
        link_id: Uuid,
        peer: Peer,
        sender: mpsc::Sender<DirectWireMessage>,
    },
    Message {
        link_id: Uuid,
        peer_session_id: Uuid,
        message_id: Uuid,
        sent_at_ms: u64,
        text: String,
    },
    Disconnected {
        link_id: Uuid,
        peer_session_id: Uuid,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkRole {
    Initiator,
    Recipient,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConversationState {
    New,
    AwaitingReply,
    Active,
}

struct DirectLink {
    link_id: Uuid,
    peer: Peer,
    sender: mpsc::Sender<DirectWireMessage>,
    role: LinkRole,
    state: ConversationState,
}

#[allow(clippy::too_many_arguments)]
async fn run_direct_hub(
    mut commands: mpsc::Receiver<DirectCommand>,
    mut link_events: mpsc::Receiver<LinkEvent>,
    link_events_tx: mpsc::Sender<LinkEvent>,
    keypair: Arc<NoiseKeypair>,
    group_id: Uuid,
    local_peer: Peer,
    members: Arc<RwLock<HashMap<Uuid, Peer>>>,
    events: mpsc::Sender<ClientEvent>,
) {
    let mut links: HashMap<Uuid, DirectLink> = HashMap::new();
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break; };
                match command {
                    DirectCommand::Send { peer_session_id, message_id, text } => {
                        let text = match sanitize_chat_text(&text) {
                            Ok(text) => text,
                            Err(error) => {
                                send_direct_error(&events, "invalid_private_message", &error.to_string()).await;
                                continue;
                            }
                        };
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            links.entry(peer_session_id)
                        {
                            let peer = members.read().await.get(&peer_session_id).cloned();
                            let Some(peer) = peer else {
                                send_direct_error(&events, "private_peer_offline", "that member is no longer online").await;
                                continue;
                            };
                            match connect_direct_link(
                                Arc::clone(&keypair),
                                group_id,
                                &local_peer,
                                peer,
                                link_events_tx.clone(),
                            ).await {
                                Ok(link) => {
                                    entry.insert(link);
                                }
                                Err(error) => {
                                    send_direct_error(
                                        &events,
                                        "private_connect_failed",
                                        &format!("could not establish a direct encrypted connection: {error:#}"),
                                    ).await;
                                    continue;
                                }
                            }
                        }
                        let Some(link) = links.get_mut(&peer_session_id) else { continue; };
                        if link.role == LinkRole::Initiator
                            && link.state == ConversationState::AwaitingReply
                        {
                            send_direct_error(
                                &events,
                                "private_waiting_for_reply",
                                "wait for the other member to reply before sending another private message",
                            ).await;
                            continue;
                        }
                        let status = match (link.role, link.state) {
                            (LinkRole::Initiator, ConversationState::New) => {
                                link.state = ConversationState::AwaitingReply;
                                PrivateConversationStatus::AwaitingReply {
                                    initiator_session_id: local_peer.session_id,
                                }
                            }
                            (LinkRole::Recipient, ConversationState::AwaitingReply) => {
                                link.state = ConversationState::Active;
                                PrivateConversationStatus::Active
                            }
                            (_, ConversationState::Active) => PrivateConversationStatus::Active,
                            _ => {
                                send_direct_error(
                                    &events,
                                    "private_not_ready",
                                    "the private connection is not ready",
                                ).await;
                                continue;
                            }
                        };
                        let sent_at_ms = now_ms();
                        if link.sender.send(DirectWireMessage::Chat {
                            message_id,
                            sent_at_ms,
                            text: text.clone(),
                        }).await.is_err() {
                            links.remove(&peer_session_id);
                            send_direct_error(&events, "private_connection_closed", "the direct connection closed").await;
                            continue;
                        }
                        emit_private_message(
                            &events,
                            DirectRecord {
                                message_id,
                                sender: local_peer.clone(),
                                recipient_session_id: peer_session_id,
                                sent_at_ms,
                                text,
                            },
                            status,
                        ).await;
                    }
                    DirectCommand::PeerLeft(peer_session_id) => {
                        if links.remove(&peer_session_id).is_some() {
                            emit_private_closed(&events, peer_session_id).await;
                        }
                    }
                }
            }
            link_event = link_events.recv() => {
                let Some(link_event) = link_event else { break; };
                match link_event {
                    LinkEvent::Connected { link_id, peer, sender } => {
                        links.entry(peer.session_id).or_insert(DirectLink {
                            link_id,
                            peer,
                            sender,
                            role: LinkRole::Recipient,
                            state: ConversationState::New,
                        });
                    }
                    LinkEvent::Message {
                        link_id,
                        peer_session_id,
                        message_id,
                        sent_at_ms,
                        text,
                    } => {
                        let Some(link) = links.get_mut(&peer_session_id) else { continue; };
                        if link.link_id != link_id {
                            continue;
                        }
                        let status = match (link.role, link.state) {
                            (LinkRole::Recipient, ConversationState::New) => {
                                link.state = ConversationState::AwaitingReply;
                                PrivateConversationStatus::AwaitingReply {
                                    initiator_session_id: peer_session_id,
                                }
                            }
                            (LinkRole::Recipient, ConversationState::AwaitingReply) => {
                                // A modified initiator is not allowed to push a second message.
                                continue;
                            }
                            (LinkRole::Initiator, ConversationState::AwaitingReply) => {
                                link.state = ConversationState::Active;
                                PrivateConversationStatus::Active
                            }
                            (_, ConversationState::Active) => PrivateConversationStatus::Active,
                            _ => continue,
                        };
                        let text = match sanitize_chat_text(&text) {
                            Ok(text) => text,
                            Err(_) => continue,
                        };
                        emit_private_message(
                            &events,
                            DirectRecord {
                                message_id,
                                sender: link.peer.clone(),
                                recipient_session_id: local_peer.session_id,
                                sent_at_ms,
                                text,
                            },
                            status,
                        ).await;
                    }
                    LinkEvent::Disconnected { link_id, peer_session_id } => {
                        if links.get(&peer_session_id).is_some_and(|link| link.link_id == link_id) {
                            links.remove(&peer_session_id);
                            emit_private_closed(&events, peer_session_id).await;
                        }
                    }
                }
            }
        }
    }
}

async fn accept_direct_connections(
    listener: TcpListener,
    keypair: Arc<NoiseKeypair>,
    group_id: Uuid,
    local_session_id: Uuid,
    members: Arc<RwLock<HashMap<Uuid, Peer>>>,
    events: mpsc::Sender<LinkEvent>,
    mut shutdown: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(MAX_DIRECT_CONNECTIONS));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break; };
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let keypair = Arc::clone(&keypair);
                let members = Arc::clone(&members);
                let events = events.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = accept_direct_link(
                        stream,
                        keypair,
                        group_id,
                        local_session_id,
                        members,
                        events,
                    ).await;
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn accept_direct_link(
    mut stream: TcpStream,
    keypair: Arc<NoiseKeypair>,
    expected_group_id: Uuid,
    local_session_id: Uuid,
    members: Arc<RwLock<HashMap<Uuid, Peer>>>,
    events: mpsc::Sender<LinkEvent>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let (transport, remote_fingerprint) = tokio::time::timeout(
        DIRECT_HANDSHAKE_TIMEOUT,
        server_handshake_with_remote(&mut stream, &keypair),
    )
    .await
    .context("direct Noise handshake timed out")??;
    let (mut reader, writer) = split_secure_stream(stream, transport);
    let hello = tokio::time::timeout(
        DIRECT_HELLO_TIMEOUT,
        reader.read_json::<DirectWireMessage>(),
    )
    .await
    .context("direct hello timed out")??;
    let DirectWireMessage::Hello {
        group_id,
        sender_session_id,
        recipient_session_id,
    } = hello
    else {
        bail!("direct peer did not send a hello first");
    };
    if group_id != expected_group_id || recipient_session_id != local_session_id {
        bail!("direct hello targeted a different group or recipient");
    }
    let peer = members
        .read()
        .await
        .get(&sender_session_id)
        .cloned()
        .context("direct peer is not an online group member")?;
    let advertised = peer
        .direct
        .as_ref()
        .context("group member did not advertise direct chat capability")?;
    if !advertised
        .fingerprint
        .eq_ignore_ascii_case(&remote_fingerprint)
    {
        bail!("direct peer Noise fingerprint did not match the gateway member record");
    }
    spawn_link_io(peer, reader, writer, events, LinkRole::Recipient).await
}

async fn connect_direct_link(
    keypair: Arc<NoiseKeypair>,
    group_id: Uuid,
    local_peer: &Peer,
    peer: Peer,
    events: mpsc::Sender<LinkEvent>,
) -> Result<DirectLink> {
    let advertised = peer
        .direct
        .clone()
        .context("that member does not support peer-to-peer private chat")?;
    let mut stream = tokio::time::timeout(
        DIRECT_CONNECT_TIMEOUT,
        TcpStream::connect(advertised.endpoint),
    )
    .await
    .context("direct TCP connection timed out")??;
    stream.set_nodelay(true)?;
    let (transport, fingerprint) = tokio::time::timeout(
        DIRECT_HANDSHAKE_TIMEOUT,
        client_handshake(&mut stream, &keypair),
    )
    .await
    .context("direct Noise handshake timed out")??;
    if !advertised.fingerprint.eq_ignore_ascii_case(&fingerprint) {
        bail!("direct peer Noise fingerprint mismatch");
    }
    let (reader, mut writer) = split_secure_stream(stream, transport);
    writer
        .write_json(&DirectWireMessage::Hello {
            group_id,
            sender_session_id: local_peer.session_id,
            recipient_session_id: peer.session_id,
        })
        .await?;
    let (sender, receiver) = mpsc::channel(DIRECT_QUEUE_CAPACITY);
    let link_id = Uuid::new_v4();
    tokio::spawn(link_io(
        link_id,
        peer.session_id,
        reader,
        writer,
        receiver,
        events,
    ));
    Ok(DirectLink {
        link_id,
        peer,
        sender,
        role: LinkRole::Initiator,
        state: ConversationState::New,
    })
}

async fn spawn_link_io<R, W>(
    peer: Peer,
    reader: crate::crypto::SecureReader<R>,
    writer: crate::crypto::SecureWriter<W>,
    events: mpsc::Sender<LinkEvent>,
    _role: LinkRole,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(DIRECT_QUEUE_CAPACITY);
    let link_id = Uuid::new_v4();
    events
        .send(LinkEvent::Connected {
            link_id,
            peer: peer.clone(),
            sender,
        })
        .await
        .context("direct chat manager stopped")?;
    tokio::spawn(link_io(
        link_id,
        peer.session_id,
        reader,
        writer,
        receiver,
        events,
    ));
    Ok(())
}

async fn link_io<R, W>(
    link_id: Uuid,
    peer_session_id: Uuid,
    mut reader: crate::crypto::SecureReader<R>,
    mut writer: crate::crypto::SecureWriter<W>,
    mut outbound: mpsc::Receiver<DirectWireMessage>,
    events: mpsc::Sender<LinkEvent>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut window_started = Instant::now();
    let mut messages_in_window = 0u32;
    loop {
        tokio::select! {
            outgoing = outbound.recv() => {
                let Some(outgoing) = outgoing else { break; };
                if writer.write_json(&outgoing).await.is_err() { break; }
            }
            incoming = reader.read_json::<DirectWireMessage>() => {
                let Ok(DirectWireMessage::Chat { message_id, sent_at_ms, text }) = incoming else {
                    break;
                };
                if window_started.elapsed() >= Duration::from_secs(1) {
                    window_started = Instant::now();
                    messages_in_window = 0;
                }
                messages_in_window += 1;
                if messages_in_window > MAX_DIRECT_MESSAGES_PER_SECOND {
                    break;
                }
                if events.send(LinkEvent::Message {
                    link_id,
                    peer_session_id,
                    message_id,
                    sent_at_ms,
                    text,
                }).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = events
        .send(LinkEvent::Disconnected {
            link_id,
            peer_session_id,
        })
        .await;
}

async fn emit_private_message(
    events: &mpsc::Sender<ClientEvent>,
    message: DirectRecord,
    status: PrivateConversationStatus,
) {
    let _ = events
        .send(ClientEvent::Server(ServerMessage::PrivateMessage {
            message,
            status,
        }))
        .await;
}

async fn emit_private_closed(events: &mpsc::Sender<ClientEvent>, peer_session_id: Uuid) {
    let _ = events
        .send(ClientEvent::Server(ServerMessage::PrivateClosed {
            peer_session_id,
        }))
        .await;
}

async fn send_direct_error(events: &mpsc::Sender<ClientEvent>, code: &str, message: &str) {
    let _ = events
        .send(ClientEvent::Server(ServerMessage::Error {
            code: code.to_owned(),
            message: message.to_owned(),
        }))
        .await;
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
