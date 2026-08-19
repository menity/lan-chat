use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc, watch},
    task::JoinHandle,
};
use uuid::Uuid;

use crate::{
    crypto::{
        NoiseKeypair, load_or_create_keypair, public_key_fingerprint, server_handshake,
        split_secure_stream,
    },
    discovery,
    protocol::{
        ClientMessage, DEFAULT_ROOM_ID, DEFAULT_ROOM_NAME, DirectPeerInfo, DiscoveryBeacon,
        GroupRole, GroupSummary, GroupTokenKind, IssuedGroupCredentials, PROTOCOL_MAX,
        PROTOCOL_MIN, Peer, RoomSummary, RoomVisibility, ServerMessage,
    },
    security::{
        is_safe_identifier, is_valid_fingerprint, is_valid_group_credential, sanitize_chat_text,
        sanitize_group_name, sanitize_nickname, sanitize_room_name,
    },
    storage::{GatewayStore, JoinAuthorization},
};

const CLIENT_QUEUE_CAPACITY: usize = 256;
const MAX_CONNECTIONS: usize = 128;
const HISTORY_CAPACITY: usize = 200;
const HISTORY_FRAME_BUDGET: usize = 12 * 1024;
const MAX_ROOMS: usize = 64;
const MAX_CLIENT_MESSAGES_PER_SECOND: u32 = 24;
const MAX_CONSECUTIVE_RATE_VIOLATIONS: u8 = 5;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const GROUP_SELECTION_TIMEOUT: Duration = Duration::from_secs(30);
const NOISE_KEY_FILE: &str = "gateway-noise.key";

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub bind: SocketAddr,
    pub gateway_name: String,
    pub advertise: bool,
    pub data_dir: PathBuf,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7373),
            gateway_name: "LAN Chat Gateway".to_owned(),
            advertise: true,
            data_dir: PathBuf::from("lan-chat-data"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayInfo {
    pub gateway_id: Uuid,
    pub gateway_name: String,
    pub listen_addr: SocketAddr,
    pub fingerprint: String,
    pub data_dir: PathBuf,
}

pub struct GatewayHandle {
    pub info: GatewayInfo,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
}

impl GatewayHandle {
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.task.await.context("gateway task panicked")?
    }
}

#[derive(Clone)]
struct ClientEntry {
    peer: Peer,
    role: GroupRole,
    sender: mpsc::Sender<ServerMessage>,
    joined_rooms: HashSet<String>,
    kick: watch::Sender<Option<KickReason>>,
}

#[derive(Clone, Copy)]
enum KickReason {
    Banned,
    CredentialRotated,
}

struct GroupState {
    summary: GroupSummary,
    clients: Mutex<HashMap<Uuid, ClientEntry>>,
    rooms: Mutex<HashMap<String, RoomSummary>>,
    room_creation: Mutex<()>,
}

struct GatewayState {
    gateway_id: Uuid,
    gateway_name: String,
    keypair: NoiseKeypair,
    store: GatewayStore,
    groups: Mutex<HashMap<Uuid, Arc<GroupState>>>,
}

struct GroupEntry {
    nickname: String,
    member_id: Uuid,
    direct: Option<DirectPeerInfo>,
    negotiated: u16,
    role: GroupRole,
    issued_credentials: Option<IssuedGroupCredentials>,
    issued_member_token: Option<String>,
}

#[derive(Clone, Copy)]
struct RoomActor {
    member_id: Uuid,
    role: GroupRole,
}

struct FixedWindowRateLimiter {
    window_started: Instant,
    used: u32,
}

impl FixedWindowRateLimiter {
    fn new() -> Self {
        Self {
            window_started: Instant::now(),
            used: 0,
        }
    }

    fn allow(&mut self) -> bool {
        if self.window_started.elapsed() >= Duration::from_secs(1) {
            self.window_started = Instant::now();
            self.used = 0;
        }
        self.used += 1;
        self.used <= MAX_CLIENT_MESSAGES_PER_SECOND
    }
}

pub async fn spawn_gateway(config: GatewayConfig) -> Result<GatewayHandle> {
    let gateway_name = sanitize_group_name(&config.gateway_name)?;
    let store = GatewayStore::open(&config.data_dir).await?;
    let gateway_id = store.gateway_id().await?;
    let keypair = load_or_create_keypair(&config.data_dir.join(NOISE_KEY_FILE))?;
    let fingerprint = public_key_fingerprint(&keypair.public);
    let groups = load_groups(&store).await?;
    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("failed to listen on {}", config.bind))?;
    let listen_addr = listener.local_addr()?;
    let info = GatewayInfo {
        gateway_id,
        gateway_name: gateway_name.clone(),
        listen_addr,
        fingerprint: fingerprint.clone(),
        data_dir: config.data_dir,
    };
    let state = Arc::new(GatewayState {
        gateway_id,
        gateway_name,
        keypair,
        store,
        groups: Mutex::new(groups),
    });
    let connection_slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    if config.advertise && !listen_addr.ip().is_loopback() {
        let beacon = DiscoveryBeacon {
            app: "lan-chat-gateway".to_owned(),
            protocol_min: PROTOCOL_MIN,
            protocol_max: PROTOCOL_MAX,
            gateway_id,
            gateway_name: info.gateway_name.clone(),
            port: listen_addr.port(),
            server_fingerprint: fingerprint,
        };
        let discovery_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(error) = discovery::advertise(beacon, discovery_shutdown).await {
                eprintln!("gateway discovery advertisement stopped: {error:#}");
            }
        });
    }

    let task = tokio::spawn(run_accept_loop(
        listener,
        state,
        connection_slots,
        shutdown_rx,
    ));
    Ok(GatewayHandle {
        info,
        shutdown: shutdown_tx,
        task,
    })
}

async fn load_groups(store: &GatewayStore) -> Result<HashMap<Uuid, Arc<GroupState>>> {
    let mut loaded = HashMap::new();
    for summary in store.list_groups().await? {
        let rooms = store
            .rooms(summary.group_id)
            .await?
            .into_iter()
            .map(|room| (room.room_id.clone(), room))
            .collect();
        loaded.insert(summary.group_id, Arc::new(GroupState::new(summary, rooms)));
    }
    Ok(loaded)
}

impl GroupState {
    fn new(summary: GroupSummary, rooms: HashMap<String, RoomSummary>) -> Self {
        Self {
            summary,
            clients: Mutex::new(HashMap::new()),
            rooms: Mutex::new(rooms),
            room_creation: Mutex::new(()),
        }
    }
}

async fn run_accept_loop(
    listener: TcpListener,
    state: Arc<GatewayState>,
    connection_slots: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted.context("failed to accept a client")?;
                let Ok(permit) = Arc::clone(&connection_slots).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_client(stream, remote_addr, state).await
                        && !is_normal_disconnect(&error)
                    {
                        eprintln!("client disconnected: {error:#}");
                    }
                });
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

async fn handle_client(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    state: Arc<GatewayState>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let transport = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        server_handshake(&mut stream, &state.keypair),
    )
    .await
    .context("Noise handshake timed out")??;
    let (mut reader, mut writer) = split_secure_stream(stream, transport);

    let hello = tokio::time::timeout(HELLO_TIMEOUT, reader.read_json::<ClientMessage>())
        .await
        .context("client hello timed out")??;
    let ClientMessage::Hello {
        protocol_min,
        protocol_max,
        nickname,
        direct_port,
        direct_fingerprint,
    } = hello
    else {
        bail!("the first encrypted message was not a client hello");
    };
    let negotiated = PROTOCOL_MAX.min(protocol_max);
    if negotiated < PROTOCOL_MIN || negotiated < protocol_min {
        writer
            .write_json(&ServerMessage::Error {
                code: "incompatible_protocol".to_owned(),
                message: format!(
                    "gateway supports protocol {PROTOCOL_MIN}-{PROTOCOL_MAX}, client supports {protocol_min}-{protocol_max}"
                ),
            })
            .await?;
        bail!("client has no compatible protocol version");
    }
    let nickname = sanitize_nickname(&nickname)?;
    let direct = match (direct_port, direct_fingerprint) {
        (Some(port), Some(fingerprint)) if port != 0 && is_valid_fingerprint(&fingerprint) => {
            Some(DirectPeerInfo {
                endpoint: SocketAddr::new(remote_addr.ip(), port),
                fingerprint,
            })
        }
        (None, None) => None,
        _ => bail!("client advertised invalid peer-to-peer connection details"),
    };
    writer
        .write_json(&ServerMessage::GatewayWelcome {
            protocol_version: negotiated,
            gateway_id: state.gateway_id,
            gateway_name: state.gateway_name.clone(),
            groups: group_summaries(&state).await,
        })
        .await?;

    let selection =
        tokio::time::timeout(GROUP_SELECTION_TIMEOUT, reader.read_json::<ClientMessage>())
            .await
            .context("client did not select a group in time")??;
    let (group, role, member_id, issued_credentials, issued_member_token) = match selection {
        ClientMessage::JoinGroup {
            group_id,
            credential,
        } => {
            let group = state.groups.lock().await.get(&group_id).cloned();
            let Some(group) = group else {
                writer
                    .write_json(&ServerMessage::Error {
                        code: "group_not_found".to_owned(),
                        message: "the selected group no longer exists".to_owned(),
                    })
                    .await?;
                bail!("client selected an unknown group");
            };
            if credential
                .as_deref()
                .is_some_and(|token| !is_valid_group_credential(token))
            {
                writer
                    .write_json(&ServerMessage::Error {
                        code: "invalid_group_credential".to_owned(),
                        message: "the group credential has an invalid format".to_owned(),
                    })
                    .await?;
                return Ok(());
            }
            let authorization = state
                .store
                .authorize_join(group_id, credential, nickname.clone())
                .await
                .context("failed to authorize group join")?;
            match authorization {
                JoinAuthorization::Allowed {
                    role,
                    member_id,
                    issued_member_token,
                } => (group, role, member_id, None, issued_member_token),
                JoinAuthorization::ApprovalRequired => {
                    let (request_id, request_token) = state
                        .store
                        .create_join_request(group_id, nickname.clone())
                        .await
                        .context("failed to create join request")?;
                    writer
                        .write_json(&ServerMessage::JoinPending {
                            group_id,
                            request_id,
                            request_token,
                        })
                        .await?;
                    return Ok(());
                }
                JoinAuthorization::Pending {
                    request_id,
                    request_token,
                } => {
                    writer
                        .write_json(&ServerMessage::JoinPending {
                            group_id,
                            request_id,
                            request_token,
                        })
                        .await?;
                    return Ok(());
                }
                JoinAuthorization::InviteRequired => {
                    writer
                        .write_json(&ServerMessage::Error {
                            code: "invite_required".to_owned(),
                            message: "this group requires an invite token".to_owned(),
                        })
                        .await?;
                    return Ok(());
                }
                JoinAuthorization::Rejected => {
                    writer
                        .write_json(&ServerMessage::Error {
                            code: "join_rejected".to_owned(),
                            message: "an administrator rejected this join request".to_owned(),
                        })
                        .await?;
                    return Ok(());
                }
                JoinAuthorization::Banned => {
                    writer
                        .write_json(&ServerMessage::Error {
                            code: "member_banned".to_owned(),
                            message: "this anonymous membership has been banned from the group"
                                .to_owned(),
                        })
                        .await?;
                    return Ok(());
                }
                JoinAuthorization::MemberLimit => {
                    writer
                        .write_json(&ServerMessage::Error {
                            code: "group_member_limit".to_owned(),
                            message: "this group has reached its persistent member limit"
                                .to_owned(),
                        })
                        .await?;
                    return Ok(());
                }
                JoinAuthorization::InvalidCredential => {
                    writer
                        .write_json(&ServerMessage::Error {
                            code: "invalid_group_credential".to_owned(),
                            message: "the saved invite, request, or administrator token is invalid"
                                .to_owned(),
                        })
                        .await?;
                    return Ok(());
                }
            }
        }
        ClientMessage::CreateGroup { name, access_mode } => {
            let name = sanitize_group_name(&name)?;
            let created = match state
                .store
                .create_group_with_access(name, access_mode)
                .await
            {
                Ok(created) => created,
                Err(error) => {
                    eprintln!("failed to create group: {error:#}");
                    writer
                        .write_json(&ServerMessage::Error {
                            code: "group_create_failed".to_owned(),
                            message: "the group name is already used or could not be saved"
                                .to_owned(),
                        })
                        .await?;
                    return Ok(());
                }
            };
            let group = Arc::new(GroupState::new(
                created.summary.clone(),
                HashMap::from([(
                    DEFAULT_ROOM_ID.to_owned(),
                    RoomSummary {
                        room_id: DEFAULT_ROOM_ID.to_owned(),
                        room_name: DEFAULT_ROOM_NAME.to_owned(),
                        visibility: RoomVisibility::Public,
                    },
                )]),
            ));
            state
                .groups
                .lock()
                .await
                .insert(created.summary.group_id, Arc::clone(&group));
            state
                .store
                .update_member_nickname(
                    created.summary.group_id,
                    created.creator_member_id,
                    nickname.clone(),
                )
                .await?;
            (
                group,
                GroupRole::Admin,
                created.creator_member_id,
                Some(created.credentials),
                None,
            )
        }
        _ => {
            writer
                .write_json(&ServerMessage::Error {
                    code: "group_selection_required".to_owned(),
                    message: "join or create a group before chatting".to_owned(),
                })
                .await?;
            bail!("client did not select a group");
        }
    };

    enter_group(
        reader,
        writer,
        state,
        group,
        GroupEntry {
            nickname,
            member_id,
            direct,
            negotiated,
            role,
            issued_credentials,
            issued_member_token,
        },
    )
    .await
}

async fn enter_group<R, W>(
    mut reader: crate::crypto::SecureReader<R>,
    mut writer: crate::crypto::SecureWriter<W>,
    gateway: Arc<GatewayState>,
    group: Arc<GroupState>,
    entry: GroupEntry,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let session_id = Uuid::new_v4();
    let peer = Peer {
        session_id,
        member_id: entry.member_id,
        nickname: entry.nickname,
        direct: entry.direct,
    };
    let (outbound_tx, mut outbound_rx) = mpsc::channel(CLIENT_QUEUE_CAPACITY);
    let (kick_tx, mut kick_rx) = watch::channel(None);
    let members = {
        let mut clients = group.clients.lock().await;
        let mut members: Vec<_> = clients.values().map(|entry| entry.peer.clone()).collect();
        members.push(peer.clone());
        members.sort_by(|left, right| left.nickname.cmp(&right.nickname));
        clients.insert(
            session_id,
            ClientEntry {
                peer: peer.clone(),
                role: entry.role,
                sender: outbound_tx.clone(),
                joined_rooms: HashSet::from([DEFAULT_ROOM_ID.to_owned()]),
                kick: kick_tx,
            },
        );
        members
    };
    let rooms = match gateway
        .store
        .rooms_for_member(group.summary.group_id, entry.member_id)
        .await
    {
        Ok(rooms) => rooms,
        Err(error) => {
            group.clients.lock().await.remove(&session_id);
            return Err(error).context("failed to load accessible rooms");
        }
    };
    let history = match gateway
        .store
        .history(
            group.summary.group_id,
            DEFAULT_ROOM_ID.to_owned(),
            HISTORY_CAPACITY,
        )
        .await
    {
        Ok(history) => fit_history_to_frame(history),
        Err(error) => {
            group.clients.lock().await.remove(&session_id);
            return Err(error).context("failed to load group history");
        }
    };
    let welcome = ServerMessage::Welcome {
        protocol_version: entry.negotiated,
        group_id: group.summary.group_id,
        group_name: group.summary.group_name.clone(),
        access_mode: group.summary.access_mode,
        role: entry.role,
        issued_credentials: entry.issued_credentials.map(Box::new),
        issued_member_token: entry.issued_member_token,
        room_id: DEFAULT_ROOM_ID.to_owned(),
        room_name: DEFAULT_ROOM_NAME.to_owned(),
        rooms,
        session_id,
        members,
        history,
    };
    if let Err(error) = writer.write_json(&welcome).await {
        group.clients.lock().await.remove(&session_id);
        return Err(error);
    }
    broadcast_except(
        &group,
        ServerMessage::MemberJoined {
            member: peer.clone(),
        },
        Some(session_id),
    )
    .await;

    let mut rate_limiter = FixedWindowRateLimiter::new();
    let mut consecutive_rate_violations = 0u8;
    let connection_result: Result<()> = loop {
        tokio::select! {
            incoming = reader.read_json::<ClientMessage>() => {
                let incoming = match incoming {
                    Ok(message) => message,
                    Err(error) => break Err(error),
                };
                if !rate_limiter.allow() {
                    consecutive_rate_violations += 1;
                    if consecutive_rate_violations >= MAX_CONSECUTIVE_RATE_VIOLATIONS {
                        break Err(anyhow::anyhow!("client repeatedly exceeded the message rate limit"));
                    }
                    send_error(
                        &outbound_tx,
                        "rate_limited",
                        &format!("maximum rate is {MAX_CLIENT_MESSAGES_PER_SECOND} messages per second"),
                    );
                    continue;
                }
                consecutive_rate_violations = 0;
                match incoming {
                    ClientMessage::Chat { room_id, message_id, text } => {
                        handle_room_chat(
                            &gateway.store,
                            &group,
                            &peer,
                            room_id,
                            message_id,
                            text,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::CreateRoom { name, visibility } => {
                        handle_create_room(
                            &gateway.store,
                            &group,
                            session_id,
                            entry.member_id,
                            name,
                            visibility,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::JoinRoom { room_id } => {
                        handle_join_room(&gateway.store, &group, session_id, room_id, &outbound_tx).await;
                    }
                    ClientMessage::LeaveRoom { room_id } => {
                        handle_leave_room(&group, session_id, room_id, &outbound_tx).await;
                    }
                    ClientMessage::LoadHistory { room_id, before_sequence, limit } => {
                        handle_load_history(
                            &gateway.store,
                            &group,
                            session_id,
                            room_id,
                            before_sequence,
                            limit,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::ListJoinRequests => {
                        handle_list_join_requests(
                            &gateway.store,
                            &group,
                            session_id,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::DecideJoinRequest { request_id, approve } => {
                        handle_decide_join_request(
                            &gateway.store,
                            &group,
                            session_id,
                            request_id,
                            approve,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::ListGroupMembers { offset } => {
                        handle_list_group_members(
                            &gateway.store,
                            &group,
                            session_id,
                            offset,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::SetMemberBanned { member_id, banned } => {
                        handle_set_member_banned(
                            &gateway.store,
                            &group,
                            session_id,
                            member_id,
                            banned,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::RotateGroupToken { kind } => {
                        handle_rotate_group_token(
                            &gateway.store,
                            &group,
                            session_id,
                            entry.member_id,
                            kind,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::ListRoomMembers { room_id, offset } => {
                        handle_list_room_members(
                            &gateway.store,
                            &group,
                            RoomActor {
                                member_id: entry.member_id,
                                role: entry.role,
                            },
                            room_id,
                            offset,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::SetRoomMember { room_id, member_id, included } => {
                        handle_set_room_member(
                            &gateway.store,
                            &group,
                            RoomActor {
                                member_id: entry.member_id,
                                role: entry.role,
                            },
                            room_id,
                            member_id,
                            included,
                            &outbound_tx,
                        ).await;
                    }
                    ClientMessage::PrivateChat { .. } => send_error(
                        &outbound_tx,
                        "private_requires_direct_connection",
                        "private messages must use a peer-to-peer connection",
                    ),
                    ClientMessage::Ping => send_to_client(&outbound_tx, ServerMessage::Pong),
                    ClientMessage::Hello { .. }
                    | ClientMessage::JoinGroup { .. }
                    | ClientMessage::CreateGroup { .. } => send_error(
                        &outbound_tx,
                        "unexpected_handshake_message",
                        "gateway and group selection messages can only be sent once",
                    ),
                }
            }
            outbound = outbound_rx.recv() => {
                let Some(outbound) = outbound else {
                    break Ok(());
                };
                if let Err(error) = writer.write_json(&outbound).await {
                    break Err(error);
                }
            }
            changed = kick_rx.changed() => {
                if changed.is_err() {
                    break Err(anyhow::anyhow!("client session was revoked"));
                }
                let reason = *kick_rx.borrow();
                if let Some(reason) = reason {
                    let (code, message) = match reason {
                        KickReason::Banned => (
                            "member_banned",
                            "an administrator banned this anonymous membership",
                        ),
                        KickReason::CredentialRotated => (
                            "session_revoked",
                            "this membership credential was rotated from another session",
                        ),
                    };
                    let _ = writer.write_json(&ServerMessage::Error {
                        code: code.to_owned(),
                        message: message.to_owned(),
                    }).await;
                    break Ok(());
                }
            }
        }
    };

    group.clients.lock().await.remove(&session_id);
    broadcast(&group, ServerMessage::MemberLeft { session_id }).await;
    connection_result
}

async fn require_admin(group: &GroupState, session_id: Uuid) -> bool {
    group
        .clients
        .lock()
        .await
        .get(&session_id)
        .is_some_and(|client| client.role == GroupRole::Admin)
}

async fn handle_list_join_requests(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !require_admin(group, session_id).await {
        send_error(
            sender,
            "admin_required",
            "only a group administrator can review join requests",
        );
        return;
    }
    match store.pending_join_requests(group.summary.group_id).await {
        Ok(requests) => send_to_client(sender, ServerMessage::JoinRequests { requests }),
        Err(error) => {
            eprintln!("failed to list group join requests: {error:#}");
            send_error(
                sender,
                "join_requests_unavailable",
                "join requests are unavailable",
            );
        }
    }
}

async fn handle_decide_join_request(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    request_id: Uuid,
    approve: bool,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !require_admin(group, session_id).await {
        send_error(
            sender,
            "admin_required",
            "only a group administrator can review join requests",
        );
        return;
    }
    match store
        .decide_join_request(group.summary.group_id, request_id, approve)
        .await
    {
        Ok(true) => handle_list_join_requests(store, group, session_id, sender).await,
        Ok(false) => send_error(
            sender,
            "join_request_not_found",
            "that pending join request no longer exists",
        ),
        Err(error) => {
            eprintln!("failed to decide group join request: {error:#}");
            send_error(
                sender,
                "join_request_failed",
                "the decision could not be saved",
            );
        }
    }
}

async fn handle_list_group_members(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    offset: u32,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !require_admin(group, session_id).await {
        send_error(
            sender,
            "admin_required",
            "only a group administrator can manage members",
        );
        return;
    }
    match store.group_members(group.summary.group_id, offset).await {
        Ok((members, has_more)) => send_to_client(
            sender,
            ServerMessage::GroupMembers {
                members,
                offset,
                has_more,
            },
        ),
        Err(error) => {
            eprintln!("failed to list group members: {error:#}");
            send_error(
                sender,
                "members_unavailable",
                "group members are unavailable",
            );
        }
    }
}

async fn handle_set_member_banned(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    member_id: Uuid,
    banned: bool,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !require_admin(group, session_id).await {
        send_error(
            sender,
            "admin_required",
            "only a group administrator can ban members",
        );
        return;
    }
    match store
        .set_member_banned(group.summary.group_id, member_id, banned)
        .await
    {
        Ok(true) => {
            if banned {
                let kicks: Vec<_> = group
                    .clients
                    .lock()
                    .await
                    .values()
                    .filter(|client| client.peer.member_id == member_id)
                    .map(|client| client.kick.clone())
                    .collect();
                for kick in kicks {
                    let _ = kick.send(Some(KickReason::Banned));
                }
            }
            handle_list_group_members(store, group, session_id, 0, sender).await;
        }
        Ok(false) => send_error(
            sender,
            "member_not_manageable",
            "the member does not exist or is an administrator",
        ),
        Err(error) => {
            eprintln!("failed to update member ban: {error:#}");
            send_error(
                sender,
                "member_update_failed",
                "the member change could not be saved",
            );
        }
    }
}

async fn handle_rotate_group_token(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    actor_member_id: Uuid,
    kind: GroupTokenKind,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if kind != GroupTokenKind::Member && !require_admin(group, session_id).await {
        send_error(
            sender,
            "admin_required",
            "only a group administrator can rotate tokens",
        );
        return;
    }
    match store
        .rotate_group_token(group.summary.group_id, actor_member_id, kind)
        .await
    {
        Ok(token) => {
            if matches!(kind, GroupTokenKind::Member | GroupTokenKind::Admin) {
                let kicks: Vec<_> = group
                    .clients
                    .lock()
                    .await
                    .iter()
                    .filter(|(other_session_id, client)| {
                        **other_session_id != session_id && client.peer.member_id == actor_member_id
                    })
                    .map(|(_, client)| client.kick.clone())
                    .collect();
                for kick in kicks {
                    let _ = kick.send(Some(KickReason::CredentialRotated));
                }
            }
            send_to_client(sender, ServerMessage::GroupTokenRotated { kind, token });
        }
        Err(error) => {
            eprintln!("failed to rotate group token: {error:#}");
            send_error(
                sender,
                "token_rotation_failed",
                "the token could not be rotated",
            );
        }
    }
}

async fn handle_list_room_members(
    store: &GatewayStore,
    group: &GroupState,
    actor: RoomActor,
    room_id: String,
    offset: u32,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !is_safe_identifier(&room_id) {
        send_error(sender, "invalid_room", "the room identifier is invalid");
        return;
    }
    match store
        .member_can_manage_room(
            group.summary.group_id,
            room_id.clone(),
            actor.member_id,
            actor.role,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            send_error(
                sender,
                "room_owner_required",
                "only the room owner or a group administrator can manage this room",
            );
            return;
        }
        Err(error) => {
            eprintln!("failed to authorize room management: {error:#}");
            send_error(
                sender,
                "room_authorization_failed",
                "room access could not be checked",
            );
            return;
        }
    }
    match store
        .room_members(group.summary.group_id, room_id.clone(), offset)
        .await
    {
        Ok((members, has_more)) => send_to_client(
            sender,
            ServerMessage::RoomMembers {
                room_id,
                members,
                offset,
                has_more,
            },
        ),
        Err(error) => {
            eprintln!("failed to list private room members: {error:#}");
            send_error(
                sender,
                "room_members_unavailable",
                "private-room members are unavailable",
            );
        }
    }
}

async fn handle_set_room_member(
    store: &GatewayStore,
    group: &GroupState,
    actor: RoomActor,
    room_id: String,
    target_member_id: Uuid,
    included: bool,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !is_safe_identifier(&room_id) {
        send_error(sender, "invalid_room", "the room identifier is invalid");
        return;
    }
    match store
        .set_room_member(
            group.summary.group_id,
            room_id.clone(),
            actor.member_id,
            actor.role,
            target_member_id,
            included,
        )
        .await
    {
        Ok(true) => {
            if let Some(room) = group.rooms.lock().await.get(&room_id).cloned() {
                if included {
                    broadcast_to_member(
                        group,
                        target_member_id,
                        ServerMessage::RoomCreated { room },
                    )
                    .await;
                } else {
                    remove_room_from_member(group, target_member_id, &room_id).await;
                }
            }
            handle_list_room_members(store, group, actor, room_id, 0, sender).await;
        }
        Ok(false) => send_error(
            sender,
            "room_membership_unchanged",
            "that private-room membership was already in the requested state or belongs to the owner",
        ),
        Err(error) => {
            eprintln!("failed to update private room member: {error:#}");
            send_error(
                sender,
                "room_member_update_failed",
                "the private-room membership could not be saved",
            );
        }
    }
}

async fn handle_room_chat(
    store: &GatewayStore,
    group: &GroupState,
    peer: &Peer,
    room_id: String,
    message_id: Uuid,
    text: String,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !is_safe_identifier(&room_id) {
        send_error(sender, "invalid_room", "the room identifier is invalid");
        return;
    }
    let joined = group
        .clients
        .lock()
        .await
        .get(&peer.session_id)
        .is_some_and(|entry| entry.joined_rooms.contains(&room_id));
    if !joined {
        send_error(
            sender,
            "room_not_joined",
            "join the room before sending messages",
        );
        return;
    }
    let text = match sanitize_chat_text(&text) {
        Ok(text) => text,
        Err(error) => {
            send_error(sender, "invalid_message", &error.to_string());
            return;
        }
    };
    if !group.rooms.lock().await.contains_key(&room_id) {
        send_error(
            sender,
            "room_not_found",
            "the requested room does not exist",
        );
        return;
    }
    let message = match store
        .append_message(
            group.summary.group_id,
            room_id.clone(),
            message_id,
            peer.clone(),
            now_ms(),
            text,
        )
        .await
    {
        Ok(message) => message,
        Err(error) => {
            eprintln!("failed to persist group message: {error:#}");
            send_error(
                sender,
                "message_not_persisted",
                "the gateway could not persist the message; it was not delivered",
            );
            return;
        }
    };
    broadcast_to_room(group, &room_id, ServerMessage::Chat { message }).await;
}

async fn handle_create_room(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    creator_member_id: Uuid,
    name: String,
    visibility: RoomVisibility,
    sender: &mpsc::Sender<ServerMessage>,
) {
    let name = match sanitize_room_name(&name) {
        Ok(name) => name,
        Err(error) => {
            send_error(sender, "invalid_room_name", &error.to_string());
            return;
        }
    };
    let _creation = group.room_creation.lock().await;
    {
        let rooms = group.rooms.lock().await;
        if rooms.len() >= MAX_ROOMS {
            send_error(
                sender,
                "room_limit",
                "this group has reached its room limit",
            );
            return;
        }
        if rooms
            .values()
            .any(|room| room.room_name.eq_ignore_ascii_case(&name))
        {
            send_error(
                sender,
                "room_name_used",
                "a room with that name already exists",
            );
            return;
        }
    }
    let room = match store
        .create_room_with_visibility(
            group.summary.group_id,
            name,
            visibility,
            Some(creator_member_id),
        )
        .await
    {
        Ok(room) => room,
        Err(error) => {
            eprintln!("failed to persist room: {error:#}");
            send_error(
                sender,
                "room_not_persisted",
                "the gateway could not create the room",
            );
            return;
        }
    };
    group
        .rooms
        .lock()
        .await
        .insert(room.room_id.clone(), room.clone());
    match visibility {
        RoomVisibility::Public => {
            broadcast(group, ServerMessage::RoomCreated { room: room.clone() }).await;
        }
        RoomVisibility::Private => {
            broadcast_private_room_created(
                group,
                creator_member_id,
                ServerMessage::RoomCreated { room: room.clone() },
            )
            .await;
        }
    }
    join_room(store, group, session_id, room, sender).await;
}

async fn handle_join_room(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    room_id: String,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !is_safe_identifier(&room_id) {
        send_error(sender, "invalid_room", "the room identifier is invalid");
        return;
    }
    let room = group.rooms.lock().await.get(&room_id).cloned();
    let Some(room) = room else {
        send_error(
            sender,
            "room_not_found",
            "the requested room does not exist",
        );
        return;
    };
    let member_id = group
        .clients
        .lock()
        .await
        .get(&session_id)
        .map(|client| client.peer.member_id);
    let Some(member_id) = member_id else {
        return;
    };
    match store
        .member_can_access_room(group.summary.group_id, room_id, member_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            send_error(
                sender,
                "private_room_denied",
                "this private room is not shared with you",
            );
            return;
        }
        Err(error) => {
            eprintln!("failed to authorize room join: {error:#}");
            send_error(
                sender,
                "room_authorization_failed",
                "room access could not be checked",
            );
            return;
        }
    }
    join_room(store, group, session_id, room, sender).await;
}

async fn join_room(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    room: RoomSummary,
    sender: &mpsc::Sender<ServerMessage>,
) {
    let history = match store
        .history(
            group.summary.group_id,
            room.room_id.clone(),
            HISTORY_CAPACITY,
        )
        .await
    {
        Ok(history) => fit_history_to_frame(history),
        Err(error) => {
            eprintln!("failed to load room history: {error:#}");
            send_error(sender, "history_unavailable", "room history is unavailable");
            return;
        }
    };
    if let Some(client) = group.clients.lock().await.get_mut(&session_id) {
        client.joined_rooms.insert(room.room_id.clone());
    }
    send_to_client(sender, ServerMessage::RoomJoined { room, history });
}

async fn handle_load_history(
    store: &GatewayStore,
    group: &GroupState,
    session_id: Uuid,
    room_id: String,
    before_sequence: u64,
    limit: u16,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if !is_safe_identifier(&room_id) || before_sequence <= 1 {
        send_error(
            sender,
            "invalid_history_request",
            "history request is invalid",
        );
        return;
    }
    let joined = group
        .clients
        .lock()
        .await
        .get(&session_id)
        .is_some_and(|client| client.joined_rooms.contains(&room_id));
    if !joined {
        send_error(
            sender,
            "room_not_joined",
            "join the room before loading history",
        );
        return;
    }
    let messages = match store
        .history_before(
            group.summary.group_id,
            room_id.clone(),
            before_sequence,
            usize::from(limit.clamp(1, 100)),
        )
        .await
    {
        Ok(messages) => fit_history_to_frame(messages),
        Err(error) => {
            eprintln!("failed to load older room history: {error:#}");
            send_error(sender, "history_unavailable", "room history is unavailable");
            return;
        }
    };
    let has_more = messages.first().is_some_and(|message| message.sequence > 1);
    send_to_client(
        sender,
        ServerMessage::HistoryPage {
            room_id,
            messages,
            has_more,
        },
    );
}

async fn handle_leave_room(
    group: &GroupState,
    session_id: Uuid,
    room_id: String,
    sender: &mpsc::Sender<ServerMessage>,
) {
    if room_id == DEFAULT_ROOM_ID {
        send_error(
            sender,
            "cannot_leave_general",
            "the general room is always joined",
        );
        return;
    }
    if let Some(client) = group.clients.lock().await.get_mut(&session_id) {
        client.joined_rooms.remove(&room_id);
    }
    send_to_client(sender, ServerMessage::RoomLeft { room_id });
}

async fn group_summaries(state: &GatewayState) -> Vec<GroupSummary> {
    let mut groups: Vec<_> = state
        .groups
        .lock()
        .await
        .values()
        .map(|group| group.summary.clone())
        .collect();
    groups.sort_by(|left, right| left.group_name.cmp(&right.group_name));
    groups
}

fn send_error(sender: &mpsc::Sender<ServerMessage>, code: &str, message: &str) {
    send_to_client(
        sender,
        ServerMessage::Error {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    );
}

fn send_to_client(sender: &mpsc::Sender<ServerMessage>, message: ServerMessage) {
    let _ = sender.try_send(message);
}

async fn broadcast(state: &GroupState, message: ServerMessage) {
    broadcast_except(state, message, None).await;
}

async fn broadcast_except(state: &GroupState, message: ServerMessage, excluded: Option<Uuid>) {
    let senders: Vec<_> = state
        .clients
        .lock()
        .await
        .iter()
        .filter(|(session_id, _)| Some(**session_id) != excluded)
        .map(|(_, entry)| entry.sender.clone())
        .collect();
    for sender in senders {
        send_to_client(&sender, message.clone());
    }
}

async fn broadcast_to_room(state: &GroupState, room_id: &str, message: ServerMessage) {
    let senders: Vec<_> = state
        .clients
        .lock()
        .await
        .values()
        .filter(|entry| entry.joined_rooms.contains(room_id))
        .map(|entry| entry.sender.clone())
        .collect();
    for sender in senders {
        send_to_client(&sender, message.clone());
    }
}

async fn broadcast_to_member(state: &GroupState, member_id: Uuid, message: ServerMessage) {
    let senders: Vec<_> = state
        .clients
        .lock()
        .await
        .values()
        .filter(|entry| entry.peer.member_id == member_id)
        .map(|entry| entry.sender.clone())
        .collect();
    for sender in senders {
        send_to_client(&sender, message.clone());
    }
}

async fn broadcast_private_room_created(
    state: &GroupState,
    owner_member_id: Uuid,
    message: ServerMessage,
) {
    let senders: Vec<_> = state
        .clients
        .lock()
        .await
        .values()
        .filter(|entry| entry.role == GroupRole::Admin || entry.peer.member_id == owner_member_id)
        .map(|entry| entry.sender.clone())
        .collect();
    for sender in senders {
        send_to_client(&sender, message.clone());
    }
}

async fn remove_room_from_member(state: &GroupState, member_id: Uuid, room_id: &str) {
    let senders: Vec<_> = {
        let mut clients = state.clients.lock().await;
        clients
            .values_mut()
            .filter(|entry| entry.peer.member_id == member_id)
            .map(|entry| {
                entry.joined_rooms.remove(room_id);
                entry.sender.clone()
            })
            .collect()
    };
    for sender in senders {
        send_to_client(
            &sender,
            ServerMessage::RoomLeft {
                room_id: room_id.to_owned(),
            },
        );
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn fit_history_to_frame(
    history: Vec<crate::protocol::ChatRecord>,
) -> Vec<crate::protocol::ChatRecord> {
    let mut used = 512usize;
    let mut selected = Vec::new();
    for message in history.into_iter().rev() {
        let size = serde_json::to_vec(&message)
            .map(|encoded| encoded.len())
            .unwrap_or(HISTORY_FRAME_BUDGET);
        if !selected.is_empty() && used.saturating_add(size) > HISTORY_FRAME_BUDGET {
            break;
        }
        used = used.saturating_add(size);
        selected.push(message);
    }
    selected.reverse();
    selected
}

fn is_normal_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            )
        })
    })
}
