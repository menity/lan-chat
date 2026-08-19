use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use tokio::{net::TcpStream, sync::mpsc};
use uuid::Uuid;

use crate::{
    crypto::{SecureReader, SecureWriter, client_handshake, generate_keypair, split_secure_stream},
    direct::{DirectManager, DirectSetup},
    protocol::{
        ChatRecord, ClientMessage, DirectRecord, GroupAccessMode, GroupMemberSummary, GroupRole,
        GroupSummary, IssuedGroupCredentials, JoinRequestSummary, PROTOCOL_MAX, PROTOCOL_MIN, Peer,
        RoomMemberSummary, RoomSummary, ServerMessage,
    },
    security::{
        is_safe_identifier, is_valid_fingerprint, is_valid_group_credential, sanitize_chat_text,
        sanitize_group_name, sanitize_nickname, sanitize_room_name, sanitize_status_text,
    },
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WELCOME_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_QUEUE_CAPACITY: usize = 256;

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub protocol_version: u16,
    pub gateway_id: Uuid,
    pub gateway_name: String,
    pub group_id: Uuid,
    pub group_name: String,
    pub access_mode: GroupAccessMode,
    pub role: GroupRole,
    pub issued_credentials: Option<IssuedGroupCredentials>,
    pub issued_member_token: Option<String>,
    pub room_id: String,
    pub room_name: String,
    pub rooms: Vec<RoomSummary>,
    pub session_id: Uuid,
    pub members: Vec<Peer>,
    pub history: Vec<ChatRecord>,
    pub server_fingerprint: String,
    pub endpoint: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct GatewaySnapshot {
    pub protocol_version: u16,
    pub gateway_id: Uuid,
    pub gateway_name: String,
    pub groups: Vec<GroupSummary>,
    pub server_fingerprint: String,
    pub endpoint: SocketAddr,
}

#[derive(Debug)]
pub enum ClientEvent {
    Server(ServerMessage),
    Disconnected(String),
}

pub struct ClientConnection {
    pub session: SessionInfo,
    pub outgoing: mpsc::Sender<ClientMessage>,
    pub incoming: mpsc::Receiver<ClientEvent>,
}

#[derive(Debug, Clone)]
pub struct PendingJoin {
    pub gateway_id: Uuid,
    pub group_id: Uuid,
    pub request_id: Uuid,
    pub request_token: String,
}

pub enum JoinOutcome {
    Connected(Box<ClientConnection>),
    Pending(PendingJoin),
}

enum GroupSelection {
    Join {
        group_id: Uuid,
        credential: Option<String>,
    },
    Create {
        name: String,
        access_mode: GroupAccessMode,
    },
}

struct OpenGateway {
    reader: SecureReader<tokio::net::tcp::OwnedReadHalf>,
    writer: SecureWriter<tokio::net::tcp::OwnedWriteHalf>,
    snapshot: GatewaySnapshot,
}

pub async fn inspect_gateway(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
) -> Result<GatewaySnapshot> {
    Ok(open_gateway(endpoint, nickname, expected_fingerprint, None)
        .await?
        .snapshot)
}

pub async fn join_group(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
    group_id: Uuid,
) -> Result<ClientConnection> {
    match join_group_with_credential(endpoint, nickname, expected_fingerprint, group_id, None)
        .await?
    {
        JoinOutcome::Connected(connection) => Ok(*connection),
        JoinOutcome::Pending(_) => bail!("group join is waiting for administrator approval"),
    }
}

pub async fn join_group_with_credential(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
    group_id: Uuid,
    credential: Option<String>,
) -> Result<JoinOutcome> {
    if let Some(credential) = credential.as_deref()
        && !is_valid_group_credential(credential)
    {
        bail!("group credential has an invalid format");
    }
    connect_selected(
        endpoint,
        nickname,
        expected_fingerprint,
        GroupSelection::Join {
            group_id,
            credential,
        },
    )
    .await
}

pub async fn create_group(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
    group_name: String,
) -> Result<ClientConnection> {
    create_group_with_access(
        endpoint,
        nickname,
        expected_fingerprint,
        group_name,
        GroupAccessMode::Public,
    )
    .await
}

pub async fn create_group_with_access(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
    group_name: String,
    access_mode: GroupAccessMode,
) -> Result<ClientConnection> {
    match connect_selected(
        endpoint,
        nickname,
        expected_fingerprint,
        GroupSelection::Create {
            name: group_name,
            access_mode,
        },
    )
    .await?
    {
        JoinOutcome::Connected(connection) => Ok(*connection),
        JoinOutcome::Pending(_) => bail!("group creation unexpectedly returned a pending join"),
    }
}

pub async fn connect(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
) -> Result<ClientConnection> {
    let direct = DirectSetup::bind().await?;
    let advertised = Some((direct.port, direct.fingerprint.clone()));
    let opened = open_gateway(endpoint, nickname, expected_fingerprint, advertised).await?;
    let [group] = opened.snapshot.groups.as_slice() else {
        bail!(
            "gateway has {} groups; select a group through the TUI or provide its id",
            opened.snapshot.groups.len()
        );
    };
    let group_id = group.group_id;
    match finish_connection(
        opened,
        GroupSelection::Join {
            group_id,
            credential: None,
        },
        direct,
    )
    .await?
    {
        JoinOutcome::Connected(connection) => Ok(*connection),
        JoinOutcome::Pending(_) => bail!("group join is waiting for administrator approval"),
    }
}

async fn connect_selected(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
    selection: GroupSelection,
) -> Result<JoinOutcome> {
    let direct = DirectSetup::bind().await?;
    let advertised = Some((direct.port, direct.fingerprint.clone()));
    let opened = open_gateway(endpoint, nickname, expected_fingerprint, advertised).await?;
    finish_connection(opened, selection, direct).await
}

async fn open_gateway(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
    direct: Option<(u16, String)>,
) -> Result<OpenGateway> {
    let nickname = sanitize_nickname(nickname)?;
    if let Some(expected) = expected_fingerprint
        && !is_valid_fingerprint(expected)
    {
        bail!("expected fingerprint has an invalid format");
    }
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(endpoint))
        .await
        .with_context(|| format!("connection to {endpoint} timed out"))?
        .with_context(|| format!("failed to connect to {endpoint}"))?;
    stream.set_nodelay(true)?;

    let local_keypair = generate_keypair()?;
    let (transport, server_fingerprint) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_handshake(&mut stream, &local_keypair),
    )
    .await
    .context("Noise handshake timed out")??;
    if let Some(expected) = expected_fingerprint
        && !server_fingerprint.eq_ignore_ascii_case(expected)
    {
        bail!("server fingerprint mismatch: expected {expected}, received {server_fingerprint}");
    }

    let (mut reader, mut writer) = split_secure_stream(stream, transport);
    let (direct_port, direct_fingerprint) = direct
        .map(|(port, fingerprint)| (Some(port), Some(fingerprint)))
        .unwrap_or((None, None));
    writer
        .write_json(&ClientMessage::Hello {
            protocol_min: PROTOCOL_MIN,
            protocol_max: PROTOCOL_MAX,
            nickname,
            direct_port,
            direct_fingerprint,
        })
        .await?;
    let first = sanitize_server_message(
        tokio::time::timeout(WELCOME_TIMEOUT, reader.read_json::<ServerMessage>())
            .await
            .context("server welcome timed out")??,
    )?;
    let ServerMessage::GatewayWelcome {
        protocol_version,
        gateway_id,
        gateway_name,
        groups,
    } = first
    else {
        if let ServerMessage::Error { code, message } = first {
            bail!("server rejected the connection ({code}): {message}");
        }
        bail!("server did not send a gateway welcome message");
    };

    Ok(OpenGateway {
        reader,
        writer,
        snapshot: GatewaySnapshot {
            protocol_version,
            gateway_id,
            gateway_name,
            groups,
            server_fingerprint,
            endpoint,
        },
    })
}

async fn finish_connection(
    mut opened: OpenGateway,
    selection: GroupSelection,
    direct: DirectSetup,
) -> Result<JoinOutcome> {
    let selection_message = match selection {
        GroupSelection::Join {
            group_id,
            credential,
        } => ClientMessage::JoinGroup {
            group_id,
            credential,
        },
        GroupSelection::Create { name, access_mode } => {
            ClientMessage::CreateGroup { name, access_mode }
        }
    };
    opened.writer.write_json(&selection_message).await?;
    let first = sanitize_server_message(
        tokio::time::timeout(WELCOME_TIMEOUT, opened.reader.read_json::<ServerMessage>())
            .await
            .context("group welcome timed out")??,
    )?;
    if let ServerMessage::JoinPending {
        group_id,
        request_id,
        request_token,
    } = first
    {
        return Ok(JoinOutcome::Pending(PendingJoin {
            gateway_id: opened.snapshot.gateway_id,
            group_id,
            request_id,
            request_token,
        }));
    }
    let ServerMessage::Welcome {
        protocol_version,
        group_id,
        group_name,
        access_mode,
        role,
        issued_credentials,
        issued_member_token,
        room_id,
        room_name,
        rooms,
        session_id,
        members,
        history,
    } = first
    else {
        if let ServerMessage::Error { code, message } = first {
            bail!("gateway rejected the group selection ({code}): {message}");
        }
        bail!("gateway did not send a group welcome message");
    };

    let session = SessionInfo {
        protocol_version,
        gateway_id: opened.snapshot.gateway_id,
        gateway_name: opened.snapshot.gateway_name,
        group_id,
        group_name,
        access_mode,
        role,
        issued_credentials: issued_credentials.map(|credentials| *credentials),
        issued_member_token,
        room_id,
        room_name,
        rooms,
        session_id,
        members,
        history,
        server_fingerprint: opened.snapshot.server_fingerprint,
        endpoint: opened.snapshot.endpoint,
    };
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel(CLIENT_QUEUE_CAPACITY);
    let (incoming_tx, incoming_rx) = mpsc::channel(CLIENT_QUEUE_CAPACITY);
    let local_peer = session
        .members
        .iter()
        .find(|member| member.session_id == session.session_id)
        .cloned()
        .context("gateway welcome omitted the local member")?;
    let direct_manager = DirectManager::start(
        direct,
        session.group_id,
        local_peer,
        session.members.clone(),
        incoming_tx.clone(),
    );

    tokio::spawn(async move {
        let disconnect_reason = loop {
            tokio::select! {
                outgoing = outgoing_rx.recv() => {
                    let Some(outgoing) = outgoing else {
                        break "client closed the connection".to_owned();
                    };
                    if let ClientMessage::PrivateChat {
                        peer_session_id,
                        message_id,
                        text,
                    } = outgoing
                    {
                        if let Err(error) = direct_manager
                            .send(peer_session_id, message_id, text)
                            .await
                        {
                            break format!("private chat manager stopped: {error:#}");
                        }
                        continue;
                    }
                    if let Err(error) = opened.writer.write_json(&outgoing).await {
                        break format!("failed to send: {error:#}");
                    }
                }
                incoming = opened.reader.read_json::<ServerMessage>() => {
                    match incoming {
                        Ok(message) => {
                            let message = match sanitize_server_message(message) {
                                Ok(message) => message,
                                Err(error) => break format!("server sent unsafe data: {error:#}"),
                            };
                            match &message {
                                ServerMessage::MemberJoined { member } => {
                                    direct_manager.upsert_member(member.clone()).await;
                                }
                                ServerMessage::MemberLeft { session_id } => {
                                    direct_manager.remove_member(*session_id).await;
                                }
                                _ => {}
                            }
                            if incoming_tx.send(ClientEvent::Server(message)).await.is_err() {
                                break "client event receiver was closed".to_owned();
                            }
                        }
                        Err(error) => break format!("connection closed: {error:#}"),
                    }
                }
            }
        };
        let _ = incoming_tx
            .send(ClientEvent::Disconnected(disconnect_reason))
            .await;
    });

    Ok(JoinOutcome::Connected(Box::new(ClientConnection {
        session,
        outgoing: outgoing_tx,
        incoming: incoming_rx,
    })))
}

fn sanitize_server_message(message: ServerMessage) -> Result<ServerMessage> {
    Ok(match message {
        ServerMessage::GatewayWelcome {
            protocol_version,
            gateway_id,
            gateway_name,
            groups,
        } => {
            if !(PROTOCOL_MIN..=PROTOCOL_MAX).contains(&protocol_version) {
                bail!("gateway selected an unsupported protocol version");
            }
            ServerMessage::GatewayWelcome {
                protocol_version,
                gateway_id,
                gateway_name: sanitize_group_name(&gateway_name)?,
                groups: groups
                    .into_iter()
                    .map(sanitize_group_summary)
                    .collect::<Result<Vec<_>>>()?,
            }
        }
        ServerMessage::Welcome {
            protocol_version,
            group_id,
            group_name,
            access_mode,
            role,
            issued_credentials,
            issued_member_token,
            room_id,
            room_name,
            rooms,
            session_id,
            members,
            history,
        } => {
            if !(PROTOCOL_MIN..=PROTOCOL_MAX).contains(&protocol_version) {
                bail!("server selected an unsupported protocol version");
            }
            if !is_safe_identifier(&room_id) {
                bail!("server sent an unsafe room identifier");
            }
            let members = members
                .into_iter()
                .map(sanitize_peer)
                .collect::<Result<Vec<_>>>()?;
            let history = history
                .into_iter()
                .map(sanitize_chat_record)
                .collect::<Result<Vec<_>>>()?;
            let rooms = rooms
                .into_iter()
                .map(sanitize_room_summary)
                .collect::<Result<Vec<_>>>()?;
            let issued_credentials = issued_credentials
                .map(|credentials| sanitize_issued_credentials(*credentials).map(Box::new))
                .transpose()?;
            if issued_member_token
                .as_deref()
                .is_some_and(|token| !is_valid_group_credential(token))
            {
                bail!("server sent an invalid member credential");
            }
            ServerMessage::Welcome {
                protocol_version,
                group_id,
                group_name: sanitize_group_name(&group_name)?,
                access_mode,
                role,
                issued_credentials,
                issued_member_token,
                room_id,
                room_name: sanitize_room_name(&room_name)?,
                rooms,
                session_id,
                members,
                history,
            }
        }
        ServerMessage::Chat { message } => ServerMessage::Chat {
            message: sanitize_chat_record(message)?,
        },
        ServerMessage::RoomCreated { room } => ServerMessage::RoomCreated {
            room: sanitize_room_summary(room)?,
        },
        ServerMessage::RoomJoined { room, history } => ServerMessage::RoomJoined {
            room: sanitize_room_summary(room)?,
            history: history
                .into_iter()
                .map(sanitize_chat_record)
                .collect::<Result<Vec<_>>>()?,
        },
        ServerMessage::RoomLeft { room_id } => {
            if !is_safe_identifier(&room_id) {
                bail!("server sent an unsafe room identifier");
            }
            ServerMessage::RoomLeft { room_id }
        }
        ServerMessage::HistoryPage {
            room_id,
            messages,
            has_more,
        } => {
            if !is_safe_identifier(&room_id) {
                bail!("server sent an unsafe room identifier");
            }
            ServerMessage::HistoryPage {
                room_id,
                messages: messages
                    .into_iter()
                    .map(sanitize_chat_record)
                    .collect::<Result<Vec<_>>>()?,
                has_more,
            }
        }
        ServerMessage::JoinPending {
            group_id,
            request_id,
            request_token,
        } => {
            if !is_valid_group_credential(&request_token) {
                bail!("server sent an invalid join request token");
            }
            ServerMessage::JoinPending {
                group_id,
                request_id,
                request_token,
            }
        }
        ServerMessage::JoinRequests { requests } => ServerMessage::JoinRequests {
            requests: requests
                .into_iter()
                .map(sanitize_join_request)
                .collect::<Result<Vec<_>>>()?,
        },
        ServerMessage::GroupMembers {
            members,
            offset,
            has_more,
        } => ServerMessage::GroupMembers {
            members: members
                .into_iter()
                .map(sanitize_group_member)
                .collect::<Result<Vec<_>>>()?,
            offset,
            has_more,
        },
        ServerMessage::GroupTokenRotated { kind, token } => {
            if !is_valid_group_credential(&token) {
                bail!("server sent an invalid rotated group token");
            }
            ServerMessage::GroupTokenRotated { kind, token }
        }
        ServerMessage::RoomMembers {
            room_id,
            members,
            offset,
            has_more,
        } => {
            if !is_safe_identifier(&room_id) {
                bail!("server sent an unsafe room identifier");
            }
            ServerMessage::RoomMembers {
                room_id,
                members: members
                    .into_iter()
                    .map(sanitize_room_member)
                    .collect::<Result<Vec<_>>>()?,
                offset,
                has_more,
            }
        }
        ServerMessage::PrivateMessage { message, status } => ServerMessage::PrivateMessage {
            message: sanitize_direct_record(message)?,
            status,
        },
        ServerMessage::MemberJoined { member } => ServerMessage::MemberJoined {
            member: sanitize_peer(member)?,
        },
        ServerMessage::Error { code, message } => {
            if !is_safe_identifier(&code) {
                bail!("server sent an unsafe error code");
            }
            ServerMessage::Error {
                code,
                message: sanitize_status_text(&message)?,
            }
        }
        unchanged @ (ServerMessage::MemberLeft { .. }
        | ServerMessage::PrivateClosed { .. }
        | ServerMessage::Pong) => unchanged,
    })
}

fn sanitize_issued_credentials(
    credentials: IssuedGroupCredentials,
) -> Result<IssuedGroupCredentials> {
    if !is_valid_group_credential(&credentials.admin_token)
        || credentials
            .invite_token
            .as_deref()
            .is_some_and(|token| !is_valid_group_credential(token))
    {
        bail!("server sent invalid group credentials");
    }
    Ok(credentials)
}

fn sanitize_join_request(mut request: JoinRequestSummary) -> Result<JoinRequestSummary> {
    request.nickname = sanitize_nickname(&request.nickname)?;
    Ok(request)
}

fn sanitize_group_member(mut member: GroupMemberSummary) -> Result<GroupMemberSummary> {
    member.nickname = sanitize_nickname(&member.nickname)?;
    Ok(member)
}

fn sanitize_room_member(mut member: RoomMemberSummary) -> Result<RoomMemberSummary> {
    member.nickname = sanitize_nickname(&member.nickname)?;
    Ok(member)
}

fn sanitize_group_summary(mut group: GroupSummary) -> Result<GroupSummary> {
    group.group_name = sanitize_group_name(&group.group_name)?;
    Ok(group)
}

fn sanitize_peer(mut peer: Peer) -> Result<Peer> {
    peer.nickname = sanitize_nickname(&peer.nickname)?;
    if let Some(direct) = &peer.direct
        && (direct.endpoint.port() == 0
            || direct.endpoint.ip().is_unspecified()
            || direct.endpoint.ip().is_multicast()
            || !is_valid_fingerprint(&direct.fingerprint))
    {
        bail!("server sent unsafe peer-to-peer connection details");
    }
    Ok(peer)
}

fn sanitize_chat_record(mut message: ChatRecord) -> Result<ChatRecord> {
    if !is_safe_identifier(&message.room_id) {
        bail!("server sent an unsafe room identifier");
    }
    message.sender = sanitize_peer(message.sender)?;
    message.text = sanitize_chat_text(&message.text)?;
    Ok(message)
}

fn sanitize_direct_record(mut message: DirectRecord) -> Result<DirectRecord> {
    message.sender = sanitize_peer(message.sender)?;
    message.text = sanitize_chat_text(&message.text)?;
    Ok(message)
}

fn sanitize_room_summary(mut room: RoomSummary) -> Result<RoomSummary> {
    if !is_safe_identifier(&room.room_id) {
        bail!("server sent an unsafe room identifier");
    }
    room.room_name = sanitize_room_name(&room.room_name)?;
    Ok(room)
}

pub async fn send_one_message(
    endpoint: SocketAddr,
    nickname: &str,
    expected_fingerprint: Option<&str>,
    text: String,
) -> Result<ChatRecord> {
    let mut connection = connect(endpoint, nickname, expected_fingerprint).await?;
    send_message(&mut connection, text).await
}

pub async fn send_message(connection: &mut ClientConnection, text: String) -> Result<ChatRecord> {
    let message_id = Uuid::new_v4();
    connection
        .outgoing
        .send(ClientMessage::Chat {
            room_id: connection.session.room_id.clone(),
            message_id,
            text,
        })
        .await
        .context("connection closed before the message could be sent")?;

    tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(event) = connection.incoming.recv().await {
            match event {
                ClientEvent::Server(ServerMessage::Chat { message })
                    if message.message_id == message_id =>
                {
                    return Ok(message);
                }
                ClientEvent::Server(ServerMessage::Error { code, message }) => {
                    bail!("server rejected the message ({code}): {message}");
                }
                ClientEvent::Disconnected(reason) => bail!(reason),
                _ => {}
            }
        }
        bail!("connection closed before the server acknowledged the message")
    })
    .await
    .context("timed out waiting for the gateway to persist and echo the message")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{DEFAULT_ROOM_ID, GroupTokenKind, RoomVisibility, ServerMessage},
        server::{GatewayConfig, GatewayHandle, spawn_gateway},
    };
    use std::{
        net::{IpAddr, Ipv4Addr},
        path::Path,
    };

    async fn wait_for_server_message(
        client: &mut ClientConnection,
        mut predicate: impl FnMut(&ServerMessage) -> bool,
    ) -> ServerMessage {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client.incoming.recv().await {
                    Some(ClientEvent::Server(message)) if predicate(&message) => return message,
                    Some(ClientEvent::Disconnected(reason)) => {
                        panic!("client disconnected while waiting for a message: {reason}")
                    }
                    Some(_) => {}
                    None => panic!("client event stream ended"),
                }
            }
        })
        .await
        .expect("timed out waiting for a matching server message")
    }

    async fn test_gateway(data_dir: &Path) -> GatewayHandle {
        spawn_gateway(GatewayConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            gateway_name: "Test gateway".to_owned(),
            advertise: false,
            data_dir: data_dir.to_path_buf(),
        })
        .await
        .unwrap()
    }

    async fn create_test_group(gateway: &GatewayHandle, name: &str) -> (ClientConnection, Uuid) {
        let client = create_group(
            gateway.info.listen_addr,
            "Alice",
            Some(&gateway.info.fingerprint),
            name.to_owned(),
        )
        .await
        .unwrap();
        let group_id = client.session.group_id;
        (client, group_id)
    }

    #[tokio::test]
    async fn encrypted_message_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let (mut client, _) = create_test_group(&gateway, "Test group").await;
        let message_id = Uuid::new_v4();
        client
            .outgoing
            .send(ClientMessage::Chat {
                room_id: DEFAULT_ROOM_ID.to_owned(),
                message_id,
                text: "encrypted hello".to_owned(),
            })
            .await
            .unwrap();

        let echoed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(ClientEvent::Server(ServerMessage::Chat { message })) =
                    client.incoming.recv().await
                    && message.message_id == message_id
                {
                    break message;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(echoed.text, "encrypted hello");
        assert_eq!(echoed.sender.nickname, "Alice");

        drop(client);
        gateway.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn incorrect_server_fingerprint_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let result = inspect_gateway(gateway.info.listen_addr, "Alice", Some("00:00")).await;
        assert!(result.is_err());
        gateway.shutdown().await.unwrap();
    }

    #[test]
    fn remote_terminal_controls_are_removed_before_reaching_the_ui() {
        let message = ServerMessage::Chat {
            message: ChatRecord {
                sequence: 1,
                message_id: Uuid::new_v4(),
                sender: Peer {
                    session_id: Uuid::new_v4(),
                    member_id: Uuid::new_v4(),
                    nickname: "Mallory\u{1b}[31m".to_owned(),
                    direct: None,
                },
                room_id: "general".to_owned(),
                sent_at_ms: 0,
                text: "hello\u{1b}]52;c;payload\u{7}".to_owned(),
            },
        };
        let ServerMessage::Chat { message } = sanitize_server_message(message).unwrap() else {
            panic!("expected chat message");
        };
        assert_eq!(message.sender.nickname, "Mallory[31m");
        assert_eq!(message.text, "hello]52;c;payload");
    }

    #[tokio::test]
    async fn clients_can_create_join_and_chat_in_a_room() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let (mut alice, group_id) = create_test_group(&gateway, "Rooms").await;
        let mut bob = join_group(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
        )
        .await
        .unwrap();

        alice
            .outgoing
            .send(ClientMessage::CreateRoom {
                name: "Rust".to_owned(),
                visibility: RoomVisibility::Public,
            })
            .await
            .unwrap();
        let ServerMessage::RoomJoined { room, .. } = wait_for_server_message(
            &mut alice,
            |message| matches!(message, ServerMessage::RoomJoined { room, .. } if room.room_name == "Rust"),
        )
        .await
        else {
            unreachable!();
        };
        let room_id = room.room_id;
        wait_for_server_message(
            &mut bob,
            |message| matches!(message, ServerMessage::RoomCreated { room } if room.room_id == room_id),
        )
        .await;
        bob.outgoing
            .send(ClientMessage::JoinRoom {
                room_id: room_id.clone(),
            })
            .await
            .unwrap();
        wait_for_server_message(
            &mut bob,
            |message| matches!(message, ServerMessage::RoomJoined { room, .. } if room.room_id == room_id),
        )
        .await;

        let message_id = Uuid::new_v4();
        alice
            .outgoing
            .send(ClientMessage::Chat {
                room_id: room_id.clone(),
                message_id,
                text: "room message".to_owned(),
            })
            .await
            .unwrap();
        let ServerMessage::Chat { message } = wait_for_server_message(
            &mut bob,
            |message| matches!(message, ServerMessage::Chat { message } if message.message_id == message_id),
        )
        .await
        else {
            unreachable!();
        };
        assert_eq!(message.room_id, room_id);
        assert_eq!(message.text, "room message");

        drop(alice);
        drop(bob);
        gateway.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn invite_groups_require_the_issued_token_and_never_store_it_in_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let alice = create_group_with_access(
            gateway.info.listen_addr,
            "Alice",
            Some(&fingerprint),
            "Invite only".to_owned(),
            GroupAccessMode::Invite,
        )
        .await
        .unwrap();
        assert_eq!(alice.session.role, GroupRole::Admin);
        let group_id = alice.session.group_id;
        let issued = alice.session.issued_credentials.clone().unwrap();
        let invite_token = issued.invite_token.clone().unwrap();

        let without_token = join_group(
            gateway.info.listen_addr,
            "Mallory",
            Some(&fingerprint),
            group_id,
        )
        .await;
        let error = match without_token {
            Ok(_) => panic!("invite group accepted a client without a token"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invite_required"));

        let JoinOutcome::Connected(bob) = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
            Some(invite_token.clone()),
        )
        .await
        .unwrap() else {
            panic!("invite token should join immediately");
        };
        assert_eq!(bob.session.role, GroupRole::Member);
        let member_token = bob.session.issued_member_token.clone().unwrap();

        let JoinOutcome::Connected(admin_again) = join_group_with_credential(
            gateway.info.listen_addr,
            "Alice admin",
            Some(&fingerprint),
            group_id,
            Some(issued.admin_token.clone()),
        )
        .await
        .unwrap() else {
            panic!("admin token should join immediately");
        };
        assert_eq!(admin_again.session.role, GroupRole::Admin);

        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let bytes = std::fs::read(entry.path()).unwrap();
                assert!(!contains_bytes(&bytes, invite_token.as_bytes()));
                assert!(!contains_bytes(&bytes, issued.admin_token.as_bytes()));
                assert!(!contains_bytes(&bytes, member_token.as_bytes()));
            }
        }

        drop(alice);
        drop(bob);
        drop(admin_again);
        gateway.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn members_can_rotate_their_own_token_and_other_sessions_are_revoked() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let admin = create_group_with_access(
            gateway.info.listen_addr,
            "Admin",
            Some(&fingerprint),
            "Members".to_owned(),
            GroupAccessMode::Public,
        )
        .await
        .unwrap();
        let group_id = admin.session.group_id;

        let JoinOutcome::Connected(mut bob) = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
            None,
        )
        .await
        .unwrap() else {
            unreachable!();
        };
        let old_member_token = bob.session.issued_member_token.clone().unwrap();
        let JoinOutcome::Connected(mut second_session) = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob second session",
            Some(&fingerprint),
            group_id,
            Some(old_member_token.clone()),
        )
        .await
        .unwrap() else {
            unreachable!();
        };

        bob.outgoing
            .send(ClientMessage::RotateGroupToken {
                kind: GroupTokenKind::Member,
            })
            .await
            .unwrap();
        let ServerMessage::GroupTokenRotated {
            token: new_member_token,
            ..
        } = wait_for_server_message(&mut bob, |message| {
            matches!(
                message,
                ServerMessage::GroupTokenRotated {
                    kind: GroupTokenKind::Member,
                    ..
                }
            )
        })
        .await
        else {
            unreachable!();
        };
        wait_for_server_message(&mut second_session, |message| {
            matches!(message, ServerMessage::Error { code, .. } if code == "session_revoked")
        })
        .await;

        assert!(
            join_group_with_credential(
                gateway.info.listen_addr,
                "Old token",
                Some(&fingerprint),
                group_id,
                Some(old_member_token),
            )
            .await
            .is_err()
        );
        let JoinOutcome::Connected(reconnected) = join_group_with_credential(
            gateway.info.listen_addr,
            "New token",
            Some(&fingerprint),
            group_id,
            Some(new_member_token),
        )
        .await
        .unwrap() else {
            unreachable!();
        };
        assert_eq!(reconnected.session.role, GroupRole::Member);

        drop(admin);
        drop(bob);
        drop(second_session);
        drop(reconnected);
        gateway.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn approval_groups_block_until_an_admin_approves_the_persisted_request() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let mut admin = create_group_with_access(
            gateway.info.listen_addr,
            "Admin",
            Some(&fingerprint),
            "Approval only".to_owned(),
            GroupAccessMode::Approval,
        )
        .await
        .unwrap();
        let group_id = admin.session.group_id;

        let JoinOutcome::Pending(pending) = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
            None,
        )
        .await
        .unwrap() else {
            panic!("first approval join should become pending");
        };

        let JoinOutcome::Pending(still_pending) = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
            Some(pending.request_token.clone()),
        )
        .await
        .unwrap() else {
            panic!("unapproved request token must remain pending");
        };
        assert_eq!(still_pending.request_id, pending.request_id);

        admin
            .outgoing
            .send(ClientMessage::ListJoinRequests)
            .await
            .unwrap();
        let ServerMessage::JoinRequests { requests } =
            wait_for_server_message(&mut admin, |message| {
                matches!(message, ServerMessage::JoinRequests { .. })
            })
            .await
        else {
            unreachable!();
        };
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].request_id, pending.request_id);
        assert_eq!(requests[0].nickname, "Bob");

        admin
            .outgoing
            .send(ClientMessage::DecideJoinRequest {
                request_id: pending.request_id,
                approve: true,
            })
            .await
            .unwrap();
        let ServerMessage::JoinRequests { requests } =
            wait_for_server_message(&mut admin, |message| {
                matches!(message, ServerMessage::JoinRequests { .. })
            })
            .await
        else {
            unreachable!();
        };
        assert!(requests.is_empty());

        let JoinOutcome::Connected(mut bob) = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
            Some(pending.request_token),
        )
        .await
        .unwrap() else {
            panic!("approved request token should join");
        };
        assert_eq!(bob.session.role, GroupRole::Member);
        bob.outgoing
            .send(ClientMessage::ListJoinRequests)
            .await
            .unwrap();
        wait_for_server_message(&mut bob, |message| {
            matches!(message, ServerMessage::Error { code, .. } if code == "admin_required")
        })
        .await;

        drop(admin);
        drop(bob);
        gateway.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn member_bans_and_group_token_rotation_are_enforced_on_reconnect() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let mut admin = create_group_with_access(
            gateway.info.listen_addr,
            "Admin",
            Some(&fingerprint),
            "Moderated".to_owned(),
            GroupAccessMode::Invite,
        )
        .await
        .unwrap();
        let group_id = admin.session.group_id;
        let issued = admin.session.issued_credentials.clone().unwrap();
        let old_admin_token = issued.admin_token;
        let old_invite_token = issued.invite_token.unwrap();

        let JoinOutcome::Connected(mut bob) = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
            Some(old_invite_token.clone()),
        )
        .await
        .unwrap() else {
            panic!("invite should create a persistent member");
        };
        let bob_member_token = bob.session.issued_member_token.clone().unwrap();
        let bob_member_id = bob
            .session
            .members
            .iter()
            .find(|peer| peer.session_id == bob.session.session_id)
            .unwrap()
            .member_id;

        admin
            .outgoing
            .send(ClientMessage::SetMemberBanned {
                member_id: bob_member_id,
                banned: true,
            })
            .await
            .unwrap();
        let ServerMessage::GroupMembers { members, .. } =
            wait_for_server_message(&mut admin, |message| {
                matches!(message, ServerMessage::GroupMembers { .. })
            })
            .await
        else {
            unreachable!();
        };
        assert!(members.iter().any(|member| {
            member.member_id == bob_member_id
                && member.status == crate::protocol::GroupMemberStatus::Banned
        }));
        wait_for_server_message(&mut bob, |message| {
            matches!(message, ServerMessage::Error { code, .. } if code == "member_banned")
        })
        .await;

        let banned_rejoin = join_group_with_credential(
            gateway.info.listen_addr,
            "Bob again",
            Some(&fingerprint),
            group_id,
            Some(bob_member_token),
        )
        .await;
        let error = match banned_rejoin {
            Ok(_) => panic!("banned member token rejoined"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("member_banned"));

        admin
            .outgoing
            .send(ClientMessage::RotateGroupToken {
                kind: GroupTokenKind::Invite,
            })
            .await
            .unwrap();
        let ServerMessage::GroupTokenRotated {
            token: new_invite_token,
            ..
        } = wait_for_server_message(&mut admin, |message| {
            matches!(
                message,
                ServerMessage::GroupTokenRotated {
                    kind: GroupTokenKind::Invite,
                    ..
                }
            )
        })
        .await
        else {
            unreachable!();
        };
        assert!(
            join_group_with_credential(
                gateway.info.listen_addr,
                "Old invite",
                Some(&fingerprint),
                group_id,
                Some(old_invite_token),
            )
            .await
            .is_err()
        );
        assert!(matches!(
            join_group_with_credential(
                gateway.info.listen_addr,
                "New invite",
                Some(&fingerprint),
                group_id,
                Some(new_invite_token),
            )
            .await
            .unwrap(),
            JoinOutcome::Connected(_)
        ));

        admin
            .outgoing
            .send(ClientMessage::RotateGroupToken {
                kind: GroupTokenKind::Admin,
            })
            .await
            .unwrap();
        let ServerMessage::GroupTokenRotated {
            token: new_admin_token,
            ..
        } = wait_for_server_message(&mut admin, |message| {
            matches!(
                message,
                ServerMessage::GroupTokenRotated {
                    kind: GroupTokenKind::Admin,
                    ..
                }
            )
        })
        .await
        else {
            unreachable!();
        };
        assert!(
            join_group_with_credential(
                gateway.info.listen_addr,
                "Old admin",
                Some(&fingerprint),
                group_id,
                Some(old_admin_token),
            )
            .await
            .is_err()
        );
        let JoinOutcome::Connected(new_admin) = join_group_with_credential(
            gateway.info.listen_addr,
            "New admin",
            Some(&fingerprint),
            group_id,
            Some(new_admin_token),
        )
        .await
        .unwrap() else {
            panic!("rotated admin token did not work");
        };
        assert_eq!(new_admin.session.role, GroupRole::Admin);

        drop(admin);
        drop(bob);
        drop(new_admin);
        gateway.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn private_rooms_are_hidden_and_enforce_persistent_membership() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let (mut admin, group_id) = create_test_group(&gateway, "Private rooms").await;
        let mut bob = join_group(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
        )
        .await
        .unwrap();
        let mut carol = join_group(
            gateway.info.listen_addr,
            "Carol",
            Some(&fingerprint),
            group_id,
        )
        .await
        .unwrap();
        let carol_member_id = carol
            .session
            .members
            .iter()
            .find(|peer| peer.session_id == carol.session.session_id)
            .unwrap()
            .member_id;

        bob.outgoing
            .send(ClientMessage::CreateRoom {
                name: "Secret".to_owned(),
                visibility: RoomVisibility::Private,
            })
            .await
            .unwrap();
        let ServerMessage::RoomJoined { room, .. } = wait_for_server_message(
            &mut bob,
            |message| matches!(message, ServerMessage::RoomJoined { room, .. } if room.room_name == "Secret"),
        )
        .await
        else {
            unreachable!();
        };
        let room_id = room.room_id;
        wait_for_server_message(&mut admin, |message| {
            matches!(message, ServerMessage::RoomCreated { room } if room.room_id == room_id)
        })
        .await;
        admin
            .outgoing
            .send(ClientMessage::JoinRoom {
                room_id: room_id.clone(),
            })
            .await
            .unwrap();
        wait_for_server_message(&mut admin, |message| {
            matches!(message, ServerMessage::RoomJoined { room, .. } if room.room_id == room_id)
        })
        .await;

        carol
            .outgoing
            .send(ClientMessage::JoinRoom {
                room_id: room_id.clone(),
            })
            .await
            .unwrap();
        wait_for_server_message(&mut carol, |message| {
            matches!(message, ServerMessage::Error { code, .. } if code == "private_room_denied")
        })
        .await;

        bob.outgoing
            .send(ClientMessage::SetRoomMember {
                room_id: room_id.clone(),
                member_id: carol_member_id,
                included: true,
            })
            .await
            .unwrap();
        wait_for_server_message(&mut carol, |message| {
            matches!(message, ServerMessage::RoomCreated { room } if room.room_id == room_id)
        })
        .await;
        carol
            .outgoing
            .send(ClientMessage::JoinRoom {
                room_id: room_id.clone(),
            })
            .await
            .unwrap();
        wait_for_server_message(&mut carol, |message| {
            matches!(message, ServerMessage::RoomJoined { room, .. } if room.room_id == room_id)
        })
        .await;

        let message_id = Uuid::new_v4();
        bob.outgoing
            .send(ClientMessage::Chat {
                room_id: room_id.clone(),
                message_id,
                text: "private history".to_owned(),
            })
            .await
            .unwrap();
        wait_for_server_message(&mut carol, |message| {
            matches!(message, ServerMessage::Chat { message } if message.message_id == message_id)
        })
        .await;

        bob.outgoing
            .send(ClientMessage::SetRoomMember {
                room_id: room_id.clone(),
                member_id: carol_member_id,
                included: false,
            })
            .await
            .unwrap();
        wait_for_server_message(&mut carol, |message| {
            matches!(message, ServerMessage::RoomLeft { room_id: removed } if removed == &room_id)
        })
        .await;
        carol
            .outgoing
            .send(ClientMessage::JoinRoom {
                room_id: room_id.clone(),
            })
            .await
            .unwrap();
        wait_for_server_message(&mut carol, |message| {
            matches!(message, ServerMessage::Error { code, .. } if code == "private_room_denied")
        })
        .await;

        drop(admin);
        drop(bob);
        drop(carol);
        gateway.shutdown().await.unwrap();
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[tokio::test]
    async fn gateway_restart_restores_rooms_and_encrypted_history() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let (mut alice, group_id) = create_test_group(&gateway, "Durable").await;
        let message_id = Uuid::new_v4();
        alice
            .outgoing
            .send(ClientMessage::Chat {
                room_id: DEFAULT_ROOM_ID.to_owned(),
                message_id,
                text: "survives every client uninstall".to_owned(),
            })
            .await
            .unwrap();
        wait_for_server_message(
            &mut alice,
            |message| matches!(message, ServerMessage::Chat { message } if message.message_id == message_id),
        )
        .await;
        drop(alice);
        let old_gateway_id = gateway.info.gateway_id;
        let old_fingerprint = gateway.info.fingerprint.clone();
        gateway.shutdown().await.unwrap();

        let restarted = test_gateway(directory.path()).await;
        assert_eq!(restarted.info.gateway_id, old_gateway_id);
        assert_eq!(restarted.info.fingerprint, old_fingerprint);
        let restored = join_group(
            restarted.info.listen_addr,
            "Alice after reinstall",
            Some(&old_fingerprint),
            group_id,
        )
        .await
        .unwrap();
        assert_eq!(restored.session.history.len(), 1);
        assert_eq!(
            restored.session.history[0].text,
            "survives every client uninstall"
        );
        restarted.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn private_chat_is_direct_and_requires_one_reply() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let (mut alice, group_id) = create_test_group(&gateway, "Direct messages").await;
        let mut bob = join_group(
            gateway.info.listen_addr,
            "Bob",
            Some(&fingerprint),
            group_id,
        )
        .await
        .unwrap();
        let alice_id = alice.session.session_id;
        let bob_id = bob.session.session_id;
        wait_for_server_message(&mut alice, |message| {
            matches!(message, ServerMessage::MemberJoined { member } if member.session_id == bob_id)
        })
        .await;

        let opening_id = Uuid::new_v4();
        alice
            .outgoing
            .send(ClientMessage::PrivateChat {
                peer_session_id: bob_id,
                message_id: opening_id,
                text: "Can we chat directly?".to_owned(),
            })
            .await
            .unwrap();
        for client in [&mut alice, &mut bob] {
            wait_for_server_message(client, |message| {
                matches!(
                    message,
                    ServerMessage::PrivateMessage {
                        message,
                        status: crate::protocol::PrivateConversationStatus::AwaitingReply {
                            initiator_session_id,
                        },
                    } if message.message_id == opening_id && *initiator_session_id == alice_id
                )
            })
            .await;
        }

        alice
            .outgoing
            .send(ClientMessage::PrivateChat {
                peer_session_id: bob_id,
                message_id: Uuid::new_v4(),
                text: "This must be blocked".to_owned(),
            })
            .await
            .unwrap();
        wait_for_server_message(&mut alice, |message| {
            matches!(message, ServerMessage::Error { code, .. } if code == "private_waiting_for_reply")
        })
        .await;

        let reply_id = Uuid::new_v4();
        bob.outgoing
            .send(ClientMessage::PrivateChat {
                peer_session_id: alice_id,
                message_id: reply_id,
                text: "Yes".to_owned(),
            })
            .await
            .unwrap();
        for client in [&mut alice, &mut bob] {
            wait_for_server_message(client, |message| {
                matches!(
                    message,
                    ServerMessage::PrivateMessage {
                        message,
                        status: crate::protocol::PrivateConversationStatus::Active,
                    } if message.message_id == reply_id
                )
            })
            .await;
        }

        let unlocked_id = Uuid::new_v4();
        alice
            .outgoing
            .send(ClientMessage::PrivateChat {
                peer_session_id: bob_id,
                message_id: unlocked_id,
                text: "Now unlocked".to_owned(),
            })
            .await
            .unwrap();
        wait_for_server_message(&mut bob, |message| {
            matches!(
                message,
                ServerMessage::PrivateMessage {
                    message,
                    status: crate::protocol::PrivateConversationStatus::Active,
                } if message.message_id == unlocked_id
            )
        })
        .await;

        drop((alice, bob));
        gateway.shutdown().await.unwrap();
        let restarted = test_gateway(directory.path()).await;
        let restored = join_group(
            restarted.info.listen_addr,
            "History checker",
            Some(&fingerprint),
            group_id,
        )
        .await
        .unwrap();
        assert!(restored.session.history.is_empty());
        restarted.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn older_group_history_is_available_in_bounded_pages() {
        let directory = tempfile::tempdir().unwrap();
        let gateway = test_gateway(directory.path()).await;
        let fingerprint = gateway.info.fingerprint.clone();
        let (mut alice, group_id) = create_test_group(&gateway, "Long history").await;
        for index in 0..20 {
            send_message(
                &mut alice,
                format!("message {index:02} {}", "x".repeat(700)),
            )
            .await
            .unwrap();
        }
        let mut restored = join_group(
            gateway.info.listen_addr,
            "Fresh install",
            Some(&fingerprint),
            group_id,
        )
        .await
        .unwrap();
        assert!(restored.session.history.len() < 20);
        let first_sequence = restored.session.history[0].sequence;
        assert!(first_sequence > 1);
        restored
            .outgoing
            .send(ClientMessage::LoadHistory {
                room_id: DEFAULT_ROOM_ID.to_owned(),
                before_sequence: first_sequence,
                limit: 100,
            })
            .await
            .unwrap();
        let ServerMessage::HistoryPage { messages, .. } =
            wait_for_server_message(&mut restored, |message| {
                matches!(message, ServerMessage::HistoryPage { .. })
            })
            .await
        else {
            unreachable!();
        };
        assert!(!messages.is_empty());
        assert!(messages.last().unwrap().sequence < first_sequence);
        gateway.shutdown().await.unwrap();
    }
}
