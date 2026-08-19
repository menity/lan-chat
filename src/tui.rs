use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    io::{self, Stdout},
    net::SocketAddr,
    time::Duration,
};

use anyhow::{Context, Result};
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures_util::StreamExt;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use tokio::sync::mpsc;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use uuid::Uuid;

use crate::{
    client::{self, ClientConnection, ClientEvent, SessionInfo},
    credentials::CredentialStore,
    discovery::{self, DiscoveredGateway},
    protocol::{
        ChatRecord, ClientMessage, DirectRecord, GroupAccessMode, GroupMemberStatus,
        GroupMemberSummary, GroupRole, GroupTokenKind, IssuedGroupCredentials, JoinRequestSummary,
        Peer, PrivateConversationStatus, RoomMemberSummary, RoomSummary, RoomVisibility,
        ServerMessage,
    },
    security::{
        MAX_MESSAGE_BYTES, sanitize_group_credential, sanitize_group_name, sanitize_nickname,
        sanitize_paste_for_input, sanitize_room_name,
    },
};

const MAX_UI_ITEMS: usize = 1000;
const DISCOVERY_DURATION: Duration = Duration::from_secs(2);
const MEMBER_PAGE_SIZE: u32 = 40;
const ACCESS_MODES: [GroupAccessMode; 3] = [
    GroupAccessMode::Public,
    GroupAccessMode::Invite,
    GroupAccessMode::Approval,
];

pub enum LobbyAction {
    Quit,
    Join {
        endpoint: SocketAddr,
        fingerprint: Option<String>,
        gateway_id: Option<Uuid>,
        group_id: Option<Uuid>,
        credential: Option<String>,
    },
    Create {
        group_name: String,
        access_mode: GroupAccessMode,
        endpoint: SocketAddr,
        fingerprint: String,
    },
    SetNickname(String),
    ForgetCredential {
        gateway_id: Uuid,
        group_id: Uuid,
    },
}

pub enum ChatAction {
    BackToLobby,
    QuitApplication,
}

pub async fn run_lobby(
    nickname: &str,
    initial_status: Option<&str>,
    known_credentials: &[(Uuid, Uuid)],
) -> Result<LobbyAction> {
    let mut terminal = TerminalGuard::new()?;
    let mut events = EventStream::new();
    let (discovery_tx, mut discovery_rx) = mpsc::channel(1);
    let mut refresh_interval = tokio::time::interval(Duration::from_secs(4));
    refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut app = LobbyApp::new(nickname, initial_status, known_credentials);
    start_discovery(nickname.to_owned(), discovery_tx.clone());
    app.refreshing = true;

    loop {
        terminal.draw(|frame| render_lobby(frame, &app))?;
        tokio::select! {
            terminal_event = events.next() => {
                match terminal_event {
                    Some(Ok(Event::Key(key))) if key.kind != KeyEventKind::Release => {
                        if let Some(action) = app.handle_key(key)? {
                            return Ok(action);
                        }
                        if app.refresh_requested {
                            app.refresh_requested = false;
                            if !app.refreshing {
                                app.refreshing = true;
                                app.status = "Refreshing LAN groups…".to_owned();
                                start_discovery(app.nickname.clone(), discovery_tx.clone());
                            }
                        }
                    }
                    Some(Ok(Event::Paste(text))) => app.paste(&text),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => app.status = format!("Terminal input error: {error}"),
                    None => return Ok(LobbyAction::Quit),
                }
            }
            discovered = discovery_rx.recv() => {
                if let Some(discovered) = discovered {
                    app.refreshing = false;
                    match discovered {
                        Ok(result) => app.set_discovery(result),
                        Err(error) => app.status = error,
                    }
                }
            }
            _ = refresh_interval.tick() => {
                if !app.refreshing {
                    app.refreshing = true;
                    app.status = "Refreshing LAN groups…".to_owned();
                    start_discovery(app.nickname.clone(), discovery_tx.clone());
                }
            }
        }
    }
}

struct LobbyGroup {
    gateway_id: Uuid,
    group_id: Uuid,
    group_name: String,
    access_mode: GroupAccessMode,
    gateway_name: String,
    endpoint: SocketAddr,
    server_fingerprint: String,
}

struct LobbyDiscovery {
    gateways: Vec<DiscoveredGateway>,
    groups: Vec<LobbyGroup>,
}

type DiscoveryResult = std::result::Result<LobbyDiscovery, String>;

fn start_discovery(nickname: String, sender: mpsc::Sender<DiscoveryResult>) {
    tokio::spawn(async move {
        let result = async {
            let gateways = discovery::discover(DISCOVERY_DURATION).await?;
            let mut groups = Vec::new();
            for gateway in &gateways {
                let snapshot = match client::inspect_gateway(
                    gateway.endpoint,
                    &nickname,
                    Some(&gateway.server_fingerprint),
                )
                .await
                {
                    Ok(snapshot) => snapshot,
                    Err(_) => continue,
                };
                for group in snapshot.groups {
                    groups.push(LobbyGroup {
                        gateway_id: snapshot.gateway_id,
                        group_id: group.group_id,
                        group_name: group.group_name,
                        access_mode: group.access_mode,
                        gateway_name: snapshot.gateway_name.clone(),
                        endpoint: gateway.endpoint,
                        server_fingerprint: gateway.server_fingerprint.clone(),
                    });
                }
            }
            groups.sort_by(|left, right| {
                left.group_name
                    .cmp(&right.group_name)
                    .then_with(|| left.gateway_name.cmp(&right.gateway_name))
            });
            Ok::<_, anyhow::Error>(LobbyDiscovery { gateways, groups })
        }
        .await
        .map_err(|error| format!("Discovery failed: {error:#}"));
        let _ = sender.send(result).await;
    });
}

enum LobbyMode {
    Browse,
    Input {
        kind: LobbyInputKind,
        value: String,
    },
    ChooseAccess {
        group_name: String,
        endpoint: SocketAddr,
        fingerprint: String,
        selected: usize,
    },
    InviteToken {
        group_index: usize,
        value: String,
    },
    ConfirmForget {
        group_index: usize,
    },
}

#[derive(Clone, Copy)]
enum LobbyInputKind {
    CreateGroup,
    DirectJoin,
    Nickname,
}

struct LobbyApp {
    nickname: String,
    gateways: Vec<DiscoveredGateway>,
    groups: Vec<LobbyGroup>,
    selected: usize,
    mode: LobbyMode,
    status: String,
    refreshing: bool,
    refresh_requested: bool,
    known_credentials: HashSet<(Uuid, Uuid)>,
}

impl LobbyApp {
    fn new(
        nickname: &str,
        initial_status: Option<&str>,
        known_credentials: &[(Uuid, Uuid)],
    ) -> Self {
        Self {
            nickname: nickname.to_owned(),
            gateways: Vec::new(),
            groups: Vec::new(),
            selected: 0,
            mode: LobbyMode::Browse,
            status: initial_status
                .unwrap_or("Discovering groups on your LAN…")
                .to_owned(),
            refreshing: false,
            refresh_requested: false,
            known_credentials: known_credentials.iter().copied().collect(),
        }
    }

    fn set_discovery(&mut self, discovery: LobbyDiscovery) {
        self.gateways = discovery.gateways;
        self.groups = discovery.groups;
        self.selected = self.selected.min(self.groups.len().saturating_sub(1));
        self.status = if self.groups.is_empty() {
            if self.gateways.is_empty() {
                "No gateway found — start `lan-chat gateway` on an always-on device".to_owned()
            } else {
                format!(
                    "Found {} gateway(s), but no groups — press C to create one",
                    self.gateways.len()
                )
            }
        } else {
            format!("Found {} group(s)", self.groups.len())
        };
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<Option<LobbyAction>> {
        match &mut self.mode {
            LobbyMode::Browse => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => Ok(Some(LobbyAction::Quit)),
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected = self.selected.saturating_sub(1);
                    Ok(None)
                }
                KeyCode::Down => {
                    self.selected = (self.selected + 1).min(self.groups.len().saturating_sub(1));
                    Ok(None)
                }
                KeyCode::Enter if !self.groups.is_empty() => {
                    let group = &self.groups[self.selected];
                    if group.access_mode == GroupAccessMode::Invite
                        && !self
                            .known_credentials
                            .contains(&(group.gateway_id, group.group_id))
                    {
                        self.mode = LobbyMode::InviteToken {
                            group_index: self.selected,
                            value: String::new(),
                        };
                        self.status = "Paste the group's invite token".to_owned();
                        return Ok(None);
                    }
                    Ok(Some(LobbyAction::Join {
                        endpoint: group.endpoint,
                        fingerprint: Some(group.server_fingerprint.clone()),
                        gateway_id: Some(group.gateway_id),
                        group_id: Some(group.group_id),
                        credential: None,
                    }))
                }
                KeyCode::Char('c') | KeyCode::Char('C') => {
                    if self.gateways.is_empty() {
                        self.status =
                            "No gateway available — run `lan-chat gateway` first".to_owned();
                        return Ok(None);
                    }
                    self.mode = LobbyMode::Input {
                        kind: LobbyInputKind::CreateGroup,
                        value: String::new(),
                    };
                    Ok(None)
                }
                KeyCode::Char('j') | KeyCode::Char('J') => {
                    self.mode = LobbyMode::Input {
                        kind: LobbyInputKind::DirectJoin,
                        value: String::new(),
                    };
                    Ok(None)
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.mode = LobbyMode::Input {
                        kind: LobbyInputKind::Nickname,
                        value: self.nickname.clone(),
                    };
                    Ok(None)
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    self.refresh_requested = true;
                    Ok(None)
                }
                KeyCode::Char('x') | KeyCode::Char('X') if !self.groups.is_empty() => {
                    let group = &self.groups[self.selected];
                    if self
                        .known_credentials
                        .contains(&(group.gateway_id, group.group_id))
                    {
                        self.mode = LobbyMode::ConfirmForget {
                            group_index: self.selected,
                        };
                        self.status =
                            "Confirm before deleting this local bearer credential".to_owned();
                        Ok(None)
                    } else {
                        self.status = "No saved credential for this group".to_owned();
                        Ok(None)
                    }
                }
                _ => Ok(None),
            },
            LobbyMode::Input { kind, value } => match key.code {
                KeyCode::Esc => {
                    self.mode = LobbyMode::Browse;
                    self.status = "Cancelled".to_owned();
                    Ok(None)
                }
                KeyCode::Backspace => {
                    value.pop();
                    Ok(None)
                }
                KeyCode::Enter => {
                    let value = value.clone();
                    match kind {
                        LobbyInputKind::CreateGroup => match sanitize_group_name(&value) {
                            Ok(group_name) => {
                                let gateway = self
                                    .groups
                                    .get(self.selected)
                                    .map(|group| (group.endpoint, group.server_fingerprint.clone()))
                                    .or_else(|| {
                                        self.gateways.first().map(|gateway| {
                                            (gateway.endpoint, gateway.server_fingerprint.clone())
                                        })
                                    });
                                let Some((endpoint, fingerprint)) = gateway else {
                                    self.status = "No gateway available".to_owned();
                                    return Ok(None);
                                };
                                self.mode = LobbyMode::ChooseAccess {
                                    group_name,
                                    endpoint,
                                    fingerprint,
                                    selected: 0,
                                };
                                self.status = "Choose how people may join the group".to_owned();
                                Ok(None)
                            }
                            Err(error) => {
                                self.status = error.to_string();
                                Ok(None)
                            }
                        },
                        LobbyInputKind::DirectJoin => match value.parse::<SocketAddr>() {
                            Ok(endpoint) => Ok(Some(LobbyAction::Join {
                                endpoint,
                                fingerprint: None,
                                gateway_id: None,
                                group_id: None,
                                credential: None,
                            })),
                            Err(_) => {
                                self.status =
                                    "Enter an address such as 192.168.1.20:7373".to_owned();
                                Ok(None)
                            }
                        },
                        LobbyInputKind::Nickname => match sanitize_nickname(&value) {
                            Ok(nickname) => Ok(Some(LobbyAction::SetNickname(nickname))),
                            Err(error) => {
                                self.status = error.to_string();
                                Ok(None)
                            }
                        },
                    }
                }
                KeyCode::Char(ch)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !ch.is_control()
                        && value.len().saturating_add(ch.len_utf8()) <= 128 =>
                {
                    value.push(ch);
                    Ok(None)
                }
                _ => Ok(None),
            },
            LobbyMode::ChooseAccess {
                group_name,
                endpoint,
                fingerprint,
                selected,
            } => match key.code {
                KeyCode::Esc => {
                    self.mode = LobbyMode::Browse;
                    self.status = "Cancelled".to_owned();
                    Ok(None)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    *selected = selected.saturating_sub(1);
                    Ok(None)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    *selected = (*selected + 1).min(ACCESS_MODES.len() - 1);
                    Ok(None)
                }
                KeyCode::Char('1') => {
                    *selected = 0;
                    Ok(None)
                }
                KeyCode::Char('2') => {
                    *selected = 1;
                    Ok(None)
                }
                KeyCode::Char('3') => {
                    *selected = 2;
                    Ok(None)
                }
                KeyCode::Enter => Ok(Some(LobbyAction::Create {
                    group_name: group_name.clone(),
                    access_mode: ACCESS_MODES[*selected],
                    endpoint: *endpoint,
                    fingerprint: fingerprint.clone(),
                })),
                _ => Ok(None),
            },
            LobbyMode::InviteToken { group_index, value } => match key.code {
                KeyCode::Esc => {
                    self.mode = LobbyMode::Browse;
                    self.status = "Cancelled".to_owned();
                    Ok(None)
                }
                KeyCode::Backspace => {
                    value.pop();
                    Ok(None)
                }
                KeyCode::Enter => match sanitize_group_credential(value) {
                    Ok(credential) => {
                        let group = &self.groups[*group_index];
                        Ok(Some(LobbyAction::Join {
                            endpoint: group.endpoint,
                            fingerprint: Some(group.server_fingerprint.clone()),
                            gateway_id: Some(group.gateway_id),
                            group_id: Some(group.group_id),
                            credential: Some(credential),
                        }))
                    }
                    Err(error) => {
                        self.status = error.to_string();
                        Ok(None)
                    }
                },
                KeyCode::Char(ch)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && (ch.is_ascii_alphanumeric() || ch == '_') =>
                {
                    if value.len().saturating_add(ch.len_utf8()) <= 128 {
                        value.push(ch);
                    }
                    Ok(None)
                }
                _ => Ok(None),
            },
            LobbyMode::ConfirmForget { group_index } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let group = &self.groups[*group_index];
                    Ok(Some(LobbyAction::ForgetCredential {
                        gateway_id: group.gateway_id,
                        group_id: group.group_id,
                    }))
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.mode = LobbyMode::Browse;
                    self.status = "Credential kept".to_owned();
                    Ok(None)
                }
                _ => Ok(None),
            },
        }
    }

    fn paste(&mut self, raw: &str) {
        match &mut self.mode {
            LobbyMode::Input { value, .. } => {
                let pasted = sanitize_paste_for_input(raw);
                let remaining = 128usize.saturating_sub(value.len());
                value.extend(pasted.chars().take(remaining));
            }
            LobbyMode::InviteToken { value, .. } => {
                let pasted: String = raw
                    .trim()
                    .chars()
                    .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                    .collect();
                let remaining = 128usize.saturating_sub(value.len());
                value.extend(pasted.chars().take(remaining));
            }
            LobbyMode::Browse
            | LobbyMode::ChooseAccess { .. }
            | LobbyMode::ConfirmForget { .. } => {}
        }
    }
}

pub async fn run_chat(
    mut connection: ClientConnection,
    credentials: &mut CredentialStore,
) -> Result<ChatAction> {
    let mut terminal = TerminalGuard::new()?;
    let mut events = EventStream::new();
    let mut app = ChatApp::new(&connection.session);

    loop {
        terminal.draw(|frame| render_chat_app(frame, &app))?;
        tokio::select! {
            terminal_event = events.next() => {
                match terminal_event {
                    Some(Ok(Event::Key(key))) if key.kind != KeyEventKind::Release => {
                        match app.handle_key(key)? {
                            ChatKeyAction::None => {}
                            ChatKeyAction::Back => return Ok(ChatAction::BackToLobby),
                            ChatKeyAction::Quit => return Ok(ChatAction::QuitApplication),
                            ChatKeyAction::Send(message) => {
                                match connection.outgoing.try_send(message) {
                                    Ok(()) => {
                                        app.input.clear();
                                        app.status = "Sent".to_owned();
                                    }
                                    Err(error) => app.status = format!("Cannot send: {error}"),
                                }
                            }
                        }
                    }
                    Some(Ok(Event::Paste(text))) => app.paste(&text),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => app.status = format!("Terminal input error: {error}"),
                    None => return Ok(ChatAction::BackToLobby),
                }
            }
            incoming = connection.incoming.recv() => {
                match incoming {
                    Some(event) => {
                        if let ClientEvent::Server(ServerMessage::GroupTokenRotated { kind, token }) = &event {
                            persist_rotated_token(credentials, &connection.session, *kind, token)?;
                        }
                        app.handle_server_event(event)
                    },
                    None => {
                        app.connected = false;
                        app.status = "Connection closed — Esc returns to groups".to_owned();
                    }
                }
            }
        }
    }
}

fn persist_rotated_token(
    credentials: &mut CredentialStore,
    session: &SessionInfo,
    kind: GroupTokenKind,
    token: &str,
) -> Result<()> {
    let existing = credentials
        .get(session.gateway_id, session.group_id)
        .cloned()
        .context("rotated token arrived without a saved group credential")?;
    let (join_token, invite_token) = match kind {
        GroupTokenKind::Member | GroupTokenKind::Admin => (token.to_owned(), existing.invite_token),
        GroupTokenKind::Invite => (existing.join_token, Some(token.to_owned())),
    };
    credentials
        .set(
            session.gateway_id,
            session.group_id,
            join_token,
            invite_token,
        )
        .with_context(|| format!("rotated token could not be saved; copy this token now: {token}"))
}

#[derive(Clone, PartialEq, Eq)]
enum ConversationTarget {
    Room(String),
    Private(Uuid),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChatFocus {
    Input,
    Conversations,
    Members,
}

enum ChatOverlay {
    CreateRoom {
        name: String,
        visibility: RoomVisibility,
    },
    JoinRequests {
        requests: Vec<JoinRequestSummary>,
        selected: usize,
        loading: bool,
    },
    IssuedCredentials(IssuedGroupCredentials),
    GroupMembers {
        members: Vec<GroupMemberSummary>,
        selected: usize,
        loading: bool,
        offset: u32,
        has_more: bool,
    },
    RoomMembers {
        room_id: String,
        members: Vec<RoomMemberSummary>,
        selected: usize,
        loading: bool,
        offset: u32,
        has_more: bool,
    },
    RotateTokens {
        selected: usize,
        confirming: bool,
    },
    RotatedToken {
        kind: GroupTokenKind,
        token: String,
    },
}

enum ChatKeyAction {
    None,
    Send(ClientMessage),
    Back,
    Quit,
}

enum UiItem {
    Chat(ChatRecord),
    Notice(String),
}

struct RoomView {
    summary: RoomSummary,
    joined: bool,
    items: VecDeque<UiItem>,
    unread: usize,
    has_more_history: bool,
    loading_history: bool,
}

struct PrivateView {
    peer: Peer,
    items: VecDeque<DirectRecord>,
    status: Option<PrivateConversationStatus>,
    unread: usize,
    online: bool,
}

struct ChatApp {
    group_name: String,
    access_mode: GroupAccessMode,
    role: GroupRole,
    session_id: Uuid,
    member_id: Uuid,
    endpoint: String,
    fingerprint: String,
    protocol_version: u16,
    rooms: BTreeMap<String, RoomView>,
    private_chats: BTreeMap<Uuid, PrivateView>,
    members: BTreeMap<Uuid, String>,
    active: ConversationTarget,
    selected_conversation: usize,
    selected_member: usize,
    focus: ChatFocus,
    overlay: Option<ChatOverlay>,
    input: String,
    status: String,
    scroll_from_bottom: usize,
    connected: bool,
    focus_mode: bool,
}

impl ChatApp {
    fn new(session: &SessionInfo) -> Self {
        let member_id = session
            .members
            .iter()
            .find(|member| member.session_id == session.session_id)
            .map(|member| member.member_id)
            .unwrap_or_else(Uuid::nil);
        let members = session
            .members
            .iter()
            .map(|member| (member.session_id, member.nickname.clone()))
            .collect();
        let mut rooms = BTreeMap::new();
        for summary in &session.rooms {
            rooms.insert(
                summary.room_id.clone(),
                RoomView {
                    summary: summary.clone(),
                    joined: summary.room_id == session.room_id,
                    items: VecDeque::new(),
                    unread: 0,
                    has_more_history: false,
                    loading_history: false,
                },
            );
        }
        let room = rooms.entry(session.room_id.clone()).or_insert(RoomView {
            summary: RoomSummary {
                room_id: session.room_id.clone(),
                room_name: session.room_name.clone(),
                visibility: RoomVisibility::Public,
            },
            joined: true,
            items: VecDeque::new(),
            unread: 0,
            has_more_history: false,
            loading_history: false,
        });
        for message in &session.history {
            room.items.push_back(UiItem::Chat(message.clone()));
        }
        room.has_more_history = session
            .history
            .first()
            .is_some_and(|message| message.sequence > 1);
        let mut app = Self {
            group_name: session.group_name.clone(),
            access_mode: session.access_mode,
            role: session.role,
            session_id: session.session_id,
            member_id,
            endpoint: session.endpoint.to_string(),
            fingerprint: session.server_fingerprint.clone(),
            protocol_version: session.protocol_version,
            rooms,
            private_chats: BTreeMap::new(),
            members,
            active: ConversationTarget::Room(session.room_id.clone()),
            selected_conversation: 0,
            selected_member: 0,
            focus: ChatFocus::Input,
            overlay: session
                .issued_credentials
                .clone()
                .map(ChatOverlay::IssuedCredentials),
            input: String::new(),
            status: "Encrypted connection established".to_owned(),
            scroll_from_bottom: 0,
            connected: true,
            focus_mode: false,
        };
        app.sync_conversation_selection();
        app
    }

    fn handle_server_event(&mut self, event: ClientEvent) {
        match event {
            ClientEvent::Server(ServerMessage::Chat { message }) => {
                let room_id = message.room_id.clone();
                if let Some(room) = self.rooms.get_mut(&room_id) {
                    if self.active != ConversationTarget::Room(room_id.clone()) {
                        room.unread += 1;
                    }
                    push_bounded(&mut room.items, UiItem::Chat(message));
                }
            }
            ClientEvent::Server(ServerMessage::RoomCreated { room }) => {
                self.rooms.entry(room.room_id.clone()).or_insert(RoomView {
                    summary: room,
                    joined: false,
                    items: VecDeque::new(),
                    unread: 0,
                    has_more_history: false,
                    loading_history: false,
                });
                if self.focus != ChatFocus::Conversations {
                    self.sync_conversation_selection();
                }
                self.status = "A room was added — select it and press Enter to join".to_owned();
            }
            ClientEvent::Server(ServerMessage::RoomJoined { room, history }) => {
                let room_id = room.room_id.clone();
                let view = self.rooms.entry(room_id.clone()).or_insert(RoomView {
                    summary: room.clone(),
                    joined: true,
                    items: VecDeque::new(),
                    unread: 0,
                    has_more_history: false,
                    loading_history: false,
                });
                view.summary = room;
                view.joined = true;
                view.unread = 0;
                view.items = history.into_iter().map(UiItem::Chat).collect();
                view.has_more_history = view
                    .items
                    .iter()
                    .find_map(|item| match item {
                        UiItem::Chat(message) => Some(message.sequence > 1),
                        UiItem::Notice(_) => None,
                    })
                    .unwrap_or(false);
                view.loading_history = false;
                self.active = ConversationTarget::Room(room_id);
                self.sync_conversation_selection();
                self.focus = ChatFocus::Input;
                self.status = "Joined room".to_owned();
            }
            ClientEvent::Server(ServerMessage::RoomLeft { room_id }) => {
                let private = self
                    .rooms
                    .get(&room_id)
                    .is_some_and(|room| room.summary.visibility == RoomVisibility::Private);
                if self.active == ConversationTarget::Room(room_id.clone()) {
                    self.active = ConversationTarget::Room("general".to_owned());
                }
                if private {
                    self.rooms.remove(&room_id);
                    self.status = "Private room access was removed".to_owned();
                } else {
                    if let Some(room) = self.rooms.get_mut(&room_id) {
                        room.joined = false;
                    }
                    self.status = "Left room".to_owned();
                }
            }
            ClientEvent::Server(ServerMessage::HistoryPage {
                room_id,
                messages,
                has_more,
            }) => {
                if let Some(room) = self.rooms.get_mut(&room_id) {
                    let existing: std::collections::HashSet<_> = room
                        .items
                        .iter()
                        .filter_map(|item| match item {
                            UiItem::Chat(message) => Some(message.message_id),
                            UiItem::Notice(_) => None,
                        })
                        .collect();
                    let added = messages.len();
                    for message in messages.into_iter().rev() {
                        if !existing.contains(&message.message_id) {
                            room.items.push_front(UiItem::Chat(message));
                        }
                    }
                    room.has_more_history = has_more;
                    room.loading_history = false;
                    self.scroll_from_bottom = self.scroll_from_bottom.saturating_add(added);
                    self.status = if added == 0 {
                        "Reached the beginning of room history".to_owned()
                    } else {
                        format!("Loaded {added} older message(s) from the gateway")
                    };
                }
            }
            ClientEvent::Server(ServerMessage::JoinRequests { requests }) => {
                let selected = match &self.overlay {
                    Some(ChatOverlay::JoinRequests { selected, .. }) => *selected,
                    _ => 0,
                }
                .min(requests.len().saturating_sub(1));
                self.status = if requests.is_empty() {
                    "No pending join requests".to_owned()
                } else {
                    format!("{} pending join request(s)", requests.len())
                };
                self.overlay = Some(ChatOverlay::JoinRequests {
                    requests,
                    selected,
                    loading: false,
                });
            }
            ClientEvent::Server(ServerMessage::GroupMembers {
                members,
                offset,
                has_more,
            }) => {
                let selected = match &self.overlay {
                    Some(ChatOverlay::GroupMembers { selected, .. }) => *selected,
                    _ => 0,
                }
                .min(members.len().saturating_sub(1));
                self.status = format!("{} persistent member(s)", members.len());
                self.overlay = Some(ChatOverlay::GroupMembers {
                    members,
                    selected,
                    loading: false,
                    offset,
                    has_more,
                });
            }
            ClientEvent::Server(ServerMessage::RoomMembers {
                room_id,
                members,
                offset,
                has_more,
            }) => {
                let selected = match &self.overlay {
                    Some(ChatOverlay::RoomMembers { selected, .. }) => *selected,
                    _ => 0,
                }
                .min(members.len().saturating_sub(1));
                self.status = format!("{} eligible private-room member(s)", members.len());
                self.overlay = Some(ChatOverlay::RoomMembers {
                    room_id,
                    members,
                    selected,
                    loading: false,
                    offset,
                    has_more,
                });
            }
            ClientEvent::Server(ServerMessage::GroupTokenRotated { kind, token }) => {
                self.status = "Rotated token saved locally".to_owned();
                self.overlay = Some(ChatOverlay::RotatedToken { kind, token });
            }
            ClientEvent::Server(ServerMessage::PrivateMessage { message, status }) => {
                self.handle_private_message(message, status);
            }
            ClientEvent::Server(ServerMessage::PrivateClosed { peer_session_id }) => {
                if let Some(private) = self.private_chats.get_mut(&peer_session_id) {
                    private.online = false;
                }
                self.status = "Private conversation closed because the member left".to_owned();
            }
            ClientEvent::Server(ServerMessage::MemberJoined { member }) => {
                self.members
                    .insert(member.session_id, member.nickname.clone());
                self.push_room_notice("general", format!("{} joined the group", member.nickname));
            }
            ClientEvent::Server(ServerMessage::MemberLeft { session_id }) => {
                if let Some(nickname) = self.members.remove(&session_id) {
                    self.push_room_notice("general", format!("{nickname} left the group"));
                }
                if let Some(private) = self.private_chats.get_mut(&session_id) {
                    private.online = false;
                }
                self.selected_member = self
                    .selected_member
                    .min(self.member_entries().len().saturating_sub(1));
            }
            ClientEvent::Server(ServerMessage::Error { code, message }) => {
                match &mut self.overlay {
                    Some(ChatOverlay::JoinRequests { loading, .. })
                    | Some(ChatOverlay::GroupMembers { loading, .. })
                    | Some(ChatOverlay::RoomMembers { loading, .. }) => *loading = false,
                    _ => {}
                }
                self.status = format!("{code}: {message}");
            }
            ClientEvent::Server(ServerMessage::Pong) => {
                self.status = "Connected".to_owned();
            }
            ClientEvent::Server(ServerMessage::Welcome { .. }) => {
                self.status = "Ignored an unexpected second welcome".to_owned();
            }
            ClientEvent::Server(ServerMessage::GatewayWelcome { .. }) => {
                self.status = "Ignored an unexpected gateway welcome".to_owned();
            }
            ClientEvent::Server(ServerMessage::JoinPending { .. }) => {
                self.status = "Ignored an unexpected join-pending message".to_owned();
            }
            ClientEvent::Disconnected(reason) => {
                self.connected = false;
                self.status = format!("{reason} — Esc returns to groups");
            }
        }
    }

    fn handle_private_message(&mut self, message: DirectRecord, status: PrivateConversationStatus) {
        let peer_id = if message.sender.session_id == self.session_id {
            message.recipient_session_id
        } else {
            message.sender.session_id
        };
        let peer = if message.sender.session_id == peer_id {
            message.sender.clone()
        } else {
            Peer {
                session_id: peer_id,
                member_id: Uuid::nil(),
                nickname: self
                    .members
                    .get(&peer_id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_owned()),
                direct: None,
            }
        };
        let was_waiting_for_reply = self.private_chats.get(&peer_id).is_some_and(|chat| {
            matches!(
                chat.status,
                Some(PrivateConversationStatus::AwaitingReply {
                    initiator_session_id
                }) if initiator_session_id == self.session_id
            )
        });
        let view = self.private_chats.entry(peer_id).or_insert(PrivateView {
            peer,
            items: VecDeque::new(),
            status: None,
            unread: 0,
            online: true,
        });
        view.status = Some(status.clone());
        view.online = true;
        if self.active != ConversationTarget::Private(peer_id) {
            view.unread += 1;
        }
        push_bounded(&mut view.items, message);
        if was_waiting_for_reply && matches!(status, PrivateConversationStatus::Active) {
            self.status = format!("{} replied — private chat unlocked", view.peer.nickname);
        } else if matches!(status, PrivateConversationStatus::AwaitingReply { .. }) {
            self.status = "Private chat started; the initiator must wait for one reply".to_owned();
        }
        self.sync_conversation_selection();
    }

    fn push_room_notice(&mut self, room_id: &str, notice: String) {
        if let Some(room) = self.rooms.get_mut(room_id) {
            push_bounded(&mut room.items, UiItem::Notice(notice));
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<ChatKeyAction> {
        let access_mode = self.access_mode;
        let role = self.role;
        if self.overlay.is_none() && key.code == KeyCode::F(3) {
            self.focus_mode = !self.focus_mode;
            self.focus = ChatFocus::Input;
            self.status = if self.focus_mode {
                "Focus mode enabled — F3 restores the full view".to_owned()
            } else {
                "Full view restored".to_owned()
            };
            return Ok(ChatKeyAction::None);
        }
        if let Some(overlay) = &mut self.overlay {
            return match overlay {
                ChatOverlay::CreateRoom { name, visibility } => match key.code {
                    KeyCode::Esc => {
                        self.overlay = None;
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Backspace => {
                        name.pop();
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Tab => {
                        *visibility = match *visibility {
                            RoomVisibility::Public => RoomVisibility::Private,
                            RoomVisibility::Private => RoomVisibility::Public,
                        };
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Enter => match sanitize_room_name(name) {
                        Ok(name) => {
                            let visibility = *visibility;
                            self.overlay = None;
                            Ok(ChatKeyAction::Send(ClientMessage::CreateRoom {
                                name,
                                visibility,
                            }))
                        }
                        Err(error) => {
                            self.status = error.to_string();
                            Ok(ChatKeyAction::None)
                        }
                    },
                    KeyCode::Char(ch)
                        if !key.modifiers.contains(KeyModifiers::CONTROL)
                            && !ch.is_control()
                            && name.len().saturating_add(ch.len_utf8()) <= 64 =>
                    {
                        name.push(ch);
                        Ok(ChatKeyAction::None)
                    }
                    _ => Ok(ChatKeyAction::None),
                },
                ChatOverlay::IssuedCredentials(_) => match key.code {
                    KeyCode::Esc | KeyCode::Enter => {
                        self.overlay = None;
                        Ok(ChatKeyAction::None)
                    }
                    _ => Ok(ChatKeyAction::None),
                },
                ChatOverlay::JoinRequests {
                    requests,
                    selected,
                    loading,
                } => match key.code {
                    KeyCode::Esc => {
                        self.overlay = None;
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *selected = selected.saturating_sub(1);
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *selected = (*selected + 1).min(requests.len().saturating_sub(1));
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        *loading = true;
                        Ok(ChatKeyAction::Send(ClientMessage::ListJoinRequests))
                    }
                    KeyCode::Enter | KeyCode::Char('a') | KeyCode::Char('A')
                        if !requests.is_empty() && !*loading =>
                    {
                        *loading = true;
                        Ok(ChatKeyAction::Send(ClientMessage::DecideJoinRequest {
                            request_id: requests[*selected].request_id,
                            approve: true,
                        }))
                    }
                    KeyCode::Delete | KeyCode::Char('d') | KeyCode::Char('D')
                        if !requests.is_empty() && !*loading =>
                    {
                        *loading = true;
                        Ok(ChatKeyAction::Send(ClientMessage::DecideJoinRequest {
                            request_id: requests[*selected].request_id,
                            approve: false,
                        }))
                    }
                    _ => Ok(ChatKeyAction::None),
                },
                ChatOverlay::GroupMembers {
                    members,
                    selected,
                    loading,
                    offset,
                    has_more,
                } => match key.code {
                    KeyCode::Esc => {
                        self.overlay = None;
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *selected = selected.saturating_sub(1);
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *selected = (*selected + 1).min(members.len().saturating_sub(1));
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        *loading = true;
                        Ok(ChatKeyAction::Send(ClientMessage::ListGroupMembers {
                            offset: *offset,
                        }))
                    }
                    KeyCode::PageDown if *has_more && !*loading => {
                        *loading = true;
                        *selected = 0;
                        Ok(ChatKeyAction::Send(ClientMessage::ListGroupMembers {
                            offset: offset.saturating_add(MEMBER_PAGE_SIZE),
                        }))
                    }
                    KeyCode::PageUp if *offset > 0 && !*loading => {
                        *loading = true;
                        *selected = 0;
                        Ok(ChatKeyAction::Send(ClientMessage::ListGroupMembers {
                            offset: offset.saturating_sub(MEMBER_PAGE_SIZE),
                        }))
                    }
                    KeyCode::Enter | KeyCode::Char('b') | KeyCode::Char('B')
                        if !members.is_empty() && !*loading =>
                    {
                        let member = &members[*selected];
                        if member.role == GroupRole::Admin {
                            self.status = "Administrator memberships cannot be banned".to_owned();
                            return Ok(ChatKeyAction::None);
                        }
                        *loading = true;
                        Ok(ChatKeyAction::Send(ClientMessage::SetMemberBanned {
                            member_id: member.member_id,
                            banned: member.status == GroupMemberStatus::Active,
                        }))
                    }
                    _ => Ok(ChatKeyAction::None),
                },
                ChatOverlay::RoomMembers {
                    room_id,
                    members,
                    selected,
                    loading,
                    offset,
                    has_more,
                } => match key.code {
                    KeyCode::Esc => {
                        self.overlay = None;
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *selected = selected.saturating_sub(1);
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *selected = (*selected + 1).min(members.len().saturating_sub(1));
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        *loading = true;
                        Ok(ChatKeyAction::Send(ClientMessage::ListRoomMembers {
                            room_id: room_id.clone(),
                            offset: *offset,
                        }))
                    }
                    KeyCode::PageDown if *has_more && !*loading => {
                        *loading = true;
                        *selected = 0;
                        Ok(ChatKeyAction::Send(ClientMessage::ListRoomMembers {
                            room_id: room_id.clone(),
                            offset: offset.saturating_add(MEMBER_PAGE_SIZE),
                        }))
                    }
                    KeyCode::PageUp if *offset > 0 && !*loading => {
                        *loading = true;
                        *selected = 0;
                        Ok(ChatKeyAction::Send(ClientMessage::ListRoomMembers {
                            room_id: room_id.clone(),
                            offset: offset.saturating_sub(MEMBER_PAGE_SIZE),
                        }))
                    }
                    KeyCode::Enter | KeyCode::Char(' ') if !members.is_empty() && !*loading => {
                        let member = &members[*selected];
                        if member.is_owner || member.group_role == GroupRole::Admin {
                            self.status =
                                "Room owners and group administrators always retain access"
                                    .to_owned();
                            return Ok(ChatKeyAction::None);
                        }
                        *loading = true;
                        Ok(ChatKeyAction::Send(ClientMessage::SetRoomMember {
                            room_id: room_id.clone(),
                            member_id: member.member_id,
                            included: !member.included,
                        }))
                    }
                    _ => Ok(ChatKeyAction::None),
                },
                ChatOverlay::RotateTokens {
                    selected,
                    confirming,
                } => match key.code {
                    KeyCode::Esc => {
                        self.overlay = None;
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *selected = selected.saturating_sub(1);
                        *confirming = false;
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let maximum = token_rotation_choices(role, access_mode)
                            .len()
                            .saturating_sub(1);
                        *selected = (*selected + 1).min(maximum);
                        *confirming = false;
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Enter => {
                        *confirming = true;
                        self.status = "Press Y to invalidate the old token".to_owned();
                        Ok(ChatKeyAction::None)
                    }
                    KeyCode::Char('y') | KeyCode::Char('Y') if *confirming => {
                        let kind = token_rotation_choices(role, access_mode)[*selected].0;
                        Ok(ChatKeyAction::Send(ClientMessage::RotateGroupToken {
                            kind,
                        }))
                    }
                    _ => Ok(ChatKeyAction::None),
                },
                ChatOverlay::RotatedToken { .. } => match key.code {
                    KeyCode::Esc | KeyCode::Enter => {
                        self.overlay = None;
                        Ok(ChatKeyAction::None)
                    }
                    _ => Ok(ChatKeyAction::None),
                },
            };
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('q') => return Ok(ChatKeyAction::Quit),
                KeyCode::Char('l') => {
                    self.clear_active_view();
                    return Ok(ChatKeyAction::None);
                }
                KeyCode::Char('w') if self.focus == ChatFocus::Input => {
                    trim_last_word(&mut self.input);
                    return Ok(ChatKeyAction::None);
                }
                _ => {}
            }
        }

        if self.focus_mode {
            return match key.code {
                KeyCode::Esc => Ok(ChatKeyAction::Back),
                _ => self.handle_input_key(key),
            };
        }

        match key.code {
            KeyCode::Esc => Ok(ChatKeyAction::Back),
            KeyCode::F(2) => {
                self.overlay = Some(ChatOverlay::CreateRoom {
                    name: String::new(),
                    visibility: RoomVisibility::Public,
                });
                Ok(ChatKeyAction::None)
            }
            KeyCode::F(4) if self.role == GroupRole::Admin => {
                self.overlay = Some(ChatOverlay::JoinRequests {
                    requests: Vec::new(),
                    selected: 0,
                    loading: true,
                });
                self.status = "Loading join requests…".to_owned();
                Ok(ChatKeyAction::Send(ClientMessage::ListJoinRequests))
            }
            KeyCode::F(5) => {
                let ConversationTarget::Room(room_id) = &self.active else {
                    self.status = "Select a private room first".to_owned();
                    return Ok(ChatKeyAction::None);
                };
                if !self
                    .rooms
                    .get(room_id)
                    .is_some_and(|room| room.summary.visibility == RoomVisibility::Private)
                {
                    self.status = "The active room is public".to_owned();
                    return Ok(ChatKeyAction::None);
                }
                let room_id = room_id.clone();
                self.overlay = Some(ChatOverlay::RoomMembers {
                    room_id: room_id.clone(),
                    members: Vec::new(),
                    selected: 0,
                    loading: true,
                    offset: 0,
                    has_more: false,
                });
                Ok(ChatKeyAction::Send(ClientMessage::ListRoomMembers {
                    room_id,
                    offset: 0,
                }))
            }
            KeyCode::F(6) if self.role == GroupRole::Admin => {
                self.overlay = Some(ChatOverlay::GroupMembers {
                    members: Vec::new(),
                    selected: 0,
                    loading: true,
                    offset: 0,
                    has_more: false,
                });
                Ok(ChatKeyAction::Send(ClientMessage::ListGroupMembers {
                    offset: 0,
                }))
            }
            KeyCode::F(7) => {
                self.overlay = Some(ChatOverlay::RotateTokens {
                    selected: 0,
                    confirming: false,
                });
                Ok(ChatKeyAction::None)
            }
            KeyCode::Tab => {
                self.focus = match self.focus {
                    ChatFocus::Input => ChatFocus::Conversations,
                    ChatFocus::Conversations => ChatFocus::Members,
                    ChatFocus::Members => ChatFocus::Input,
                };
                Ok(ChatKeyAction::None)
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    ChatFocus::Input => ChatFocus::Members,
                    ChatFocus::Members => ChatFocus::Conversations,
                    ChatFocus::Conversations => ChatFocus::Input,
                };
                Ok(ChatKeyAction::None)
            }
            _ => match self.focus {
                ChatFocus::Input => self.handle_input_key(key),
                ChatFocus::Conversations => self.handle_conversation_key(key),
                ChatFocus::Members => self.handle_member_key(key),
            },
        }
    }

    fn handle_input_key(&mut self, key: KeyEvent) -> Result<ChatKeyAction> {
        match key.code {
            KeyCode::Enter if !self.input.trim().is_empty() => self.prepare_message(),
            KeyCode::Backspace => {
                self.input.pop();
                Ok(ChatKeyAction::None)
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !ch.is_control()
                    && self.input.len().saturating_add(ch.len_utf8()) <= MAX_MESSAGE_BYTES =>
            {
                self.input.push(ch);
                Ok(ChatKeyAction::None)
            }
            KeyCode::PageUp => {
                self.scroll_from_bottom = self.scroll_from_bottom.saturating_add(8);
                if let ConversationTarget::Room(room_id) = &self.active
                    && let Some(room) = self.rooms.get_mut(room_id)
                    && room.has_more_history
                    && !room.loading_history
                {
                    let before_sequence = room.items.iter().find_map(|item| match item {
                        UiItem::Chat(message) => Some(message.sequence),
                        UiItem::Notice(_) => None,
                    });
                    if let Some(before_sequence) = before_sequence {
                        room.loading_history = true;
                        self.status = "Loading older history from the gateway…".to_owned();
                        return Ok(ChatKeyAction::Send(ClientMessage::LoadHistory {
                            room_id: room_id.clone(),
                            before_sequence,
                            limit: 100,
                        }));
                    }
                }
                Ok(ChatKeyAction::None)
            }
            KeyCode::PageDown => {
                self.scroll_from_bottom = self.scroll_from_bottom.saturating_sub(8);
                Ok(ChatKeyAction::None)
            }
            KeyCode::End => {
                self.scroll_from_bottom = 0;
                Ok(ChatKeyAction::None)
            }
            _ => Ok(ChatKeyAction::None),
        }
    }

    fn prepare_message(&mut self) -> Result<ChatKeyAction> {
        let text = match crate::security::sanitize_chat_text(&self.input) {
            Ok(text) => text,
            Err(error) => {
                self.status = error.to_string();
                return Ok(ChatKeyAction::None);
            }
        };
        match self.active.clone() {
            ConversationTarget::Room(room_id) => {
                let joined = self.rooms.get(&room_id).is_some_and(|room| room.joined);
                if !joined {
                    self.status = "Join this room before sending".to_owned();
                    return Ok(ChatKeyAction::None);
                }
                Ok(ChatKeyAction::Send(ClientMessage::Chat {
                    room_id,
                    message_id: Uuid::new_v4(),
                    text,
                }))
            }
            ConversationTarget::Private(peer_id) => {
                let Some(private) = self.private_chats.get_mut(&peer_id) else {
                    return Ok(ChatKeyAction::None);
                };
                if !private.online {
                    self.status = "That member is offline".to_owned();
                    return Ok(ChatKeyAction::None);
                }
                if matches!(
                    private.status,
                    Some(PrivateConversationStatus::AwaitingReply {
                        initiator_session_id
                    }) if initiator_session_id == self.session_id
                ) {
                    self.status = format!("Wait for {} to reply once", private.peer.nickname);
                    return Ok(ChatKeyAction::None);
                }
                if private.status.is_none() {
                    private.status = Some(PrivateConversationStatus::AwaitingReply {
                        initiator_session_id: self.session_id,
                    });
                }
                Ok(ChatKeyAction::Send(ClientMessage::PrivateChat {
                    peer_session_id: peer_id,
                    message_id: Uuid::new_v4(),
                    text,
                }))
            }
        }
    }

    fn handle_conversation_key(&mut self, key: KeyEvent) -> Result<ChatKeyAction> {
        let entries = self.conversation_entries();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_conversation = self.selected_conversation.saturating_sub(1);
                Ok(ChatKeyAction::None)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_conversation =
                    (self.selected_conversation + 1).min(entries.len().saturating_sub(1));
                Ok(ChatKeyAction::None)
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.overlay = Some(ChatOverlay::CreateRoom {
                    name: String::new(),
                    visibility: RoomVisibility::Public,
                });
                Ok(ChatKeyAction::None)
            }
            KeyCode::Delete => {
                let Some(ConversationTarget::Room(room_id)) =
                    entries.get(self.selected_conversation).cloned()
                else {
                    return Ok(ChatKeyAction::None);
                };
                Ok(ChatKeyAction::Send(ClientMessage::LeaveRoom { room_id }))
            }
            KeyCode::Enter => {
                let Some(target) = entries.get(self.selected_conversation).cloned() else {
                    return Ok(ChatKeyAction::None);
                };
                match target.clone() {
                    ConversationTarget::Room(room_id) => {
                        if self.rooms.get(&room_id).is_some_and(|room| room.joined) {
                            self.activate(target);
                            self.focus = ChatFocus::Input;
                            Ok(ChatKeyAction::None)
                        } else {
                            self.status = "Joining room…".to_owned();
                            Ok(ChatKeyAction::Send(ClientMessage::JoinRoom { room_id }))
                        }
                    }
                    ConversationTarget::Private(_) => {
                        self.activate(target);
                        self.focus = ChatFocus::Input;
                        Ok(ChatKeyAction::None)
                    }
                }
            }
            _ => Ok(ChatKeyAction::None),
        }
    }

    fn handle_member_key(&mut self, key: KeyEvent) -> Result<ChatKeyAction> {
        let members = self.member_entries();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_member = self.selected_member.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected_member =
                    (self.selected_member + 1).min(members.len().saturating_sub(1));
            }
            KeyCode::Enter => {
                if let Some((peer_id, nickname)) = members.get(self.selected_member).cloned() {
                    self.private_chats.entry(peer_id).or_insert(PrivateView {
                        peer: Peer {
                            session_id: peer_id,
                            member_id: Uuid::nil(),
                            nickname,
                            direct: None,
                        },
                        items: VecDeque::new(),
                        status: None,
                        unread: 0,
                        online: true,
                    });
                    self.activate(ConversationTarget::Private(peer_id));
                    self.sync_conversation_selection();
                    self.focus = ChatFocus::Input;
                    self.status =
                        "Send one message; then wait for one reply to unlock chat".to_owned();
                }
            }
            _ => {}
        }
        Ok(ChatKeyAction::None)
    }

    fn paste(&mut self, raw: &str) {
        if let Some(overlay) = &mut self.overlay {
            if let ChatOverlay::CreateRoom { name: value, .. } = overlay {
                let pasted = sanitize_paste_for_input(raw);
                value.extend(pasted.chars().take(64usize.saturating_sub(value.len())));
            }
            return;
        }
        if self.focus == ChatFocus::Input {
            let pasted = sanitize_paste_for_input(raw);
            if self.input.len().saturating_add(pasted.len()) <= MAX_MESSAGE_BYTES {
                self.input.push_str(&pasted);
            } else {
                self.status = format!("Message cannot exceed {MAX_MESSAGE_BYTES} bytes");
            }
        }
    }

    fn activate(&mut self, target: ConversationTarget) {
        self.active = target.clone();
        self.scroll_from_bottom = 0;
        match target {
            ConversationTarget::Room(room_id) => {
                if let Some(room) = self.rooms.get_mut(&room_id) {
                    room.unread = 0;
                }
            }
            ConversationTarget::Private(peer_id) => {
                if let Some(private) = self.private_chats.get_mut(&peer_id) {
                    private.unread = 0;
                }
            }
        }
    }

    fn conversation_entries(&self) -> Vec<ConversationTarget> {
        let mut rooms: Vec<_> = self.rooms.values().collect();
        rooms.sort_by(|left, right| left.summary.room_name.cmp(&right.summary.room_name));
        let mut private: Vec<_> = self.private_chats.values().collect();
        private.sort_by(|left, right| left.peer.nickname.cmp(&right.peer.nickname));
        rooms
            .into_iter()
            .map(|room| ConversationTarget::Room(room.summary.room_id.clone()))
            .chain(
                private
                    .into_iter()
                    .map(|chat| ConversationTarget::Private(chat.peer.session_id)),
            )
            .collect()
    }

    fn member_entries(&self) -> Vec<(Uuid, String)> {
        let mut members: Vec<_> = self
            .members
            .iter()
            .filter(|(session_id, _)| **session_id != self.session_id)
            .map(|(session_id, nickname)| (*session_id, nickname.clone()))
            .collect();
        members.sort_by(|left, right| left.1.cmp(&right.1));
        members
    }

    fn sync_conversation_selection(&mut self) {
        if let Some(index) = self
            .conversation_entries()
            .iter()
            .position(|entry| *entry == self.active)
        {
            self.selected_conversation = index;
        }
    }

    fn clear_active_view(&mut self) {
        match self.active.clone() {
            ConversationTarget::Room(room_id) => {
                if let Some(room) = self.rooms.get_mut(&room_id) {
                    room.items.clear();
                }
            }
            ConversationTarget::Private(peer_id) => {
                if let Some(private) = self.private_chats.get_mut(&peer_id) {
                    private.items.clear();
                }
            }
        }
        self.status = "Local view cleared".to_owned();
    }

    fn private_send_locked(&self) -> Option<String> {
        let ConversationTarget::Private(peer_id) = self.active else {
            return None;
        };
        let private = self.private_chats.get(&peer_id)?;
        if !private.online {
            return Some("member offline".to_owned());
        }
        match private.status {
            Some(PrivateConversationStatus::AwaitingReply {
                initiator_session_id,
            }) if initiator_session_id == self.session_id => {
                Some(format!("waiting for {} to reply", private.peer.nickname))
            }
            _ => None,
        }
    }
}

fn push_bounded<T>(items: &mut VecDeque<T>, item: T) {
    if items.len() == MAX_UI_ITEMS {
        items.pop_front();
    }
    items.push_back(item);
}

fn trim_last_word(input: &mut String) {
    while input.ends_with(char::is_whitespace) {
        input.pop();
    }
    while input
        .chars()
        .last()
        .is_some_and(|character| !character.is_whitespace())
    {
        input.pop();
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn new() -> Result<Self> {
        enable_raw_mode().context("failed to enable terminal raw mode")?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error).context("failed to enter the terminal alternate screen");
        }
        let terminal = Terminal::new(CrosstermBackend::new(stdout))
            .context("failed to initialize terminal rendering")?;
        Ok(Self { terminal })
    }

    fn draw(&mut self, render: impl FnOnce(&mut Frame<'_>)) -> Result<()> {
        self.terminal
            .draw(render)
            .context("failed to render the terminal UI")?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

fn render_lobby(frame: &mut Frame<'_>, app: &LobbyApp) {
    let area = frame.area();
    if area.width < 30 || area.height < 10 {
        render_too_small(frame, area, 30, 10);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(2),
        ])
        .split(area);
    let header = Line::from(vec![
        Span::styled(
            " LAN CHAT ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Groups on your local network"),
        Span::styled(
            format!("  @{}", app.nickname),
            Style::default().fg(Color::Magenta),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        rows[0],
    );

    if area.width >= 78 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(rows[1]);
        render_group_list(frame, columns[0], app);
        render_lobby_help(frame, columns[1], app);
    } else {
        render_group_list(frame, rows[1], app);
    }
    frame.render_widget(
        Paragraph::new(format!(" {}", app.status)).style(Style::default().fg(Color::Black).bg(
            if app.refreshing {
                Color::Yellow
            } else {
                Color::Cyan
            },
        )),
        rows[2],
    );

    match &app.mode {
        LobbyMode::Input { kind, value } => {
            let title = match kind {
                LobbyInputKind::CreateGroup => " CREATE GROUP ",
                LobbyInputKind::DirectJoin => " DIRECT ADDRESS ",
                LobbyInputKind::Nickname => " NICKNAME ",
            };
            render_text_overlay(frame, area, title, value, None);
        }
        LobbyMode::ChooseAccess { selected, .. } => {
            render_access_overlay(frame, area, *selected);
        }
        LobbyMode::InviteToken { value, .. } => {
            let hidden = "•".repeat(value.chars().count());
            render_text_overlay(
                frame,
                area,
                " INVITE TOKEN ",
                &hidden,
                Some("Paste token, then Enter • Esc cancels"),
            );
        }
        LobbyMode::ConfirmForget { group_index } => {
            let group_name = app
                .groups
                .get(*group_index)
                .map(|group| group.group_name.as_str())
                .unwrap_or("selected group");
            render_confirmation_overlay(frame, area, group_name);
        }
        LobbyMode::Browse => {}
    }
}

fn render_group_list(frame: &mut Frame<'_>, area: Rect, app: &LobbyApp) {
    let mut lines = Vec::new();
    if app.groups.is_empty() {
        lines.push(Line::styled(
            "  Searching… create a group with C if none appear.",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        for (index, group) in app.groups.iter().enumerate() {
            let selected = index == app.selected;
            let marker = if selected { "▶" } else { " " };
            let access = match group.access_mode {
                GroupAccessMode::Public => "public",
                GroupAccessMode::Invite => "invite token",
                GroupAccessMode::Approval => "admin approval",
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {marker} {}", group.group_name),
                    Style::default()
                        .fg(if selected { Color::Cyan } else { Color::White })
                        .add_modifier(if selected {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
                Span::styled(
                    format!("  {}", group.endpoint),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
            lines.push(Line::styled(
                format!(
                    "     {access}  •  via {}  •  key {}",
                    group.gateway_name, group.server_fingerprint
                ),
                Style::default().fg(Color::DarkGray),
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" GROUPS {} ", app.groups.len()))
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn render_lobby_help(frame: &mut Frame<'_>, area: Rect, _app: &LobbyApp) {
    let lines = vec![
        Line::styled("ENTER", Style::default().fg(Color::Cyan)),
        Line::raw("Join selected group"),
        Line::raw(""),
        Line::styled("C", Style::default().fg(Color::Cyan)),
        Line::raw("Create group on gateway"),
        Line::raw(""),
        Line::styled("J", Style::default().fg(Color::Cyan)),
        Line::raw("Direct IP fallback"),
        Line::raw(""),
        Line::styled("N", Style::default().fg(Color::Cyan)),
        Line::raw("Change anonymous nickname"),
        Line::raw(""),
        Line::styled("X", Style::default().fg(Color::Cyan)),
        Line::raw("Forget selected credential"),
        Line::raw(""),
        Line::styled("Q / ESC", Style::default().fg(Color::Cyan)),
        Line::raw("Quit"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ACTIONS ")
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn render_chat_app(frame: &mut Frame<'_>, app: &ChatApp) {
    let area = frame.area();
    if app.focus_mode {
        if area.width < 24 || area.height < 6 {
            render_too_small(frame, area, 24, 6);
            return;
        }
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(area);
        render_active_messages(frame, rows[0], app);
        render_chat_input(frame, rows[1], app);
        return;
    }
    if area.width < 30 || area.height < 10 {
        render_too_small(frame, area, 30, 10);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);
    render_chat_header(frame, rows[0], app);
    render_chat_body(frame, rows[1], app);
    render_chat_input(frame, rows[2], app);
    render_chat_footer(frame, rows[3], app);

    match &app.overlay {
        Some(ChatOverlay::CreateRoom { name, visibility }) => {
            render_create_room_overlay(frame, area, name, *visibility)
        }
        Some(ChatOverlay::JoinRequests {
            requests,
            selected,
            loading,
        }) => render_join_requests_overlay(frame, area, requests, *selected, *loading),
        Some(ChatOverlay::IssuedCredentials(credentials)) => {
            render_credentials_overlay(frame, area, credentials)
        }
        Some(ChatOverlay::GroupMembers {
            members,
            selected,
            loading,
            offset,
            has_more,
        }) => render_group_members_overlay(
            frame, area, members, *selected, *loading, *offset, *has_more,
        ),
        Some(ChatOverlay::RoomMembers {
            members,
            selected,
            loading,
            offset,
            has_more,
            ..
        }) => render_room_members_overlay(
            frame, area, members, *selected, *loading, *offset, *has_more,
        ),
        Some(ChatOverlay::RotateTokens {
            selected,
            confirming,
        }) => render_rotate_tokens_overlay(
            frame,
            area,
            app.role,
            app.access_mode,
            *selected,
            *confirming,
        ),
        Some(ChatOverlay::RotatedToken { kind, token }) => {
            render_rotated_token_overlay(frame, area, *kind, token)
        }
        None => {}
    }
}

fn render_chat_header(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let status_color = if app.connected {
        Color::Green
    } else {
        Color::Red
    };
    let content = Line::from(vec![
        Span::styled(" ● ", Style::default().fg(status_color)),
        Span::styled(
            app.group_name.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  {}  {}  ",
            app.endpoint,
            match app.access_mode {
                GroupAccessMode::Public => "public",
                GroupAccessMode::Invite => "invite",
                GroupAccessMode::Approval => "approval",
            }
        )),
        Span::styled("Noise XX", Style::default().fg(Color::Green)),
    ]);
    frame.render_widget(
        Paragraph::new(content).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" LAN CHAT ")
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn render_chat_body(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    if area.width >= 78 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(20),
                Constraint::Min(30),
                Constraint::Length(22),
            ])
            .split(area);
        render_conversations(frame, columns[0], app);
        render_active_messages(frame, columns[1], app);
        render_members(frame, columns[2], app);
    } else if area.width >= 55 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(21), Constraint::Min(30)])
            .split(area);
        if app.focus == ChatFocus::Members {
            render_members(frame, columns[0], app);
        } else {
            render_conversations(frame, columns[0], app);
        }
        render_active_messages(frame, columns[1], app);
    } else {
        render_active_messages(frame, area, app);
    }
}

fn render_conversations(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let entries = app.conversation_entries();
    let mut lines = Vec::new();
    for (index, target) in entries.iter().enumerate() {
        let selected = app.focus == ChatFocus::Conversations && index == app.selected_conversation;
        let active = *target == app.active;
        let marker = if selected {
            "▶"
        } else if active {
            "●"
        } else {
            " "
        };
        let (label, unread, joined) = match target {
            ConversationTarget::Room(room_id) => {
                let room = &app.rooms[room_id];
                (
                    format!(
                        "{} {}",
                        if room.summary.visibility == RoomVisibility::Private {
                            "◇"
                        } else {
                            "#"
                        },
                        room.summary.room_name
                    ),
                    room.unread,
                    room.joined,
                )
            }
            ConversationTarget::Private(peer_id) => {
                let private = &app.private_chats[peer_id];
                (
                    format!("@ {}", private.peer.nickname),
                    private.unread,
                    private.online,
                )
            }
        };
        let suffix = if unread > 0 {
            format!(" ({unread})")
        } else if !joined {
            " ◌".to_owned()
        } else {
            String::new()
        };
        lines.push(Line::styled(
            format!(" {marker} {label}{suffix}"),
            Style::default()
                .fg(if selected || active {
                    Color::Cyan
                } else {
                    Color::White
                })
                .add_modifier(if selected {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ));
    }
    let border = if app.focus == ChatFocus::Conversations {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ROOMS / DMS ")
                .border_style(Style::default().fg(border)),
        ),
        area,
    );
}

fn render_members(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let members = app.member_entries();
    let lines: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(index, (session_id, nickname))| {
            let selected = app.focus == ChatFocus::Members && index == app.selected_member;
            let marker = if selected { "▶" } else { "●" };
            let suffix = &session_id.simple().to_string()[..4];
            Line::from(vec![
                Span::styled(
                    format!(" {marker} "),
                    Style::default().fg(if selected { Color::Cyan } else { Color::Green }),
                ),
                Span::styled(nickname.clone(), nickname_style(nickname)),
                Span::styled(format!("~{suffix}"), Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();
    let border = if app.focus == ChatFocus::Members {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" MEMBERS {} ", members.len()))
                .border_style(Style::default().fg(border)),
        ),
        area,
    );
}

fn render_active_messages(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let (title, lines) = match &app.active {
        ConversationTarget::Room(room_id) => {
            let room = &app.rooms[room_id];
            (
                format!(
                    " {}{} ",
                    if room.summary.visibility == RoomVisibility::Private {
                        "◇"
                    } else {
                        "#"
                    },
                    room.summary.room_name
                ),
                room_lines(&room.items, app.member_id),
            )
        }
        ConversationTarget::Private(peer_id) => {
            let private = &app.private_chats[peer_id];
            let lock = app
                .private_send_locked()
                .map(|reason| format!(" — {reason}"))
                .unwrap_or_default();
            (
                format!(" @{}{} ", private.peer.nickname, lock),
                direct_lines(&private.items, app.session_id),
            )
        }
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let height = inner.height as usize;
    let end = lines
        .len()
        .saturating_sub(app.scroll_from_bottom.min(lines.len()));
    let start = end.saturating_sub(height);
    frame.render_widget(
        Paragraph::new(lines[start..end].to_vec()).wrap(Wrap { trim: false }),
        inner,
    );
}

fn room_lines(items: &VecDeque<UiItem>, own_member_id: Uuid) -> Vec<Line<'static>> {
    if items.is_empty() {
        return vec![Line::styled(
            "  No messages yet.",
            Style::default().fg(Color::DarkGray),
        )];
    }
    let mut lines = Vec::new();
    for item in items {
        match item {
            UiItem::Notice(notice) => lines.push(Line::styled(
                format!("  · {notice}"),
                Style::default().fg(Color::DarkGray),
            )),
            UiItem::Chat(message) => append_message_lines(
                &mut lines,
                message.sent_at_ms,
                &message.sender.nickname,
                &message.text,
                message.sender.member_id == own_member_id,
            ),
        }
    }
    lines
}

fn direct_lines(items: &VecDeque<DirectRecord>, own_session_id: Uuid) -> Vec<Line<'static>> {
    if items.is_empty() {
        return vec![Line::styled(
            "  Send one message. The sender must then wait for one reply.",
            Style::default().fg(Color::DarkGray),
        )];
    }
    let mut lines = Vec::new();
    for message in items {
        append_message_lines(
            &mut lines,
            message.sent_at_ms,
            &message.sender.nickname,
            &message.text,
            message.sender.session_id == own_session_id,
        );
    }
    lines
}

fn append_message_lines(
    lines: &mut Vec<Line<'static>>,
    sent_at_ms: u64,
    nickname: &str,
    text: &str,
    own_message: bool,
) {
    let mut text_lines = text.lines();
    let first = text_lines.next().unwrap_or_default();
    if own_message {
        lines.push(
            Line::from(vec![
                Span::raw(first.to_owned()),
                Span::styled(format!("  {nickname}"), nickname_style(nickname)),
                Span::styled(
                    format!(" {} ", short_time(sent_at_ms)),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
            .right_aligned(),
        );
        for continuation in text_lines {
            lines.push(Line::raw(format!("{continuation} ")).right_aligned());
        }
    } else {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", short_time(sent_at_ms)),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(format!("{nickname} "), nickname_style(nickname)),
            Span::raw(first.to_owned()),
        ]));
        for continuation in text_lines {
            lines.push(Line::raw(format!("          {continuation}")));
        }
    }
}

fn render_chat_input(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let locked = app.private_send_locked();
    let title = locked
        .as_ref()
        .map(|reason| format!(" MESSAGE — {reason} "))
        .unwrap_or_else(|| " MESSAGE ".to_owned());
    let border = if locked.is_some() {
        Color::Yellow
    } else if app.focus == ChatFocus::Input {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(border));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let prompt = if locked.is_some() { "⏳ " } else { "> " };
    let prompt_width = UnicodeWidthStr::width(prompt);
    let shown = tail_by_width(
        &app.input,
        (inner.width as usize)
            .saturating_sub(prompt_width)
            .saturating_sub(1),
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(prompt, Style::default().fg(border)),
            Span::raw(shown.clone()),
        ])),
        inner,
    );
    if app.focus == ChatFocus::Input && app.overlay.is_none() {
        let cursor_x = inner
            .x
            .saturating_add((prompt_width + UnicodeWidthStr::width(shown.as_str())) as u16)
            .min(inner.right().saturating_sub(1));
        frame.set_cursor_position((cursor_x, inner.y));
    }
}

fn render_chat_footer(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let admin_help = if app.role == GroupRole::Admin {
        "  •  F4 approvals  •  F6 bans  •  F7 tokens"
    } else {
        ""
    };
    let text = format!(
        " {}  •  Tab panels  •  F2 new room  •  F3 focus  •  F5 private members{admin_help}  •  Esc groups  •  v{}  •  {} ",
        app.status, app.protocol_version, app.fingerprint,
    );
    frame.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::Black).bg(Color::Cyan)),
        area,
    );
}

fn render_create_room_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    name: &str,
    visibility: RoomVisibility,
) {
    let popup = centered_rect(72, 7, area);
    frame.render_widget(Clear, popup);
    let visibility_label = match visibility {
        RoomVisibility::Public => "PUBLIC — visible to every group member",
        RoomVisibility::Private => "PRIVATE — only explicitly added members can see it",
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Cyan)),
            Span::raw(name.to_owned()),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" Visibility: ", Style::default().fg(Color::DarkGray)),
            Span::styled(visibility_label, Style::default().fg(Color::Cyan)),
        ]),
        Line::raw(""),
        Line::styled(
            " Tab toggles visibility • Enter creates • Esc cancels",
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" CREATE ROOM ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_group_members_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    members: &[GroupMemberSummary],
    selected: usize,
    loading: bool,
    offset: u32,
    has_more: bool,
) {
    let popup = centered_rect(78, 16, area);
    frame.render_widget(Clear, popup);
    let mut lines = Vec::new();
    if loading {
        lines.push(Line::styled(
            " Loading members…",
            Style::default().fg(Color::Yellow),
        ));
    } else {
        let window_size = 10usize;
        let start = selected
            .saturating_sub(window_size / 2)
            .min(members.len().saturating_sub(window_size));
        for (index, member) in members
            .iter()
            .enumerate()
            .take((start + window_size).min(members.len()))
            .skip(start)
        {
            let active = index == selected;
            let marker = if active { "▶" } else { " " };
            let state = match (member.role, member.status) {
                (GroupRole::Admin, _) => "ADMIN",
                (_, GroupMemberStatus::Active) => "active",
                (_, GroupMemberStatus::Banned) => "BANNED",
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {marker} {:<24}", member.nickname),
                    Style::default().fg(if active { Color::Cyan } else { Color::White }),
                ),
                Span::styled(
                    format!(
                        " {state:<7} ~{}",
                        &member.member_id.simple().to_string()[..8]
                    ),
                    Style::default().fg(if member.status == GroupMemberStatus::Banned {
                        Color::Red
                    } else {
                        Color::DarkGray
                    }),
                ),
            ]));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!(
            " Enter/B ban • PgUp/PgDn pages • R refresh • offset {offset}{} • Esc close",
            if has_more { " +" } else { "" }
        ),
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" GROUP MEMBERS {} ", members.len()))
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_room_members_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    members: &[RoomMemberSummary],
    selected: usize,
    loading: bool,
    offset: u32,
    has_more: bool,
) {
    let popup = centered_rect(78, 16, area);
    frame.render_widget(Clear, popup);
    let mut lines = Vec::new();
    if loading {
        lines.push(Line::styled(
            " Loading private-room members…",
            Style::default().fg(Color::Yellow),
        ));
    } else {
        let window_size = 10usize;
        let start = selected
            .saturating_sub(window_size / 2)
            .min(members.len().saturating_sub(window_size));
        for (index, member) in members
            .iter()
            .enumerate()
            .take((start + window_size).min(members.len()))
            .skip(start)
        {
            let active = index == selected;
            let marker = if active { "▶" } else { " " };
            let membership = if member.group_role == GroupRole::Admin {
                "ADMIN"
            } else if member.is_owner {
                "OWNER"
            } else if member.included {
                "[x]"
            } else {
                "[ ]"
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {marker} {membership:<5} {:<24}", member.nickname),
                    Style::default().fg(if active { Color::Cyan } else { Color::White }),
                ),
                Span::styled(
                    format!("~{}", &member.member_id.simple().to_string()[..8]),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        format!(
            " Enter/Space access • PgUp/PgDn pages • offset {offset}{} • Esc close",
            if has_more { " +" } else { "" }
        ),
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" PRIVATE ROOM MEMBERS ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_rotate_tokens_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    role: GroupRole,
    access_mode: GroupAccessMode,
    selected: usize,
    confirming: bool,
) {
    let popup = centered_rect(76, 10, area);
    frame.render_widget(Clear, popup);
    let choices = token_rotation_choices(role, access_mode);
    let mut lines = vec![Line::styled(
        " Rotation immediately invalidates the previous token.",
        Style::default().fg(Color::Yellow),
    )];
    lines.push(Line::raw(""));
    for (index, (_, label)) in choices.iter().enumerate() {
        lines.push(Line::styled(
            format!(" {} {label}", if index == selected { "▶" } else { " " }),
            Style::default().fg(if index == selected {
                Color::Cyan
            } else {
                Color::White
            }),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        if confirming {
            " Press Y to confirm rotation • Esc cancels"
        } else {
            " ↑/↓ select • Enter asks for confirmation • Esc closes"
        },
        Style::default().fg(if confirming {
            Color::Yellow
        } else {
            Color::DarkGray
        }),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" ROTATE GROUP TOKEN ")
                .border_style(Style::default().fg(Color::Yellow)),
        ),
        popup,
    );
}

fn token_rotation_choices(
    role: GroupRole,
    access_mode: GroupAccessMode,
) -> Vec<(GroupTokenKind, &'static str)> {
    if role == GroupRole::Member {
        return vec![(GroupTokenKind::Member, "My member token")];
    }
    let mut choices = vec![(GroupTokenKind::Admin, "Administrator token")];
    if access_mode == GroupAccessMode::Invite {
        choices.push((GroupTokenKind::Invite, "Shared invite token"));
    }
    choices
}

fn render_rotated_token_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    kind: GroupTokenKind,
    token: &str,
) {
    let popup = centered_rect(88, 10, area);
    frame.render_widget(Clear, popup);
    let label = match kind {
        GroupTokenKind::Member => "New member token — keep it private:",
        GroupTokenKind::Admin => "New administrator token — never share:",
        GroupTokenKind::Invite => "New invite token — share only with intended members:",
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                " Saved to the local credential file.",
                Style::default().fg(Color::Green),
            ),
            Line::raw(""),
            Line::styled(format!(" {label}"), Style::default().fg(Color::Yellow)),
            Line::raw(format!(" {token}")),
            Line::raw(""),
            Line::styled(" Enter or Esc closes", Style::default().fg(Color::DarkGray)),
        ])
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" TOKEN ROTATED ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_join_requests_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    requests: &[JoinRequestSummary],
    selected: usize,
    loading: bool,
) {
    let popup = centered_rect(72, 14, area);
    frame.render_widget(Clear, popup);
    let mut lines = Vec::new();
    if loading {
        lines.push(Line::styled(
            " Loading requests…",
            Style::default().fg(Color::Yellow),
        ));
    } else if requests.is_empty() {
        lines.push(Line::styled(
            " No pending requests.",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        let window_size = 8usize;
        let start = selected
            .saturating_sub(window_size / 2)
            .min(requests.len().saturating_sub(window_size));
        let end = (start + window_size).min(requests.len());
        for (index, request) in requests.iter().enumerate().take(end).skip(start) {
            let active = index == selected;
            let marker = if active { "▶" } else { " " };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {marker} {} ", request.nickname),
                    Style::default()
                        .fg(if active { Color::Cyan } else { Color::White })
                        .add_modifier(if active {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        }),
                ),
                Span::styled(
                    format!("~{}", &request.request_id.simple().to_string()[..8]),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        " ↑/↓ select • Enter/A approve • D/Delete reject • R refresh • Esc close",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" JOIN REQUESTS {} ", requests.len()))
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_credentials_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    credentials: &IssuedGroupCredentials,
) {
    let popup = centered_rect(
        88,
        if credentials.invite_token.is_some() {
            18
        } else {
            13
        },
        area,
    );
    frame.render_widget(Clear, popup);
    let mut lines = vec![
        Line::styled(
            " Credentials were saved to your private client data file.",
            Style::default().fg(Color::Green),
        ),
        Line::raw(""),
        Line::styled(
            " Administrator token — never share:",
            Style::default().fg(Color::Yellow),
        ),
        Line::raw(format!(" {}", credentials.admin_token)),
    ];
    if let Some(invite_token) = &credentials.invite_token {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            " Invite token — share only with intended members:",
            Style::default().fg(Color::Cyan),
        ));
        lines.push(Line::raw(format!(" {invite_token}")));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        " Enter or Esc closes this view",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" GROUP CREDENTIALS ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_access_overlay(frame: &mut Frame<'_>, area: Rect, selected: usize) {
    let popup = centered_rect(72, 11, area);
    frame.render_widget(Clear, popup);
    let choices = [
        ("1  Public", "Anyone on the LAN may enter"),
        ("2  Invite", "A shared invite token is required"),
        ("3  Approval", "An administrator approves each request"),
    ];
    let mut lines = vec![
        Line::raw(" Choose the group's membership boundary:"),
        Line::raw(""),
    ];
    for (index, (label, description)) in choices.into_iter().enumerate() {
        let marker = if index == selected { "▶" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {marker} {label:<13}"),
                Style::default()
                    .fg(if index == selected {
                        Color::Cyan
                    } else {
                        Color::White
                    })
                    .add_modifier(if index == selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Span::styled(description, Style::default().fg(Color::DarkGray)),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        " ↑/↓ or 1–3 selects • Enter creates • Esc cancels",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" GROUP ACCESS ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn render_confirmation_overlay(frame: &mut Frame<'_>, area: Rect, group_name: &str) {
    let popup = centered_rect(72, 8, area);
    frame.render_widget(Clear, popup);
    let lines = vec![
        Line::styled(
            format!(" Delete the saved credential for “{group_name}”?"),
            Style::default().fg(Color::Yellow),
        ),
        Line::raw(""),
        Line::raw(" This may remove your only administrator access."),
        Line::raw(" Group history on the gateway is not deleted."),
        Line::raw(""),
        Line::styled(
            " Y confirms • N/Esc keeps it",
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" FORGET CREDENTIAL ")
                .border_style(Style::default().fg(Color::Yellow)),
        ),
        popup,
    );
}

fn render_text_overlay(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    value: &str,
    hint: Option<&str>,
) {
    let popup = centered_rect(70, 5, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let lines = vec![
        Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Cyan)),
            Span::raw(tail_by_width(value, inner.width.saturating_sub(3) as usize)),
        ]),
        Line::styled(
            hint.unwrap_or("Enter confirms • Esc cancels"),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
    let cursor_x = inner
        .x
        .saturating_add(2)
        .saturating_add(UnicodeWidthStr::width(value) as u16)
        .min(inner.right().saturating_sub(1));
    frame.set_cursor_position((cursor_x, inner.y));
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Length(height.min(area.height)),
            Constraint::Percentage(50),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn render_too_small(frame: &mut Frame<'_>, area: Rect, width: u16, height: u16) {
    frame.render_widget(
        Paragraph::new(format!(
            "Terminal too small\nResize to at least {width}×{height}"
        ))
        .style(Style::default().fg(Color::Yellow)),
        area,
    );
}

fn nickname_style(nickname: &str) -> Style {
    const COLORS: [Color; 6] = [
        Color::Cyan,
        Color::Magenta,
        Color::Yellow,
        Color::Blue,
        Color::Green,
        Color::LightRed,
    ];
    let hash = nickname.bytes().fold(0usize, |value, byte| {
        value.wrapping_mul(31).wrapping_add(byte as usize)
    });
    Style::default()
        .fg(COLORS[hash % COLORS.len()])
        .add_modifier(Modifier::BOLD)
}

fn short_time(timestamp_ms: u64) -> String {
    let seconds = timestamp_ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        (seconds / 3600) % 24,
        (seconds / 60) % 60,
        seconds % 60
    )
}

fn tail_by_width(value: &str, maximum_width: usize) -> String {
    let mut width = 0usize;
    let mut chars = Vec::new();
    for ch in value.chars().rev() {
        let char_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width.saturating_add(char_width) > maximum_width {
            break;
        }
        width += char_width;
        chars.push(ch);
    }
    chars.into_iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PROTOCOL_MAX;
    use ratatui::{backend::TestBackend, layout::Alignment};

    fn test_session() -> SessionInfo {
        let session_id = Uuid::new_v4();
        SessionInfo {
            protocol_version: PROTOCOL_MAX,
            gateway_id: Uuid::new_v4(),
            gateway_name: "Test gateway".to_owned(),
            group_id: Uuid::new_v4(),
            group_name: "Test".to_owned(),
            access_mode: GroupAccessMode::Public,
            role: GroupRole::Member,
            issued_credentials: None,
            issued_member_token: None,
            room_id: "general".to_owned(),
            room_name: "general".to_owned(),
            rooms: vec![RoomSummary {
                room_id: "general".to_owned(),
                room_name: "general".to_owned(),
                visibility: RoomVisibility::Public,
            }],
            session_id,
            members: vec![Peer {
                session_id,
                member_id: Uuid::new_v4(),
                nickname: "Alice".to_owned(),
                direct: None,
            }],
            history: Vec::new(),
            server_fingerprint: "1234:5678:90ab:cdef:1234:5678".to_owned(),
            endpoint: "127.0.0.1:7373".parse().unwrap(),
        }
    }

    #[test]
    fn input_tail_respects_double_width_characters() {
        assert_eq!(tail_by_width("ab中文", 4), "中文");
        assert_eq!(tail_by_width("ab中文", 5), "b中文");
    }

    #[test]
    fn utc_clock_rendering_is_stable() {
        assert_eq!(short_time(3_723_000), "01:02:03");
    }

    #[test]
    fn own_messages_are_right_aligned_across_group_reconnects() {
        let session = test_session();
        let app = ChatApp::new(&session);
        let items = VecDeque::from([
            UiItem::Chat(ChatRecord {
                sequence: 1,
                message_id: Uuid::new_v4(),
                sender: Peer {
                    session_id: Uuid::new_v4(),
                    member_id: app.member_id,
                    nickname: "Alice".to_owned(),
                    direct: None,
                },
                room_id: "general".to_owned(),
                sent_at_ms: 1,
                text: "my older message".to_owned(),
            }),
            UiItem::Chat(ChatRecord {
                sequence: 2,
                message_id: Uuid::new_v4(),
                sender: Peer {
                    session_id: Uuid::new_v4(),
                    member_id: Uuid::new_v4(),
                    nickname: "Bob".to_owned(),
                    direct: None,
                },
                room_id: "general".to_owned(),
                sent_at_ms: 2,
                text: "their message".to_owned(),
            }),
        ]);

        let lines = room_lines(&items, app.member_id);
        assert_eq!(lines[0].alignment, Some(Alignment::Right));
        assert_eq!(lines[1].alignment, None);
    }

    #[test]
    fn own_direct_messages_are_right_aligned() {
        let session = test_session();
        let records = VecDeque::from([DirectRecord {
            message_id: Uuid::new_v4(),
            sender: session.members[0].clone(),
            recipient_session_id: Uuid::new_v4(),
            sent_at_ms: 1,
            text: "hello".to_owned(),
        }]);

        let lines = direct_lines(&records, session.session_id);
        assert_eq!(lines[0].alignment, Some(Alignment::Right));
    }

    #[test]
    fn tiny_terminals_render_a_resize_hint_without_panicking() {
        let app = ChatApp::new(&test_session());
        let backend = TestBackend::new(18, 5);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_chat_app(frame, &app)).unwrap();
    }

    #[test]
    fn focus_mode_toggles_and_keeps_keyboard_focus_on_message_input() {
        let mut app = ChatApp::new(&test_session());
        app.focus = ChatFocus::Members;

        app.handle_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE))
            .unwrap();
        assert!(app.focus_mode);
        assert!(matches!(app.focus, ChatFocus::Input));

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(app.focus, ChatFocus::Input));

        app.handle_key(KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE))
            .unwrap();
        assert!(!app.focus_mode);
    }

    #[test]
    fn focus_mode_renders_only_the_active_conversation_and_input() {
        let mut app = ChatApp::new(&test_session());
        app.focus_mode = true;
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_chat_app(frame, &app)).unwrap();

        let rendered: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(rendered.contains("#general"));
        assert!(rendered.contains("MESSAGE"));
        assert!(!rendered.contains("LAN CHAT"));
        assert!(!rendered.contains("ROOMS / DMS"));
        assert!(!rendered.contains("MEMBERS"));
        assert!(!rendered.contains(&app.fingerprint));
    }

    #[test]
    fn focus_mode_supports_a_six_row_terminal() {
        let mut app = ChatApp::new(&test_session());
        app.focus_mode = true;
        let backend = TestBackend::new(24, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_chat_app(frame, &app)).unwrap();
    }

    #[test]
    fn invite_groups_prompt_in_the_lobby_when_no_token_is_saved() {
        let mut app = LobbyApp::new("Alice", None, &[]);
        app.groups.push(LobbyGroup {
            gateway_id: Uuid::new_v4(),
            group_id: Uuid::new_v4(),
            group_name: "Private".to_owned(),
            access_mode: GroupAccessMode::Invite,
            gateway_name: "Gateway".to_owned(),
            endpoint: "127.0.0.1:7373".parse().unwrap(),
            server_fingerprint: "1234:5678:90ab:cdef:1234:5678".to_owned(),
        });
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert!(action.is_none());
        assert!(matches!(app.mode, LobbyMode::InviteToken { .. }));
    }

    #[test]
    fn administrators_can_open_and_decide_join_requests() {
        let mut session = test_session();
        session.role = GroupRole::Admin;
        let mut app = ChatApp::new(&session);
        let action = app
            .handle_key(KeyEvent::new(KeyCode::F(4), KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(
            action,
            ChatKeyAction::Send(ClientMessage::ListJoinRequests)
        ));

        let request_id = Uuid::new_v4();
        app.handle_server_event(ClientEvent::Server(ServerMessage::JoinRequests {
            requests: vec![JoinRequestSummary {
                request_id,
                nickname: "Bob".to_owned(),
                requested_at_ms: 1,
            }],
        }));
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(
            action,
            ChatKeyAction::Send(ClientMessage::DecideJoinRequest {
                request_id: decided,
                approve: true,
            }) if decided == request_id
        ));
    }

    #[test]
    fn room_creation_toggles_to_private_before_sending() {
        let mut app = ChatApp::new(&test_session());
        app.handle_key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE))
            .unwrap();
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .unwrap();
        for character in "Secret".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE))
                .unwrap();
        }
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(
            action,
            ChatKeyAction::Send(ClientMessage::CreateRoom {
                name,
                visibility: RoomVisibility::Private,
            }) if name == "Secret"
        ));
    }

    #[test]
    fn administrator_member_panel_emits_persistent_bans() {
        let mut session = test_session();
        session.role = GroupRole::Admin;
        let mut app = ChatApp::new(&session);
        let action = app
            .handle_key(KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(
            action,
            ChatKeyAction::Send(ClientMessage::ListGroupMembers { offset: 0 })
        ));

        let member_id = Uuid::new_v4();
        app.handle_server_event(ClientEvent::Server(ServerMessage::GroupMembers {
            members: vec![GroupMemberSummary {
                member_id,
                nickname: "Bob".to_owned(),
                role: GroupRole::Member,
                status: GroupMemberStatus::Active,
            }],
            offset: 0,
            has_more: false,
        }));
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(
            action,
            ChatKeyAction::Send(ClientMessage::SetMemberBanned {
                member_id: target,
                banned: true,
            }) if target == member_id
        ));
    }

    #[test]
    fn rotated_tokens_replace_the_local_credential_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            CredentialStore::open_at(directory.path().join("credentials.json")).unwrap();
        let session = test_session();
        store
            .set(
                session.gateway_id,
                session.group_id,
                "lc_admin_old".to_owned(),
                Some("lc_invite_old".to_owned()),
            )
            .unwrap();
        persist_rotated_token(&mut store, &session, GroupTokenKind::Admin, "lc_admin_new").unwrap();
        persist_rotated_token(
            &mut store,
            &session,
            GroupTokenKind::Member,
            "lc_member_new",
        )
        .unwrap();
        persist_rotated_token(
            &mut store,
            &session,
            GroupTokenKind::Invite,
            "lc_invite_new",
        )
        .unwrap();
        let saved = store.get(session.gateway_id, session.group_id).unwrap();
        assert_eq!(saved.join_token, "lc_member_new");
        assert_eq!(saved.invite_token.as_deref(), Some("lc_invite_new"));
    }

    #[test]
    fn ordinary_members_rotate_only_their_own_token() {
        let mut session = test_session();
        session.role = GroupRole::Member;
        let mut app = ChatApp::new(&session);
        app.handle_key(KeyEvent::new(KeyCode::F(7), KeyModifiers::NONE))
            .unwrap();
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(
            action,
            ChatKeyAction::Send(ClientMessage::RotateGroupToken {
                kind: GroupTokenKind::Member,
            })
        ));
    }

    #[test]
    fn private_initiator_is_locked_until_a_reply() {
        let mut app = ChatApp::new(&test_session());
        let peer_id = Uuid::new_v4();
        app.private_chats.insert(
            peer_id,
            PrivateView {
                peer: Peer {
                    session_id: peer_id,
                    member_id: Uuid::new_v4(),
                    nickname: "Bob".to_owned(),
                    direct: None,
                },
                items: VecDeque::new(),
                status: Some(PrivateConversationStatus::AwaitingReply {
                    initiator_session_id: app.session_id,
                }),
                unread: 0,
                online: true,
            },
        );
        app.active = ConversationTarget::Private(peer_id);
        assert_eq!(
            app.private_send_locked().as_deref(),
            Some("waiting for Bob to reply")
        );
        app.private_chats.get_mut(&peer_id).unwrap().status =
            Some(PrivateConversationStatus::Active);
        assert!(app.private_send_locked().is_none());
    }
}
