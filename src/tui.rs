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
    layout::{Alignment, Constraint, Direction, Layout, Rect},
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
const APP_BACKGROUND: Color = Color::Rgb(9, 11, 16);
const ROW_BACKGROUND: Color = Color::Rgb(10, 12, 17);
const SELECTED_BACKGROUND: Color = Color::Rgb(25, 30, 39);
const PRIMARY_TEXT: Color = Color::Rgb(214, 219, 230);
const SECONDARY_TEXT: Color = Color::Rgb(169, 177, 196);
const MUTED_TEXT: Color = Color::Rgb(139, 148, 166);
const ACCENT_BLUE: Color = Color::LightBlue;
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
                                app.status = "正在刷新附近群组…".to_owned();
                                start_discovery(app.nickname.clone(), discovery_tx.clone());
                            }
                        }
                    }
                    Some(Ok(Event::Paste(text))) => app.paste(&text),
                    Some(Ok(_)) => {}
                    Some(Err(_)) => app.status = "终端输入异常，请重试".to_owned(),
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
                    app.status = "正在刷新附近群组…".to_owned();
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
        .map_err(|_| "搜索局域网群组失败，请稍后重试".to_owned());
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
            status: initial_status.unwrap_or("正在搜索局域网群组…").to_owned(),
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
                "未发现网关，请先在局域网内启动网关".to_owned()
            } else {
                format!("已连接 {} 个网关，按 C 创建第一个群组", self.gateways.len())
            }
        } else {
            format!("已发现 {} 个群组", self.groups.len())
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
                        self.status = "请粘贴群组邀请令牌".to_owned();
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
                        self.status = "未发现可用网关，请先启动网关".to_owned();
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
                        self.status = "删除本机凭据后，下次加入需重新验证".to_owned();
                        Ok(None)
                    } else {
                        self.status = "本机没有保存该群组的凭据".to_owned();
                        Ok(None)
                    }
                }
                _ => Ok(None),
            },
            LobbyMode::Input { kind, value } => match key.code {
                KeyCode::Esc => {
                    self.mode = LobbyMode::Browse;
                    self.status = "已取消".to_owned();
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
                                    self.status = "未发现可用网关".to_owned();
                                    return Ok(None);
                                };
                                self.mode = LobbyMode::ChooseAccess {
                                    group_name,
                                    endpoint,
                                    fingerprint,
                                    selected: 0,
                                };
                                self.status = "选择群组的加入方式".to_owned();
                                Ok(None)
                            }
                            Err(_) => {
                                self.status = "群组名称无效，请输入 1–64 个字符".to_owned();
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
                                self.status = "请输入类似 192.168.1.20:7373 的网关地址".to_owned();
                                Ok(None)
                            }
                        },
                        LobbyInputKind::Nickname => match sanitize_nickname(&value) {
                            Ok(nickname) => Ok(Some(LobbyAction::SetNickname(nickname))),
                            Err(_) => {
                                self.status = "昵称无效，请输入 1–32 个字符".to_owned();
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
                    self.status = "已取消".to_owned();
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
                    self.status = "已取消".to_owned();
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
                    Err(_) => {
                        self.status = "邀请令牌格式无效".to_owned();
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
                    self.status = "已保留本机凭据".to_owned();
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
                                        app.status = "已发送".to_owned();
                                    }
                                    Err(error) => app.status = format!("发送失败：{error}"),
                                }
                            }
                        }
                    }
                    Some(Ok(Event::Paste(text))) => app.paste(&text),
                    Some(Ok(_)) => {}
                    Some(Err(error)) => app.status = format!("终端输入异常：{error}"),
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
                        app.status = "连接已关闭，按 Esc 返回群组".to_owned();
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
            status: "加密连接已建立".to_owned(),
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
                self.status = "发现新房间，选中后按回车加入".to_owned();
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
                self.status = "已加入房间".to_owned();
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
                    self.status = "私有房间访问权限已移除".to_owned();
                } else {
                    if let Some(room) = self.rooms.get_mut(&room_id) {
                        room.joined = false;
                    }
                    self.status = "已离开房间".to_owned();
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
                        "已到达聊天记录开头".to_owned()
                    } else {
                        format!("已从网关载入 {added} 条更早消息")
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
                    "没有待处理的加入申请".to_owned()
                } else {
                    format!("{} 条待处理的加入申请", requests.len())
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
                self.status = format!("共 {} 名群组成员", members.len());
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
                self.status = format!("共 {} 名可加入私有房间的成员", members.len());
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
                self.status = "新令牌已保存到本机".to_owned();
                self.overlay = Some(ChatOverlay::RotatedToken { kind, token });
            }
            ClientEvent::Server(ServerMessage::PrivateMessage { message, status }) => {
                self.handle_private_message(message, status);
            }
            ClientEvent::Server(ServerMessage::PrivateClosed { peer_session_id }) => {
                if let Some(private) = self.private_chats.get_mut(&peer_session_id) {
                    private.online = false;
                }
                self.status = "对方已离开，私聊已关闭".to_owned();
            }
            ClientEvent::Server(ServerMessage::MemberJoined { member }) => {
                self.members
                    .insert(member.session_id, member.nickname.clone());
                self.push_room_notice("general", format!("{} 加入了群组", member.nickname));
            }
            ClientEvent::Server(ServerMessage::MemberLeft { session_id }) => {
                if let Some(nickname) = self.members.remove(&session_id) {
                    self.push_room_notice("general", format!("{nickname} 离开了群组"));
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
                self.status = "连接正常".to_owned();
            }
            ClientEvent::Server(ServerMessage::Welcome { .. }) => {
                self.status = "已忽略重复的欢迎消息".to_owned();
            }
            ClientEvent::Server(ServerMessage::GatewayWelcome { .. }) => {
                self.status = "已忽略意外的网关欢迎消息".to_owned();
            }
            ClientEvent::Server(ServerMessage::JoinPending { .. }) => {
                self.status = "已忽略意外的待审批消息".to_owned();
            }
            ClientEvent::Disconnected(reason) => {
                self.connected = false;
                self.status = format!("{reason}，按 Esc 返回群组");
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
                    .unwrap_or_else(|| "未知成员".to_owned()),
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
            self.status = format!("{} 已回复，可以继续私聊", view.peer.nickname);
        } else if matches!(status, PrivateConversationStatus::AwaitingReply { .. }) {
            self.status = "私聊已发起，需要等待对方回复一句".to_owned();
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
                "已进入精简模式，按 F3 恢复完整界面".to_owned()
            } else {
                "已恢复完整界面".to_owned()
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
                            self.status = "不能封禁群组管理员".to_owned();
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
                            self.status = "房主与群组管理员始终保留访问权限".to_owned();
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
                        self.status = "按 Y 确认作废旧令牌".to_owned();
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
                self.status = "正在载入加入申请…".to_owned();
                Ok(ChatKeyAction::Send(ClientMessage::ListJoinRequests))
            }
            KeyCode::F(5) => {
                let ConversationTarget::Room(room_id) = &self.active else {
                    self.status = "请先选择一个私有房间".to_owned();
                    return Ok(ChatKeyAction::None);
                };
                if !self
                    .rooms
                    .get(room_id)
                    .is_some_and(|room| room.summary.visibility == RoomVisibility::Private)
                {
                    self.status = "当前房间是公开房间".to_owned();
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
                        self.status = "正在从网关载入更早的聊天记录…".to_owned();
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
                    self.status = "请先加入该房间再发送消息".to_owned();
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
                    self.status = "对方已离线".to_owned();
                    return Ok(ChatKeyAction::None);
                }
                if matches!(
                    private.status,
                    Some(PrivateConversationStatus::AwaitingReply {
                        initiator_session_id
                    }) if initiator_session_id == self.session_id
                ) {
                    self.status = "需要等待对方回复一句".to_owned();
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
                            self.status = "正在加入房间…".to_owned();
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
                    self.status = "发送第一条消息后，需要等待对方回复一句".to_owned();
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
                self.status = format!("消息不能超过 {MAX_MESSAGE_BYTES} 字节");
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

    fn own_nickname(&self) -> &str {
        self.members
            .get(&self.session_id)
            .map(String::as_str)
            .unwrap_or("")
    }

    fn active_name(&self) -> &str {
        match &self.active {
            ConversationTarget::Room(room_id) => self
                .rooms
                .get(room_id)
                .map(room_display_name)
                .unwrap_or("聊天室"),
            ConversationTarget::Private(peer_id) => self
                .private_chats
                .get(peer_id)
                .map(|chat| chat.peer.nickname.as_str())
                .unwrap_or("私聊"),
        }
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
        self.status = "已清空本地显示".to_owned();
    }

    fn private_send_locked(&self) -> Option<String> {
        let ConversationTarget::Private(peer_id) = self.active else {
            return None;
        };
        let private = self.private_chats.get(&peer_id)?;
        if !private.online {
            return Some("对方已离线".to_owned());
        }
        match private.status {
            Some(PrivateConversationStatus::AwaitingReply {
                initiator_session_id,
            }) if initiator_session_id == self.session_id => Some("等待对方首次回复".to_owned()),
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
    if area.width < 30 || area.height < 12 {
        render_too_small(frame, area, 30, 12);
        return;
    }
    frame.render_widget(
        Block::default().style(Style::default().bg(APP_BACKGROUND)),
        area,
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(2),
        ])
        .split(area);
    render_lobby_header(frame, rows[0], app);

    if area.width >= 78 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
            .split(rows[1]);
        render_group_list(frame, columns[0], app);
        render_group_details(frame, columns[1], app);
    } else {
        render_group_list(frame, rows[1], app);
    }
    render_lobby_footer(frame, rows[2], app);

    match &app.mode {
        LobbyMode::Input { kind, value } => {
            let title = match kind {
                LobbyInputKind::CreateGroup => " 创建群组 ",
                LobbyInputKind::DirectJoin => " 指定网关地址 ",
                LobbyInputKind::Nickname => " 更换匿名昵称 ",
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
                " 邀请令牌 ",
                &hidden,
                Some("粘贴令牌后按回车确认  ·  Esc 取消"),
            );
        }
        LobbyMode::ConfirmForget { group_index } => {
            let group_name = app
                .groups
                .get(*group_index)
                .map(|group| group.group_name.as_str())
                .unwrap_or("所选群组");
            render_confirmation_overlay(frame, area, group_name);
        }
        LobbyMode::Browse => {}
    }
}

fn render_lobby_header(frame: &mut Frame<'_>, area: Rect, app: &LobbyApp) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(32),
            Constraint::Percentage(34),
        ])
        .split(Rect::new(area.x, area.y.saturating_add(1), area.width, 1));
    frame.render_widget(
        Paragraph::new(" 局域网聊天").style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        columns[0],
    );

    let (connection_text, connection_style) = if app.refreshing {
        ("正在刷新", Style::default().fg(Color::Cyan))
    } else if app.gateways.is_empty() && app.groups.is_empty() {
        ("未发现网关", Style::default().fg(Color::DarkGray))
    } else {
        ("网关已连接", Style::default().fg(Color::Green))
    };
    frame.render_widget(
        Paragraph::new(connection_text)
            .alignment(Alignment::Center)
            .style(connection_style),
        columns[1],
    );
    frame.render_widget(
        Paragraph::new(format!("{} ", app.nickname))
            .alignment(Alignment::Right)
            .style(Style::default().fg(Color::Rgb(169, 177, 196))),
        columns[2],
    );
}

fn render_group_list(frame: &mut Frame<'_>, area: Rect, app: &LobbyApp) {
    let horizontal_padding = if area.width >= 52 { 3 } else { 1 };
    let content = Rect::new(
        area.x.saturating_add(horizontal_padding),
        area.y.saturating_add(1),
        area.width
            .saturating_sub(horizontal_padding.saturating_mul(2)),
        area.height.saturating_sub(2),
    );
    if content.width == 0 || content.height == 0 {
        return;
    }

    let title_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(Rect::new(content.x, content.y, content.width, 1));
    frame.render_widget(
        Paragraph::new("附近群组").style(
            Style::default()
                .fg(Color::Rgb(179, 187, 204))
                .add_modifier(Modifier::BOLD),
        ),
        title_columns[0],
    );
    frame.render_widget(
        Paragraph::new(format!("{} 个", app.groups.len()))
            .alignment(Alignment::Right)
            .style(Style::default().fg(Color::DarkGray)),
        title_columns[1],
    );

    if app.groups.is_empty() {
        let message = if app.refreshing {
            "正在搜索附近群组…"
        } else {
            "暂未发现群组"
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(message, Style::default().fg(Color::Rgb(150, 158, 176))),
                Line::raw(""),
                Line::styled(
                    "按 C 在已连接网关上创建群组",
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Rect::new(
                content.x,
                content.y.saturating_add(3),
                content.width,
                content.height.saturating_sub(3),
            ),
        );
        return;
    }

    let mut row_y = content.y.saturating_add(3);
    for (index, group) in app.groups.iter().enumerate() {
        if row_y.saturating_add(3) > content.bottom() {
            break;
        }
        let selected = index == app.selected;
        let row = Rect::new(content.x, row_y, content.width, 3);
        let row_background = if selected {
            SELECTED_BACKGROUND
        } else {
            ROW_BACKGROUND
        };
        frame.render_widget(
            Block::default().style(Style::default().bg(row_background)),
            row,
        );

        let group_text = group.group_name.clone();
        let access_text = lobby_access_label(group.access_mode);
        let line_width = row.width.saturating_sub(2) as usize;
        let gap_width = line_width
            .saturating_sub(UnicodeWidthStr::width(group_text.as_str()))
            .saturating_sub(UnicodeWidthStr::width(access_text))
            .max(1);
        let mut group_style = Style::default()
            .fg(if selected {
                Color::LightBlue
            } else {
                Color::Rgb(214, 219, 230)
            })
            .bg(row_background);
        if selected {
            group_style = group_style.add_modifier(Modifier::BOLD);
        }
        let access_style = Style::default()
            .fg(Color::Rgb(139, 148, 166))
            .bg(row_background);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(group_text, group_style),
                Span::raw(" ".repeat(gap_width)),
                Span::styled(access_text, access_style),
            ]))
            .style(access_style),
            Rect::new(
                row.x.saturating_add(1),
                row.y.saturating_add(1),
                row.width.saturating_sub(2),
                1,
            ),
        );
        row_y = row_y.saturating_add(3);
    }
}

fn render_group_details(frame: &mut Frame<'_>, area: Rect, app: &LobbyApp) {
    let mut inner = area;
    inner.x = inner.x.saturating_add(4);
    inner.y = inner.y.saturating_add(2);
    inner.width = inner.width.saturating_sub(7);
    inner.height = inner.height.saturating_sub(4);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let Some(group) = app.groups.get(app.selected) else {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "群组详情",
                    Style::default()
                        .fg(Color::Rgb(179, 187, 204))
                        .add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::styled(
                    "选择群组后，这里会显示加入信息。",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
            .wrap(Wrap { trim: false }),
            inner,
        );
        return;
    };

    let credential = if app
        .known_credentials
        .contains(&(group.gateway_id, group.group_id))
    {
        "已保存"
    } else {
        "未保存"
    };
    let lines = vec![
        Line::styled(
            group.group_name.clone(),
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        detail_line("访问方式", lobby_access_label(group.access_mode)),
        Line::raw(""),
        detail_line("接入网关", &group.gateway_name),
        Line::raw(""),
        detail_line("网关地址", &group.endpoint.to_string()),
        Line::raw(""),
        detail_line("本机凭据", credential),
        Line::raw(""),
        Line::styled("安全指纹", Style::default().fg(Color::DarkGray)),
        Line::styled(
            group.server_fingerprint.clone(),
            Style::default().fg(Color::Rgb(169, 177, 196)),
        ),
        Line::raw(""),
        Line::styled(
            "回车  进入群组",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}  "), Style::default().fg(Color::DarkGray)),
        Span::styled(
            value.to_owned(),
            Style::default().fg(Color::Rgb(214, 219, 230)),
        ),
    ])
}

fn lobby_access_label(access_mode: GroupAccessMode) -> &'static str {
    match access_mode {
        GroupAccessMode::Public => "公开",
        GroupAccessMode::Invite => "邀请制",
        GroupAccessMode::Approval => "审批加入",
    }
}

fn render_lobby_footer(frame: &mut Frame<'_>, area: Rect, app: &LobbyApp) {
    let inner = Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(1),
        area.width.saturating_sub(4),
        1,
    );
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if area.width >= 92 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
            .split(inner);
        frame.render_widget(
            Paragraph::new("C  创建群组    N  更换昵称    R  刷新    Q  退出")
                .style(Style::default().fg(Color::Rgb(169, 177, 196))),
            columns[0],
        );
        if !app.status.starts_with("已发现") {
            frame.render_widget(
                Paragraph::new(app.status.as_str())
                    .alignment(Alignment::Right)
                    .style(Style::default().fg(Color::Rgb(139, 148, 166))),
                columns[1],
            );
        }
    } else {
        frame.render_widget(
            Paragraph::new(" C 创建   N 改名   R 刷新   Q 退出")
                .style(Style::default().fg(Color::Rgb(169, 177, 196))),
            inner,
        );
    }
}

fn render_chat_app(frame: &mut Frame<'_>, app: &ChatApp) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(APP_BACKGROUND)),
        area,
    );
    if app.focus_mode {
        if area.width < 24 || area.height < 6 {
            render_too_small(frame, area, 24, 6);
            return;
        }
        let input_height = if app.private_send_locked().is_some() {
            3
        } else {
            2
        };
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(1),
                Constraint::Length(input_height),
            ])
            .split(area);
        render_focus_header(frame, rows[0], app);
        render_active_messages(frame, rows[1], app);
        render_chat_input(frame, rows[2], app);
        return;
    }
    if area.width < 30 || area.height < 10 {
        render_too_small(frame, area, 30, 10);
        return;
    }
    let input_height = if app.private_send_locked().is_some() {
        3
    } else {
        2
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(input_height),
            Constraint::Length(1),
        ])
        .split(area);
    render_chat_header(frame, rows[0], app);
    render_chat_body(frame, rows[1], app);
    let input_area = if area.width >= 78 && matches!(app.active, ConversationTarget::Private(_)) {
        Rect::new(
            rows[2].x.saturating_add(26),
            rows[2].y,
            rows[2].width.saturating_sub(26),
            rows[2].height,
        )
    } else {
        rows[2]
    };
    render_chat_input(frame, input_area, app);
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
    let header = Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(1),
        area.width.saturating_sub(4),
        1,
    );
    if header.width == 0 {
        return;
    }
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(32),
            Constraint::Percentage(34),
        ])
        .split(header);
    frame.render_widget(
        Paragraph::new(app.group_name.as_str()).style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        columns[0],
    );
    let connection = if !app.connected {
        "连接已断开"
    } else if matches!(app.active, ConversationTarget::Private(_)) {
        "点对点已加密"
    } else {
        "网关已连接"
    };
    frame.render_widget(
        Paragraph::new(connection)
            .alignment(Alignment::Center)
            .style(Style::default().fg(if app.connected {
                Color::Green
            } else {
                Color::LightRed
            })),
        columns[1],
    );
    frame.render_widget(
        Paragraph::new(app.own_nickname())
            .alignment(Alignment::Right)
            .style(Style::default().fg(SECONDARY_TEXT)),
        columns[2],
    );
}

fn render_focus_header(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let header = Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(1),
        area.width.saturating_sub(4),
        1,
    );
    if header.width == 0 {
        return;
    }
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(38),
            Constraint::Percentage(24),
            Constraint::Percentage(38),
        ])
        .split(header);
    frame.render_widget(
        Paragraph::new(app.active_name()).style(
            Style::default()
                .fg(ACCENT_BLUE)
                .add_modifier(Modifier::BOLD),
        ),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new("精简模式")
            .alignment(Alignment::Center)
            .style(Style::default().fg(MUTED_TEXT)),
        columns[1],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("F3", Style::default().fg(ACCENT_BLUE)),
            Span::styled(" 退出精简模式", Style::default().fg(MUTED_TEXT)),
        ]))
        .alignment(Alignment::Right),
        columns[2],
    );
}

fn render_chat_body(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    if area.width >= 78 {
        if matches!(app.active, ConversationTarget::Private(_)) {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(24),
                    Constraint::Length(2),
                    Constraint::Min(30),
                ])
                .split(area);
            render_conversations(frame, columns[0], app);
            render_active_messages(frame, columns[2], app);
        } else {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(24),
                    Constraint::Length(2),
                    Constraint::Min(30),
                    Constraint::Length(2),
                    Constraint::Length(22),
                ])
                .split(area);
            render_conversations(frame, columns[0], app);
            render_active_messages(frame, columns[2], app);
            render_members(frame, columns[4], app);
        }
    } else if area.width >= 55 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(21),
                Constraint::Length(1),
                Constraint::Min(30),
            ])
            .split(area);
        if app.focus == ChatFocus::Members && !matches!(app.active, ConversationTarget::Private(_))
        {
            render_members(frame, columns[0], app);
        } else {
            render_conversations(frame, columns[0], app);
        }
        render_active_messages(frame, columns[2], app);
    } else {
        render_active_messages(frame, area, app);
    }
}

fn render_conversations(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let entries = app.conversation_entries();
    let inner = Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(1),
        area.width.saturating_sub(4),
        area.height.saturating_sub(2),
    );
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new("房间与私聊").style(
            Style::default()
                .fg(SECONDARY_TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let mut row_y = inner.y.saturating_add(2);
    for (index, target) in entries.iter().enumerate() {
        let ConversationTarget::Room(room_id) = target else {
            continue;
        };
        if row_y >= inner.bottom() {
            return;
        }
        let room = &app.rooms[room_id];
        let meta = if room.unread > 0 {
            format!("{} 条", room.unread)
        } else if !room.joined {
            "未加入".to_owned()
        } else if room.summary.visibility == RoomVisibility::Private {
            "私有".to_owned()
        } else {
            "公开".to_owned()
        };
        render_navigation_row(
            frame,
            Rect::new(inner.x, row_y, inner.width, 2),
            room_display_name(room),
            &meta,
            app.focus == ChatFocus::Conversations && index == app.selected_conversation,
            *target == app.active,
        );
        row_y = row_y.saturating_add(2);
    }

    if entries
        .iter()
        .any(|target| matches!(target, ConversationTarget::Private(_)))
        && row_y < inner.bottom()
    {
        frame.render_widget(
            Paragraph::new("私聊")
                .style(Style::default().fg(MUTED_TEXT).add_modifier(Modifier::BOLD)),
            Rect::new(inner.x, row_y, inner.width, 1),
        );
        row_y = row_y.saturating_add(1);
    }

    for (index, target) in entries.iter().enumerate() {
        let ConversationTarget::Private(peer_id) = target else {
            continue;
        };
        if row_y >= inner.bottom() {
            return;
        }
        let private = &app.private_chats[peer_id];
        let meta = if private.unread > 0 {
            format!("{} 条", private.unread)
        } else if !private.online {
            "离线".to_owned()
        } else if matches!(
            private.status,
            Some(PrivateConversationStatus::AwaitingReply {
                initiator_session_id
            }) if initiator_session_id == app.session_id
        ) {
            "等待回复".to_owned()
        } else {
            "私聊".to_owned()
        };
        render_navigation_row(
            frame,
            Rect::new(inner.x, row_y, inner.width, 2),
            &private.peer.nickname,
            &meta,
            app.focus == ChatFocus::Conversations && index == app.selected_conversation,
            *target == app.active,
        );
        row_y = row_y.saturating_add(2);
    }
}

fn render_navigation_row(
    frame: &mut Frame<'_>,
    area: Rect,
    name: &str,
    meta: &str,
    selected: bool,
    active: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let background = if selected {
        SELECTED_BACKGROUND
    } else if active {
        ROW_BACKGROUND
    } else {
        APP_BACKGROUND
    };
    frame.render_widget(
        Block::default().style(Style::default().bg(background)),
        area,
    );
    let line = Rect::new(
        area.x.saturating_add(1),
        area.y,
        area.width.saturating_sub(2),
        1,
    );
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(4), Constraint::Length(8)])
        .split(line);
    let mut name_style = Style::default()
        .fg(if selected || active {
            ACCENT_BLUE
        } else {
            PRIMARY_TEXT
        })
        .bg(background);
    if selected {
        name_style = name_style.add_modifier(Modifier::BOLD);
    }
    frame.render_widget(Paragraph::new(name).style(name_style), columns[0]);
    frame.render_widget(
        Paragraph::new(meta)
            .alignment(Alignment::Right)
            .style(Style::default().fg(MUTED_TEXT).bg(background)),
        columns[1],
    );
}

fn render_members(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let members = app.member_entries();
    let inner = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(format!("在线成员 {}", members.len())).style(
            Style::default()
                .fg(SECONDARY_TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );
    let mut row_y = inner.y.saturating_add(2);
    for (index, (_, nickname)) in members.iter().enumerate() {
        if row_y >= inner.bottom() {
            break;
        }
        let selected = app.focus == ChatFocus::Members && index == app.selected_member;
        let background = if selected {
            SELECTED_BACKGROUND
        } else {
            APP_BACKGROUND
        };
        let row = Rect::new(inner.x, row_y, inner.width, 2);
        frame.render_widget(Block::default().style(Style::default().bg(background)), row);
        frame.render_widget(
            Paragraph::new(nickname.as_str()).style(
                Style::default()
                    .fg(if selected { ACCENT_BLUE } else { PRIMARY_TEXT })
                    .bg(background)
                    .add_modifier(if selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
            Rect::new(
                row.x.saturating_add(1),
                row.y,
                row.width.saturating_sub(2),
                1,
            ),
        );
        row_y = row_y.saturating_add(2);
    }
}

fn render_active_messages(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let (title, status, lines) = match &app.active {
        ConversationTarget::Room(room_id) => {
            let room = &app.rooms[room_id];
            (
                room_display_name(room).to_owned(),
                if room.summary.visibility == RoomVisibility::Private {
                    "私有房间".to_owned()
                } else {
                    String::new()
                },
                room_lines(&room.items, app.member_id),
            )
        }
        ConversationTarget::Private(peer_id) => {
            let private = &app.private_chats[peer_id];
            (
                private.peer.nickname.clone(),
                app.private_send_locked().unwrap_or_else(|| {
                    if private.online {
                        "点对点已加密".to_owned()
                    } else {
                        "对方已离线".to_owned()
                    }
                }),
                direct_lines(&private.items, app.session_id),
            )
        }
    };
    let horizontal_padding = if area.width >= 40 { 2 } else { 1 };
    let title_height = if app.focus_mode { 0 } else { 2 };
    let inner = Rect::new(
        area.x.saturating_add(horizontal_padding),
        area.y.saturating_add(title_height),
        area.width
            .saturating_sub(horizontal_padding.saturating_mul(2)),
        area.height.saturating_sub(title_height),
    );
    if !app.focus_mode && area.height > 0 {
        let header = Rect::new(
            area.x.saturating_add(horizontal_padding),
            area.y,
            area.width
                .saturating_sub(horizontal_padding.saturating_mul(2)),
            1,
        );
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(8), Constraint::Length(18)])
            .split(header);
        frame.render_widget(
            Paragraph::new(title).style(
                Style::default()
                    .fg(ACCENT_BLUE)
                    .add_modifier(Modifier::BOLD),
            ),
            columns[0],
        );
        if !status.is_empty() {
            frame.render_widget(
                Paragraph::new(status)
                    .alignment(Alignment::Right)
                    .style(Style::default().fg(MUTED_TEXT)),
                columns[1],
            );
        }
    }
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

fn room_display_name(room: &RoomView) -> &str {
    if room.summary.room_id == "general" {
        "大厅"
    } else {
        room.summary.room_name.as_str()
    }
}

fn room_lines(items: &VecDeque<UiItem>, own_member_id: Uuid) -> Vec<Line<'static>> {
    if items.is_empty() {
        return vec![Line::styled(
            "还没有消息。",
            Style::default().fg(MUTED_TEXT),
        )];
    }
    let mut lines = Vec::new();
    for item in items {
        match item {
            UiItem::Notice(notice) => lines.push(Line::styled(
                format!("系统  {notice}"),
                Style::default().fg(MUTED_TEXT),
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
            "发送第一条消息后，需要等待对方回复一句。",
            Style::default().fg(MUTED_TEXT),
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
                Span::styled(
                    format!("  {}", short_time(sent_at_ms)),
                    Style::default().fg(MUTED_TEXT),
                ),
            ])
            .right_aligned(),
        );
        for continuation in text_lines {
            lines.push(Line::raw(continuation.to_owned()).right_aligned());
        }
    } else {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{}  ", short_time(sent_at_ms)),
                Style::default().fg(MUTED_TEXT),
            ),
            Span::styled(format!("{nickname}  "), nickname_style(nickname)),
            Span::raw(first.to_owned()),
        ]));
        for continuation in text_lines {
            lines.push(Line::raw(format!("          {continuation}")));
        }
    }
}

fn render_chat_input(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let locked = app.private_send_locked();
    let horizontal_padding = if area.width >= 40 { 2 } else { 1 };
    if locked.is_some() {
        frame.render_widget(
            Paragraph::new("对方回复一句后，才能继续发送").style(Style::default().fg(MUTED_TEXT)),
            Rect::new(
                area.x.saturating_add(horizontal_padding),
                area.y,
                area.width
                    .saturating_sub(horizontal_padding.saturating_mul(2)),
                1,
            ),
        );
    }
    let composer_y = if locked.is_some() {
        area.y.saturating_add(2)
    } else {
        area.y.saturating_add(1)
    };
    let composer = Rect::new(
        area.x.saturating_add(horizontal_padding),
        composer_y,
        area.width
            .saturating_sub(horizontal_padding.saturating_mul(2)),
        1,
    );
    frame.render_widget(
        Block::default().style(Style::default().bg(ROW_BACKGROUND)),
        composer,
    );
    let shown = tail_by_width(&app.input, (composer.width as usize).saturating_sub(2));
    let content = if locked.is_some() {
        "等待回复…".to_owned()
    } else if shown.is_empty() {
        "输入消息…".to_owned()
    } else {
        shown.clone()
    };
    frame.render_widget(
        Paragraph::new(content).style(
            Style::default()
                .fg(if locked.is_some() || shown.is_empty() {
                    MUTED_TEXT
                } else {
                    PRIMARY_TEXT
                })
                .bg(ROW_BACKGROUND),
        ),
        Rect::new(
            composer.x.saturating_add(1),
            composer.y,
            composer.width.saturating_sub(2),
            1,
        ),
    );
    if locked.is_none() && app.focus == ChatFocus::Input && app.overlay.is_none() {
        let cursor_x = composer
            .x
            .saturating_add(1)
            .saturating_add(UnicodeWidthStr::width(shown.as_str()) as u16)
            .min(composer.right().saturating_sub(1));
        frame.set_cursor_position((cursor_x, composer.y));
    }
}

fn render_chat_footer(frame: &mut Frame<'_>, area: Rect, app: &ChatApp) {
    let inner = Rect::new(
        area.x.saturating_add(2),
        area.y,
        area.width.saturating_sub(4),
        1,
    );
    if inner.width == 0 {
        return;
    }
    let shortcuts = if matches!(app.active, ConversationTarget::Private(_)) {
        Line::from(vec![
            Span::styled("Esc", Style::default().fg(ACCENT_BLUE)),
            Span::styled(" 返回    ", Style::default().fg(MUTED_TEXT)),
            Span::styled("F3", Style::default().fg(ACCENT_BLUE)),
            Span::styled(" 精简模式", Style::default().fg(MUTED_TEXT)),
        ])
    } else {
        Line::from(vec![
            Span::styled("Tab", Style::default().fg(ACCENT_BLUE)),
            Span::styled(" 切换区域    ", Style::default().fg(MUTED_TEXT)),
            Span::styled("F2", Style::default().fg(ACCENT_BLUE)),
            Span::styled(" 创建房间    ", Style::default().fg(MUTED_TEXT)),
            Span::styled("F3", Style::default().fg(ACCENT_BLUE)),
            Span::styled(" 精简模式    ", Style::default().fg(MUTED_TEXT)),
            Span::styled("Esc", Style::default().fg(ACCENT_BLUE)),
            Span::styled(" 返回群组", Style::default().fg(MUTED_TEXT)),
        ])
    };
    let routine_status = matches!(
        app.status.as_str(),
        "加密连接已建立" | "已发送" | "已进入精简模式，按 F3 恢复完整界面" | "已恢复完整界面"
    );
    if area.width >= 110 && !routine_status {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(64), Constraint::Min(20)])
            .split(inner);
        frame.render_widget(Paragraph::new(shortcuts), columns[0]);
        frame.render_widget(
            Paragraph::new(app.status.as_str())
                .alignment(Alignment::Right)
                .style(Style::default().fg(MUTED_TEXT)),
            columns[1],
        );
    } else {
        frame.render_widget(Paragraph::new(shortcuts), inner);
    }
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
        RoomVisibility::Public => "公开，所有群组成员可见",
        RoomVisibility::Private => "私有，仅指定成员可见",
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Cyan)),
            Span::raw(name.to_owned()),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" 可见范围：", Style::default().fg(Color::DarkGray)),
            Span::styled(visibility_label, Style::default().fg(ACCENT_BLUE)),
        ]),
        Line::raw(""),
        Line::styled(
            " Tab 切换可见范围    Enter 创建    Esc 取消",
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 创建房间 ")
                .border_style(Style::default().fg(ACCENT_BLUE)),
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
            " 正在载入成员…",
            Style::default().fg(ACCENT_BLUE),
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
                (GroupRole::Admin, _) => "管理员",
                (_, GroupMemberStatus::Active) => "正常",
                (_, GroupMemberStatus::Banned) => "已封禁",
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
            " Enter/B 封禁    PgUp/PgDn 翻页    R 刷新    第 {offset} 项{}    Esc 关闭",
            if has_more { " +" } else { "" }
        ),
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" 群组成员 {} ", members.len()))
                .border_style(Style::default().fg(ACCENT_BLUE)),
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
            " 正在载入私有房间成员…",
            Style::default().fg(ACCENT_BLUE),
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
                "管理员"
            } else if member.is_owner {
                "房主"
            } else if member.included {
                "可访问"
            } else {
                "未加入"
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
            " Enter/Space 切换权限    PgUp/PgDn 翻页    第 {offset} 项{}    Esc 关闭",
            if has_more { " +" } else { "" }
        ),
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 私有房间成员 ")
                .border_style(Style::default().fg(ACCENT_BLUE)),
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
        " 轮换后旧令牌会立即失效。",
        Style::default().fg(Color::LightRed),
    )];
    lines.push(Line::raw(""));
    for (index, (_, label)) in choices.iter().enumerate() {
        lines.push(Line::styled(
            format!(" {} {label}", if index == selected { "▶" } else { " " }),
            Style::default().fg(if index == selected {
                ACCENT_BLUE
            } else {
                Color::White
            }),
        ));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        if confirming {
            " 按 Y 确认轮换    Esc 取消"
        } else {
            " ↑/↓ 选择    Enter 继续    Esc 关闭"
        },
        Style::default().fg(if confirming {
            Color::LightRed
        } else {
            Color::DarkGray
        }),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 轮换群组令牌 ")
                .border_style(Style::default().fg(Color::LightRed)),
        ),
        popup,
    );
}

fn token_rotation_choices(
    role: GroupRole,
    access_mode: GroupAccessMode,
) -> Vec<(GroupTokenKind, &'static str)> {
    if role == GroupRole::Member {
        return vec![(GroupTokenKind::Member, "我的成员令牌")];
    }
    let mut choices = vec![(GroupTokenKind::Admin, "管理员令牌")];
    if access_mode == GroupAccessMode::Invite {
        choices.push((GroupTokenKind::Invite, "共享邀请令牌"));
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
        GroupTokenKind::Member => "新成员令牌，请妥善保管：",
        GroupTokenKind::Admin => "新管理员令牌，请勿分享：",
        GroupTokenKind::Invite => "新邀请令牌，仅分享给预期成员：",
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(" 已保存到本机凭据文件。", Style::default().fg(Color::Green)),
            Line::raw(""),
            Line::styled(format!(" {label}"), Style::default().fg(Color::LightRed)),
            Line::raw(format!(" {token}")),
            Line::raw(""),
            Line::styled(" Enter 或 Esc 关闭", Style::default().fg(Color::DarkGray)),
        ])
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 令牌已轮换 ")
                .border_style(Style::default().fg(ACCENT_BLUE)),
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
            " 正在载入申请…",
            Style::default().fg(ACCENT_BLUE),
        ));
    } else if requests.is_empty() {
        lines.push(Line::styled(
            " 没有待处理的申请。",
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
        " ↑/↓ 选择    Enter/A 通过    D/Delete 拒绝    R 刷新    Esc 关闭",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" 加入申请 {} ", requests.len()))
                .border_style(Style::default().fg(ACCENT_BLUE)),
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
            " 凭据已保存到本机的私有客户端数据文件。",
            Style::default().fg(Color::Green),
        ),
        Line::raw(""),
        Line::styled(
            " 管理员令牌，请勿分享：",
            Style::default().fg(Color::LightRed),
        ),
        Line::raw(format!(" {}", credentials.admin_token)),
    ];
    if let Some(invite_token) = &credentials.invite_token {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            " 邀请令牌，仅分享给预期成员：",
            Style::default().fg(ACCENT_BLUE),
        ));
        lines.push(Line::raw(format!(" {invite_token}")));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        " Enter 或 Esc 关闭此页面",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 群组凭据 ")
                .border_style(Style::default().fg(ACCENT_BLUE)),
        ),
        popup,
    );
}

fn render_access_overlay(frame: &mut Frame<'_>, area: Rect, selected: usize) {
    let popup = centered_rect(72, 11, area);
    frame.render_widget(Clear, popup);
    let choices = [
        ("1  公开", "局域网内任何人都可以加入"),
        ("2  邀请制", "需要群组邀请令牌"),
        ("3  审批加入", "每次加入由管理员审批"),
    ];
    let mut lines = vec![Line::raw(" 选择群组的加入方式："), Line::raw("")];
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
        " ↑/↓ 或 1–3 选择  ·  回车创建  ·  Esc 取消",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 加入方式 ")
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
            format!(" 删除“{group_name}”在本机保存的凭据？"),
            Style::default().fg(Color::LightRed),
        ),
        Line::raw(""),
        Line::raw(" 这可能会移除你仅有的管理员权限。"),
        Line::raw(" 网关上的群组与历史消息不会被删除。"),
        Line::raw(""),
        Line::styled(
            " Y 确认删除  ·  N/Esc 保留",
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 删除本机凭据 ")
                .border_style(Style::default().fg(Color::LightRed)),
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
            hint.unwrap_or("回车确认  ·  Esc 取消"),
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
        Paragraph::new(format!("终端窗口太小\n请调整到至少 {width}×{height}"))
            .style(Style::default().fg(Color::LightRed)),
        area,
    );
}

fn nickname_style(nickname: &str) -> Style {
    const COLORS: [Color; 6] = [
        Color::Cyan,
        Color::Magenta,
        Color::LightBlue,
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
    use ratatui::{backend::TestBackend, buffer::Buffer, layout::Alignment};

    fn compact_buffer_text(buffer: &Buffer) -> String {
        buffer
            .content()
            .iter()
            .filter_map(|cell| {
                let symbol = cell.symbol();
                (!symbol.trim().is_empty()).then_some(symbol)
            })
            .collect()
    }

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
        let own_line: String = lines[0]
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(own_line.contains("my older message"));
        assert!(!own_line.contains("Alice"));
        let other_header: String = lines[1]
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(other_header.contains("Bob"));
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
        let own_line: String = lines[0]
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(!own_line.contains("Alice"));
    }

    #[test]
    fn tiny_terminals_render_a_resize_hint_without_panicking() {
        let app = ChatApp::new(&test_session());
        let backend = TestBackend::new(18, 5);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_chat_app(frame, &app)).unwrap();
    }

    #[test]
    fn narrow_chat_keeps_navigation_and_the_active_conversation() {
        let app = ChatApp::new(&test_session());
        let backend = TestBackend::new(60, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_chat_app(frame, &app)).unwrap();
        let rendered = compact_buffer_text(terminal.backend().buffer());

        assert!(rendered.contains("房间与私聊"));
        assert!(rendered.contains("大厅"));
        assert!(rendered.contains("输入消息"));
        assert!(!rendered.contains("在线成员"));
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

        let rendered = compact_buffer_text(terminal.backend().buffer());
        assert!(rendered.contains("大厅"));
        assert!(rendered.contains("精简模式"));
        assert!(rendered.contains("F3退出精简模式"));
        assert!(rendered.contains("输入消息"));
        assert!(!rendered.contains("房间与私聊"));
        assert!(!rendered.contains("在线成员"));
        assert!(!rendered.contains("创建房间"));
    }

    #[test]
    fn wide_chat_uses_the_compact_chinese_three_column_layout() {
        let mut session = test_session();
        session.group_name = "项目讨论".to_owned();
        session.room_name = "大厅".to_owned();
        session.rooms[0].room_name = "大厅".to_owned();
        session.members.push(Peer {
            session_id: Uuid::new_v4(),
            member_id: Uuid::new_v4(),
            nickname: "沉静的松鼠".to_owned(),
            direct: None,
        });
        let app = ChatApp::new(&session);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_chat_app(frame, &app)).unwrap();
        let rendered = compact_buffer_text(terminal.backend().buffer());

        for expected in [
            "项目讨论",
            "网关已连接",
            "房间与私聊",
            "大厅",
            "公开",
            "在线成员1",
            "沉静的松鼠",
            "输入消息",
            "Tab切换区域",
            "F2创建房间",
            "F3精简模式",
            "Esc返回群组",
        ] {
            assert!(rendered.contains(expected), "missing {expected:?}");
        }
        for removed in ["#", "◇", "●", "▶", "ROOMS", "MEMBERS", "MESSAGE"] {
            assert!(
                !rendered.contains(removed),
                "found stale glyph or copy {removed:?}"
            );
        }
        assert!(
            terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .all(|cell| { cell.fg != Color::Yellow && cell.bg != Color::Yellow }),
            "the chat must not use the old yellow accent"
        );
    }

    #[test]
    fn waiting_private_chat_hides_members_and_explains_the_reply_gate() {
        let mut app = ChatApp::new(&test_session());
        let peer_id = Uuid::new_v4();
        app.private_chats.insert(
            peer_id,
            PrivateView {
                peer: Peer {
                    session_id: peer_id,
                    member_id: Uuid::new_v4(),
                    nickname: "沉静的松鼠".to_owned(),
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
        app.sync_conversation_selection();
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_chat_app(frame, &app)).unwrap();
        let rendered = compact_buffer_text(terminal.backend().buffer());

        assert!(rendered.contains("点对点已加密"));
        assert!(rendered.contains("等待对方首次回复"));
        assert!(rendered.contains("对方回复一句后，才能继续发送"));
        assert!(rendered.contains("等待回复"));
        assert!(!rendered.contains("在线成员"));
        for removed in ["@", "⏳", "◇", "●", "▶"] {
            assert!(!rendered.contains(removed), "found stale glyph {removed:?}");
        }
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
    fn wide_lobby_matches_the_compact_chinese_information_architecture() {
        let gateway_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let mut app = LobbyApp::new("安静的星光", None, &[(gateway_id, group_id)]);
        app.status = "已发现 1 个群组".to_owned();
        app.groups.push(LobbyGroup {
            gateway_id,
            group_id,
            group_name: "项目讨论".to_owned(),
            access_mode: GroupAccessMode::Invite,
            gateway_name: "二楼网关".to_owned(),
            endpoint: "192.168.1.20:7373".parse().unwrap(),
            server_fingerprint: "1234:5678:90ab:cdef:1234:5678".to_owned(),
        });

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_lobby(frame, &app)).unwrap();
        let rendered = compact_buffer_text(terminal.backend().buffer());

        for expected in [
            "局域网聊天",
            "网关已连接",
            "附近群组",
            "项目讨论",
            "访问方式",
            "本机凭据",
            "回车进入群组",
            "C创建群组",
        ] {
            assert!(rendered.contains(expected), "missing {expected:?}");
        }
        for removed in ["LANCHAT", "GROUPS", "ACTIONS", "Joinselectedgroup"] {
            assert!(!rendered.contains(removed), "found stale copy {removed:?}");
        }
        assert!(
            terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .all(|cell| cell.bg != Color::Yellow),
            "the lobby must not restore the old yellow status bar"
        );
    }

    #[test]
    fn narrow_lobby_keeps_the_group_list_and_compact_shortcuts() {
        let mut app = LobbyApp::new("安静的星光", None, &[]);
        app.groups.push(LobbyGroup {
            gateway_id: Uuid::new_v4(),
            group_id: Uuid::new_v4(),
            group_name: "项目讨论".to_owned(),
            access_mode: GroupAccessMode::Public,
            gateway_name: "二楼网关".to_owned(),
            endpoint: "192.168.1.20:7373".parse().unwrap(),
            server_fingerprint: "1234:5678:90ab:cdef:1234:5678".to_owned(),
        });

        let backend = TestBackend::new(60, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_lobby(frame, &app)).unwrap();
        let rendered = compact_buffer_text(terminal.backend().buffer());

        assert!(rendered.contains("项目讨论"));
        assert!(rendered.contains("C创建"));
        assert!(!rendered.contains("安全指纹"));
    }

    #[test]
    fn lobby_access_picker_uses_chinese_copy() {
        let mut app = LobbyApp::new("安静的星光", None, &[]);
        app.mode = LobbyMode::ChooseAccess {
            group_name: "项目讨论".to_owned(),
            endpoint: "127.0.0.1:7373".parse().unwrap(),
            fingerprint: "1234:5678:90ab:cdef:1234:5678".to_owned(),
            selected: 1,
        };

        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_lobby(frame, &app)).unwrap();
        let rendered = compact_buffer_text(terminal.backend().buffer());

        assert!(rendered.contains("加入方式"));
        assert!(rendered.contains("邀请制"));
        assert!(!rendered.contains("Public"));
        assert!(!rendered.contains("Approval"));
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
            Some("等待对方首次回复")
        );
        app.private_chats.get_mut(&peer_id).unwrap().status =
            Some(PrivateConversationStatus::Active);
        assert!(app.private_send_locked().is_none());
    }
}
