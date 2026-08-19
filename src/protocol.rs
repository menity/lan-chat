use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use uuid::Uuid;

pub const PROTOCOL_MIN: u16 = 5;
pub const PROTOCOL_MAX: u16 = 5;
pub const DEFAULT_ROOM_ID: &str = "general";
pub const DEFAULT_ROOM_NAME: &str = "general";
pub const MAX_PLAINTEXT_FRAME: usize = 16 * 1024;
pub const MAX_CIPHERTEXT_FRAME: usize = MAX_PLAINTEXT_FRAME + 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peer {
    pub session_id: Uuid,
    pub member_id: Uuid,
    pub nickname: String,
    pub direct: Option<DirectPeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectPeerInfo {
    pub endpoint: SocketAddr,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomSummary {
    pub room_id: String,
    pub room_name: String,
    pub visibility: RoomVisibility,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoomVisibility {
    Public,
    Private,
}

impl RoomVisibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupSummary {
    pub group_id: Uuid,
    pub group_name: String,
    pub access_mode: GroupAccessMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupAccessMode {
    Public,
    Invite,
    Approval,
}

impl GroupAccessMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Invite => "invite",
            Self::Approval => "approval",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Member,
    Admin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupMemberStatus {
    Active,
    Banned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMemberSummary {
    pub member_id: Uuid,
    pub nickname: String,
    pub role: GroupRole,
    pub status: GroupMemberStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomMemberSummary {
    pub member_id: Uuid,
    pub nickname: String,
    pub group_role: GroupRole,
    pub included: bool,
    pub is_owner: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupTokenKind {
    Member,
    Admin,
    Invite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedGroupCredentials {
    pub admin_token: String,
    pub invite_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinRequestSummary {
    pub request_id: Uuid,
    pub nickname: String,
    pub requested_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatRecord {
    pub sequence: u64,
    pub message_id: Uuid,
    pub sender: Peer,
    pub room_id: String,
    pub sent_at_ms: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectRecord {
    pub message_id: Uuid,
    pub sender: Peer,
    pub recipient_session_id: Uuid,
    pub sent_at_ms: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PrivateConversationStatus {
    AwaitingReply { initiator_session_id: Uuid },
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        protocol_min: u16,
        protocol_max: u16,
        nickname: String,
        direct_port: Option<u16>,
        direct_fingerprint: Option<String>,
    },
    JoinGroup {
        group_id: Uuid,
        credential: Option<String>,
    },
    CreateGroup {
        name: String,
        access_mode: GroupAccessMode,
    },
    Chat {
        room_id: String,
        message_id: Uuid,
        text: String,
    },
    CreateRoom {
        name: String,
        visibility: RoomVisibility,
    },
    JoinRoom {
        room_id: String,
    },
    LeaveRoom {
        room_id: String,
    },
    LoadHistory {
        room_id: String,
        before_sequence: u64,
        limit: u16,
    },
    ListJoinRequests,
    DecideJoinRequest {
        request_id: Uuid,
        approve: bool,
    },
    ListGroupMembers {
        offset: u32,
    },
    SetMemberBanned {
        member_id: Uuid,
        banned: bool,
    },
    RotateGroupToken {
        kind: GroupTokenKind,
    },
    ListRoomMembers {
        room_id: String,
        offset: u32,
    },
    SetRoomMember {
        room_id: String,
        member_id: Uuid,
        included: bool,
    },
    PrivateChat {
        peer_session_id: Uuid,
        message_id: Uuid,
        text: String,
    },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    GatewayWelcome {
        protocol_version: u16,
        gateway_id: Uuid,
        gateway_name: String,
        groups: Vec<GroupSummary>,
    },
    JoinPending {
        group_id: Uuid,
        request_id: Uuid,
        request_token: String,
    },
    Welcome {
        protocol_version: u16,
        group_id: Uuid,
        group_name: String,
        access_mode: GroupAccessMode,
        role: GroupRole,
        issued_credentials: Option<Box<IssuedGroupCredentials>>,
        issued_member_token: Option<String>,
        room_id: String,
        room_name: String,
        rooms: Vec<RoomSummary>,
        session_id: Uuid,
        members: Vec<Peer>,
        history: Vec<ChatRecord>,
    },
    Chat {
        message: ChatRecord,
    },
    RoomCreated {
        room: RoomSummary,
    },
    RoomJoined {
        room: RoomSummary,
        history: Vec<ChatRecord>,
    },
    RoomLeft {
        room_id: String,
    },
    HistoryPage {
        room_id: String,
        messages: Vec<ChatRecord>,
        has_more: bool,
    },
    JoinRequests {
        requests: Vec<JoinRequestSummary>,
    },
    GroupMembers {
        members: Vec<GroupMemberSummary>,
        offset: u32,
        has_more: bool,
    },
    GroupTokenRotated {
        kind: GroupTokenKind,
        token: String,
    },
    RoomMembers {
        room_id: String,
        members: Vec<RoomMemberSummary>,
        offset: u32,
        has_more: bool,
    },
    PrivateMessage {
        message: DirectRecord,
        status: PrivateConversationStatus,
    },
    PrivateClosed {
        peer_session_id: Uuid,
    },
    MemberJoined {
        member: Peer,
    },
    MemberLeft {
        session_id: Uuid,
    },
    Error {
        code: String,
        message: String,
    },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryBeacon {
    pub app: String,
    pub protocol_min: u16,
    pub protocol_max: u16,
    pub gateway_id: Uuid,
    pub gateway_name: String,
    pub port: u16,
    pub server_fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_messages_round_trip() {
        let original = ClientMessage::Chat {
            room_id: DEFAULT_ROOM_ID.to_owned(),
            message_id: Uuid::nil(),
            text: "你好，LAN".to_owned(),
        };

        let json = serde_json::to_vec(&original).unwrap();
        let decoded: ClientMessage = serde_json::from_slice(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
