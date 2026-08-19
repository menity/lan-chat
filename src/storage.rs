use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use subtle::ConstantTimeEq;
use tokio::task;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::protocol::{
    ChatRecord, DEFAULT_ROOM_ID, DEFAULT_ROOM_NAME, GroupAccessMode, GroupMemberStatus,
    GroupMemberSummary, GroupRole, GroupSummary, GroupTokenKind, IssuedGroupCredentials,
    JoinRequestSummary, Peer, RoomMemberSummary, RoomSummary, RoomVisibility,
};
use crate::security::is_valid_group_credential;

const DATABASE_FILE: &str = "gateway.sqlite3";
const DATABASE_KEY_FILE: &str = "gateway-db.key";
const NOISE_KEY_FILE: &str = "gateway-noise.key";
const ENCRYPTED_BODY_VERSION: u8 = 1;
const NONCE_LENGTH: usize = 24;
const MAX_PENDING_JOIN_REQUESTS: i64 = 256;
const JOIN_REQUEST_PAGE_SIZE: i64 = 100;
const MEMBER_PAGE_SIZE: usize = 40;
const MAX_GROUP_MEMBERS: i64 = 10_000;

type StoredGroupAuthorization = (String, Option<Vec<u8>>, Option<Vec<u8>>);

pub struct CreatedGroup {
    pub summary: GroupSummary,
    pub credentials: IssuedGroupCredentials,
    pub creator_member_id: Uuid,
}

pub enum JoinAuthorization {
    Allowed {
        role: GroupRole,
        member_id: Uuid,
        issued_member_token: Option<String>,
    },
    InviteRequired,
    ApprovalRequired,
    Pending {
        request_id: Uuid,
        request_token: String,
    },
    Rejected,
    Banned,
    MemberLimit,
    InvalidCredential,
}

#[derive(Clone)]
pub struct GatewayStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    connection: Mutex<Connection>,
    key: Zeroizing<[u8; 32]>,
    data_dir: Option<PathBuf>,
}

impl std::fmt::Debug for GatewayStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayStore")
            .field("data_dir", &self.inner.data_dir)
            .finish_non_exhaustive()
    }
}

impl GatewayStore {
    pub async fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        task::spawn_blocking(move || Self::open_blocking(&data_dir))
            .await
            .context("database initialization task panicked")?
    }

    pub fn open_blocking(data_dir: &Path) -> Result<Self> {
        create_private_directory(data_dir)?;
        let key = load_or_create_key(&data_dir.join(DATABASE_KEY_FILE))?;
        let connection = Connection::open(data_dir.join(DATABASE_FILE))
            .context("failed to open the gateway SQLite database")?;
        initialize_connection(&connection)?;
        initialize_schema(&connection)?;
        Ok(Self {
            inner: Arc::new(StoreInner {
                connection: Mutex::new(connection),
                key: Zeroizing::new(key),
                data_dir: Some(data_dir.to_path_buf()),
            }),
        })
    }

    #[cfg(test)]
    fn open_in_memory() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).context("failed to generate a test database key")?;
        let connection = Connection::open_in_memory()?;
        initialize_connection(&connection)?;
        initialize_schema(&connection)?;
        Ok(Self {
            inner: Arc::new(StoreInner {
                connection: Mutex::new(connection),
                key: Zeroizing::new(key),
                data_dir: None,
            }),
        })
    }

    pub fn data_dir(&self) -> Option<&Path> {
        self.inner.data_dir.as_deref()
    }

    pub async fn gateway_id(&self) -> Result<Uuid> {
        self.run(|connection, _| {
            let stored: Option<String> = connection
                .query_row(
                    "SELECT value FROM gateway_meta WHERE key = 'gateway_id'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(stored) = stored {
                return Uuid::parse_str(&stored).context("database contains an invalid gateway id");
            }
            let id = Uuid::new_v4();
            connection.execute(
                "INSERT INTO gateway_meta(key, value) VALUES ('gateway_id', ?1)",
                [id.to_string()],
            )?;
            Ok(id)
        })
        .await
    }

    pub async fn list_groups(&self) -> Result<Vec<GroupSummary>> {
        self.run(|connection, _| {
            let mut statement = connection.prepare(
                "SELECT group_id, name, access_mode FROM groups
                 ORDER BY name COLLATE NOCASE, group_id",
            )?;
            let groups = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|(id, name, access_mode)| {
                    Ok(GroupSummary {
                        group_id: Uuid::parse_str(&id)?,
                        group_name: name,
                        access_mode: parse_access_mode(&access_mode)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(groups)
        })
        .await
    }

    pub async fn create_group(&self, group_name: String) -> Result<GroupSummary> {
        Ok(self
            .create_group_with_access(group_name, GroupAccessMode::Public)
            .await?
            .summary)
    }

    pub async fn create_group_with_access(
        &self,
        group_name: String,
        access_mode: GroupAccessMode,
    ) -> Result<CreatedGroup> {
        self.run(move |connection, _| {
            let existing: Option<String> = connection
                .query_row(
                    "SELECT group_id FROM groups WHERE name = ?1 COLLATE NOCASE",
                    [&group_name],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.is_some() {
                bail!("a group with that name already exists");
            }
            let admin_token = generate_credential("admin")?;
            let invite_token = (access_mode == GroupAccessMode::Invite)
                .then(|| generate_credential("invite"))
                .transpose()?;
            let group = GroupSummary {
                group_id: Uuid::new_v4(),
                group_name,
                access_mode,
            };
            let creator_member_id = Uuid::new_v4();
            let admin_hash = credential_hash(&admin_token)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute(
                "INSERT INTO groups(
                    group_id, name, access_mode, admin_token_hash, invite_token_hash, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    group.group_id.to_string(),
                    group.group_name,
                    group.access_mode.as_str(),
                    admin_hash,
                    invite_token.as_deref().map(credential_hash).transpose()?,
                    now_ms_i64()
                ],
            )?;
            transaction.execute(
                "INSERT INTO rooms(
                    room_id, group_id, name, visibility, next_sequence, created_at_ms
                 ) VALUES (?1, ?2, ?3, 'public', 1, ?4)",
                params![
                    DEFAULT_ROOM_ID,
                    group.group_id.to_string(),
                    DEFAULT_ROOM_NAME,
                    now_ms_i64()
                ],
            )?;
            transaction.execute(
                "INSERT INTO group_members(
                    member_id, group_id, credential_hash, role, status,
                    last_nickname, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, 'admin', 'active', ?4, ?5, ?5)",
                params![
                    creator_member_id.to_string(),
                    group.group_id.to_string(),
                    credential_hash(&admin_token)?,
                    "administrator",
                    now_ms_i64(),
                ],
            )?;
            transaction.commit()?;
            Ok(CreatedGroup {
                summary: group,
                credentials: IssuedGroupCredentials {
                    admin_token,
                    invite_token,
                },
                creator_member_id,
            })
        })
        .await
    }

    pub async fn group(&self, group_id: Uuid) -> Result<Option<GroupSummary>> {
        self.run(move |connection, _| {
            let row: Option<(String, String, String)> = connection
                .query_row(
                    "SELECT group_id, name, access_mode FROM groups WHERE group_id = ?1",
                    [group_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            row.map(|(id, name, access_mode)| {
                Ok(GroupSummary {
                    group_id: Uuid::parse_str(&id)?,
                    group_name: name,
                    access_mode: parse_access_mode(&access_mode)?,
                })
            })
            .transpose()
        })
        .await
    }

    pub async fn authorize_join(
        &self,
        group_id: Uuid,
        credential: Option<String>,
        nickname: String,
    ) -> Result<JoinAuthorization> {
        self.run(move |connection, _| {
            let group: Option<StoredGroupAuthorization> = connection
                .query_row(
                    "SELECT access_mode, admin_token_hash, invite_token_hash
                     FROM groups WHERE group_id = ?1",
                    [group_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((access_mode, admin_hash, invite_hash)) = group else {
                bail!("group not found");
            };
            let access_mode = parse_access_mode(&access_mode)?;
            let supplied_hash = credential.as_deref().map(credential_hash).transpose()?;
            if let Some(supplied_hash) = &supplied_hash {
                let member: Option<(String, String, String)> = connection
                    .query_row(
                        "SELECT member_id, role, status FROM group_members
                         WHERE group_id = ?1 AND credential_hash = ?2",
                        params![group_id.to_string(), supplied_hash],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                if let Some((member_id, role, status)) = member {
                    if status == "banned" {
                        return Ok(JoinAuthorization::Banned);
                    }
                    connection.execute(
                        "UPDATE group_members SET last_nickname = ?1, updated_at_ms = ?2
                         WHERE member_id = ?3 AND group_id = ?4",
                        params![nickname, now_ms_i64(), member_id, group_id.to_string()],
                    )?;
                    return Ok(JoinAuthorization::Allowed {
                        role: parse_group_role(&role)?,
                        member_id: Uuid::parse_str(&member_id)?,
                        issued_member_token: None,
                    });
                }
            }
            if supplied_hash
                .as_ref()
                .zip(admin_hash.as_ref())
                .is_some_and(|(supplied, stored)| hash_matches(supplied, stored))
            {
                let member_id = insert_group_member(
                    connection,
                    group_id,
                    credential
                        .as_deref()
                        .context("admin credential is missing")?,
                    GroupRole::Admin,
                    &nickname,
                )?;
                return Ok(JoinAuthorization::Allowed {
                    role: GroupRole::Admin,
                    member_id,
                    issued_member_token: None,
                });
            }
            match access_mode {
                GroupAccessMode::Public => {
                    if credential.is_some() {
                        return Ok(JoinAuthorization::InvalidCredential);
                    }
                    issue_member(connection, group_id, &nickname)
                }
                GroupAccessMode::Invite => {
                    if credential.is_none() {
                        return Ok(JoinAuthorization::InviteRequired);
                    }
                    if supplied_hash
                        .as_ref()
                        .zip(invite_hash.as_ref())
                        .is_some_and(|(supplied, stored)| hash_matches(supplied, stored))
                    {
                        issue_member(connection, group_id, &nickname)
                    } else {
                        Ok(JoinAuthorization::InvalidCredential)
                    }
                }
                GroupAccessMode::Approval => {
                    let Some(credential) = credential else {
                        return Ok(JoinAuthorization::ApprovalRequired);
                    };
                    let hash = credential_hash(&credential)?;
                    let request: Option<(String, String)> = connection
                        .query_row(
                            "SELECT request_id, status FROM join_requests
                             WHERE group_id = ?1 AND request_token_hash = ?2",
                            params![group_id.to_string(), hash],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    match request {
                        Some((request_id, status)) if status == "approved" => {
                            let authorization = issue_member(connection, group_id, &nickname)?;
                            connection.execute(
                                "DELETE FROM join_requests
                                 WHERE group_id = ?1 AND request_id = ?2",
                                params![group_id.to_string(), request_id],
                            )?;
                            Ok(authorization)
                        }
                        Some((request_id, status)) if status == "pending" => {
                            Ok(JoinAuthorization::Pending {
                                request_id: Uuid::parse_str(&request_id)?,
                                request_token: credential,
                            })
                        }
                        Some((_, status)) if status == "rejected" => {
                            Ok(JoinAuthorization::Rejected)
                        }
                        Some(_) | None => Ok(JoinAuthorization::InvalidCredential),
                    }
                }
            }
        })
        .await
    }

    pub async fn create_join_request(
        &self,
        group_id: Uuid,
        nickname: String,
    ) -> Result<(Uuid, String)> {
        self.run(move |connection, _| {
            let request_id = Uuid::new_v4();
            let request_token = generate_credential("request")?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let access_mode: Option<String> = transaction
                .query_row(
                    "SELECT access_mode FROM groups WHERE group_id = ?1",
                    [group_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if access_mode.as_deref() != Some("approval") {
                bail!("group does not accept approval requests");
            }
            let pending: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM join_requests
                 WHERE group_id = ?1 AND status = 'pending'",
                [group_id.to_string()],
                |row| row.get(0),
            )?;
            if pending >= MAX_PENDING_JOIN_REQUESTS {
                bail!("this group has too many pending join requests");
            }
            transaction.execute(
                "INSERT INTO join_requests(
                    request_id, group_id, nickname, request_token_hash, status, requested_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'pending', ?5)",
                params![
                    request_id.to_string(),
                    group_id.to_string(),
                    nickname,
                    credential_hash(&request_token)?,
                    now_ms_i64()
                ],
            )?;
            transaction.commit()?;
            Ok((request_id, request_token))
        })
        .await
    }

    pub async fn update_member_nickname(
        &self,
        group_id: Uuid,
        member_id: Uuid,
        nickname: String,
    ) -> Result<()> {
        self.run(move |connection, _| {
            let changed = connection.execute(
                "UPDATE group_members SET last_nickname = ?1, updated_at_ms = ?2
                 WHERE group_id = ?3 AND member_id = ?4",
                params![
                    nickname,
                    now_ms_i64(),
                    group_id.to_string(),
                    member_id.to_string()
                ],
            )?;
            if changed != 1 {
                bail!("member not found");
            }
            Ok(())
        })
        .await
    }

    pub async fn pending_join_requests(&self, group_id: Uuid) -> Result<Vec<JoinRequestSummary>> {
        self.run(move |connection, _| {
            let mut statement = connection.prepare(
                "SELECT request_id, nickname, requested_at_ms FROM join_requests
                 WHERE group_id = ?1 AND status = 'pending'
                 ORDER BY requested_at_ms, request_id LIMIT ?2",
            )?;
            let requests = statement
                .query_map(
                    params![group_id.to_string(), JOIN_REQUEST_PAGE_SIZE],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|(request_id, nickname, requested_at_ms)| {
                    Ok(JoinRequestSummary {
                        request_id: Uuid::parse_str(&request_id)?,
                        nickname,
                        requested_at_ms: u64::try_from(requested_at_ms).unwrap_or_default(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(requests)
        })
        .await
    }

    pub async fn decide_join_request(
        &self,
        group_id: Uuid,
        request_id: Uuid,
        approve: bool,
    ) -> Result<bool> {
        self.run(move |connection, _| {
            let changed = connection.execute(
                "UPDATE join_requests SET status = ?1
                 WHERE group_id = ?2 AND request_id = ?3 AND status = 'pending'",
                params![
                    if approve { "approved" } else { "rejected" },
                    group_id.to_string(),
                    request_id.to_string()
                ],
            )?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn rooms(&self, group_id: Uuid) -> Result<Vec<RoomSummary>> {
        self.run(move |connection, _| {
            let mut statement = connection.prepare(
                "SELECT room_id, name, visibility FROM rooms WHERE group_id = ?1
                 ORDER BY CASE WHEN room_id = 'general' THEN 0 ELSE 1 END,
                          name COLLATE NOCASE",
            )?;
            let rooms = statement
                .query_map([group_id.to_string()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|(room_id, room_name, visibility)| {
                    Ok(RoomSummary {
                        room_id,
                        room_name,
                        visibility: parse_room_visibility(&visibility)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(rooms)
        })
        .await
    }

    pub async fn create_room(&self, group_id: Uuid, room_name: String) -> Result<RoomSummary> {
        self.create_room_with_visibility(group_id, room_name, RoomVisibility::Public, None)
            .await
    }

    pub async fn rooms_for_member(
        &self,
        group_id: Uuid,
        member_id: Uuid,
    ) -> Result<Vec<RoomSummary>> {
        self.run(move |connection, _| {
            let mut statement = connection.prepare(
                "SELECT r.room_id, r.name, r.visibility FROM rooms r
                 WHERE r.group_id = ?1 AND (
                    r.visibility = 'public' OR EXISTS (
                        SELECT 1 FROM room_members rm
                        WHERE rm.group_id = r.group_id AND rm.room_id = r.room_id
                          AND rm.member_id = ?2
                    ) OR EXISTS (
                        SELECT 1 FROM group_members gm
                        WHERE gm.group_id = r.group_id AND gm.member_id = ?2
                          AND gm.role = 'admin' AND gm.status = 'active'
                    )
                 )
                 ORDER BY CASE WHEN r.room_id = 'general' THEN 0 ELSE 1 END,
                          r.name COLLATE NOCASE",
            )?;
            let rooms = statement
                .query_map(
                    params![group_id.to_string(), member_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|(room_id, room_name, visibility)| {
                    Ok(RoomSummary {
                        room_id,
                        room_name,
                        visibility: parse_room_visibility(&visibility)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(rooms)
        })
        .await
    }

    pub async fn create_room_with_visibility(
        &self,
        group_id: Uuid,
        room_name: String,
        visibility: RoomVisibility,
        creator_member_id: Option<Uuid>,
    ) -> Result<RoomSummary> {
        self.run(move |connection, _| {
            let existing: Option<String> = connection
                .query_row(
                    "SELECT room_id FROM rooms
                     WHERE group_id = ?1 AND name = ?2 COLLATE NOCASE",
                    params![group_id.to_string(), room_name],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.is_some() {
                bail!("a room with that name already exists");
            }
            if visibility == RoomVisibility::Private && creator_member_id.is_none() {
                bail!("a private room requires an owner");
            }
            let room = RoomSummary {
                room_id: Uuid::new_v4().simple().to_string(),
                room_name,
                visibility,
            };
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute(
                "INSERT INTO rooms(
                    room_id, group_id, name, visibility, next_sequence, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![
                    room.room_id,
                    group_id.to_string(),
                    room.room_name,
                    room.visibility.as_str(),
                    now_ms_i64()
                ],
            )?;
            if let Some(creator_member_id) = creator_member_id
                && visibility == RoomVisibility::Private
            {
                transaction.execute(
                    "INSERT INTO room_members(group_id, room_id, member_id, role, added_at_ms)
                     VALUES (?1, ?2, ?3, 'owner', ?4)",
                    params![
                        group_id.to_string(),
                        room.room_id,
                        creator_member_id.to_string(),
                        now_ms_i64()
                    ],
                )?;
            }
            transaction.commit()?;
            Ok(room)
        })
        .await
    }

    pub async fn member_can_access_room(
        &self,
        group_id: Uuid,
        room_id: String,
        member_id: Uuid,
    ) -> Result<bool> {
        self.run(move |connection, _| {
            let allowed: Option<i64> = connection
                .query_row(
                    "SELECT 1 FROM rooms r
                     WHERE r.group_id = ?1 AND r.room_id = ?2 AND (
                        r.visibility = 'public' OR EXISTS (
                            SELECT 1 FROM room_members rm
                            WHERE rm.group_id = r.group_id AND rm.room_id = r.room_id
                              AND rm.member_id = ?3
                        ) OR EXISTS (
                            SELECT 1 FROM group_members gm
                            WHERE gm.group_id = r.group_id AND gm.member_id = ?3
                              AND gm.role = 'admin' AND gm.status = 'active'
                        )
                     )",
                    params![group_id.to_string(), room_id, member_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(allowed.is_some())
        })
        .await
    }

    pub async fn group_members(
        &self,
        group_id: Uuid,
        offset: u32,
    ) -> Result<(Vec<GroupMemberSummary>, bool)> {
        self.run(move |connection, _| {
            let mut statement = connection.prepare(
                "SELECT member_id, last_nickname, role, status FROM group_members
                 WHERE group_id = ?1
                 ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,
                          last_nickname COLLATE NOCASE, member_id
                 LIMIT ?2 OFFSET ?3",
            )?;
            let rows = statement
                .query_map(
                    params![
                        group_id.to_string(),
                        i64::try_from(MEMBER_PAGE_SIZE + 1).unwrap_or(41),
                        i64::from(offset)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = rows.len() > MEMBER_PAGE_SIZE;
            let members = rows
                .into_iter()
                .take(MEMBER_PAGE_SIZE)
                .map(|(member_id, nickname, role, status)| {
                    Ok(GroupMemberSummary {
                        member_id: Uuid::parse_str(&member_id)?,
                        nickname,
                        role: parse_group_role(&role)?,
                        status: parse_member_status(&status)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((members, has_more))
        })
        .await
    }

    pub async fn set_member_banned(
        &self,
        group_id: Uuid,
        member_id: Uuid,
        banned: bool,
    ) -> Result<bool> {
        self.run(move |connection, _| {
            let changed = connection.execute(
                "UPDATE group_members SET status = ?1, updated_at_ms = ?2
                 WHERE group_id = ?3 AND member_id = ?4 AND role != 'admin'",
                params![
                    if banned { "banned" } else { "active" },
                    now_ms_i64(),
                    group_id.to_string(),
                    member_id.to_string()
                ],
            )?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn rotate_group_token(
        &self,
        group_id: Uuid,
        actor_member_id: Uuid,
        kind: GroupTokenKind,
    ) -> Result<String> {
        self.run(move |connection, _| {
            let actor_role: Option<String> = connection
                .query_row(
                    "SELECT role FROM group_members
                     WHERE group_id = ?1 AND member_id = ?2 AND status = 'active'",
                    params![group_id.to_string(), actor_member_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let permitted = match kind {
                GroupTokenKind::Member => actor_role.as_deref() == Some("member"),
                GroupTokenKind::Admin | GroupTokenKind::Invite => {
                    actor_role.as_deref() == Some("admin")
                }
            };
            if !permitted {
                bail!("the active membership cannot rotate this token");
            }
            let token = generate_credential(match kind {
                GroupTokenKind::Member => "member",
                GroupTokenKind::Admin => "admin",
                GroupTokenKind::Invite => "invite",
            })?;
            let hash = credential_hash(&token)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            match kind {
                GroupTokenKind::Member => {
                    let changed = transaction.execute(
                        "UPDATE group_members SET credential_hash = ?1, updated_at_ms = ?2
                         WHERE group_id = ?3 AND member_id = ?4
                           AND role = 'member' AND status = 'active'",
                        params![
                            hash,
                            now_ms_i64(),
                            group_id.to_string(),
                            actor_member_id.to_string()
                        ],
                    )?;
                    if changed != 1 {
                        bail!("active member membership is required");
                    }
                }
                GroupTokenKind::Admin => {
                    transaction.execute(
                        "UPDATE groups SET admin_token_hash = ?1 WHERE group_id = ?2",
                        params![hash, group_id.to_string()],
                    )?;
                    transaction.execute(
                        "UPDATE group_members SET credential_hash = ?1, updated_at_ms = ?2
                         WHERE group_id = ?3 AND member_id = ?4 AND role = 'admin'",
                        params![
                            credential_hash(&token)?,
                            now_ms_i64(),
                            group_id.to_string(),
                            actor_member_id.to_string()
                        ],
                    )?;
                }
                GroupTokenKind::Invite => {
                    let changed = transaction.execute(
                        "UPDATE groups SET invite_token_hash = ?1
                         WHERE group_id = ?2 AND access_mode = 'invite'",
                        params![hash, group_id.to_string()],
                    )?;
                    if changed != 1 {
                        bail!("only invite groups have an invite token");
                    }
                }
            }
            transaction.commit()?;
            Ok(token)
        })
        .await
    }

    pub async fn room_members(
        &self,
        group_id: Uuid,
        room_id: String,
        offset: u32,
    ) -> Result<(Vec<RoomMemberSummary>, bool)> {
        self.run(move |connection, _| {
            let visibility: Option<String> = connection
                .query_row(
                    "SELECT visibility FROM rooms WHERE group_id = ?1 AND room_id = ?2",
                    params![group_id.to_string(), room_id],
                    |row| row.get(0),
                )
                .optional()?;
            if visibility.as_deref() != Some("private") {
                bail!("room is not private");
            }
            let mut statement = connection.prepare(
                "SELECT gm.member_id, gm.last_nickname, gm.role, rm.role
                 FROM group_members gm
                 LEFT JOIN room_members rm
                   ON rm.group_id = gm.group_id AND rm.member_id = gm.member_id
                  AND rm.room_id = ?2
                 WHERE gm.group_id = ?1 AND gm.status = 'active'
                 ORDER BY CASE WHEN rm.role = 'owner' THEN 0
                               WHEN rm.role = 'member' THEN 1 ELSE 2 END,
                          gm.last_nickname COLLATE NOCASE, gm.member_id
                 LIMIT ?3 OFFSET ?4",
            )?;
            let rows = statement
                .query_map(
                    params![
                        group_id.to_string(),
                        room_id,
                        i64::try_from(MEMBER_PAGE_SIZE + 1).unwrap_or(41),
                        i64::from(offset)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = rows.len() > MEMBER_PAGE_SIZE;
            let members = rows
                .into_iter()
                .take(MEMBER_PAGE_SIZE)
                .map(|(member_id, nickname, group_role, room_role)| {
                    let group_role = parse_group_role(&group_role)?;
                    Ok(RoomMemberSummary {
                        member_id: Uuid::parse_str(&member_id)?,
                        nickname,
                        group_role,
                        included: room_role.is_some() || group_role == GroupRole::Admin,
                        is_owner: room_role.as_deref() == Some("owner"),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((members, has_more))
        })
        .await
    }

    pub async fn member_can_manage_room(
        &self,
        group_id: Uuid,
        room_id: String,
        actor_member_id: Uuid,
        actor_role: GroupRole,
    ) -> Result<bool> {
        if actor_role == GroupRole::Admin {
            return Ok(true);
        }
        self.run(move |connection, _| {
            let is_owner: bool = connection.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM room_members
                    WHERE group_id = ?1 AND room_id = ?2 AND member_id = ?3
                      AND role = 'owner'
                 )",
                params![group_id.to_string(), room_id, actor_member_id.to_string()],
                |row| row.get(0),
            )?;
            Ok(is_owner)
        })
        .await
    }

    pub async fn set_room_member(
        &self,
        group_id: Uuid,
        room_id: String,
        actor_member_id: Uuid,
        actor_role: GroupRole,
        target_member_id: Uuid,
        included: bool,
    ) -> Result<bool> {
        self.run(move |connection, _| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let visibility: Option<String> = transaction
                .query_row(
                    "SELECT visibility FROM rooms WHERE group_id = ?1 AND room_id = ?2",
                    params![group_id.to_string(), room_id],
                    |row| row.get(0),
                )
                .optional()?;
            if visibility.as_deref() != Some("private") {
                bail!("room is not private");
            }
            let actor_is_owner: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM room_members
                    WHERE group_id = ?1 AND room_id = ?2 AND member_id = ?3
                      AND role = 'owner'
                 )",
                params![group_id.to_string(), room_id, actor_member_id.to_string()],
                |row| row.get(0),
            )?;
            if actor_role != GroupRole::Admin && !actor_is_owner {
                bail!("room owner or group administrator is required");
            }
            let target_active: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM group_members
                    WHERE group_id = ?1 AND member_id = ?2 AND status = 'active'
                      AND role != 'admin'
                 )",
                params![group_id.to_string(), target_member_id.to_string()],
                |row| row.get(0),
            )?;
            if !target_active {
                bail!("target member is not active");
            }
            let changed = if included {
                transaction.execute(
                    "INSERT INTO room_members(group_id, room_id, member_id, role, added_at_ms)
                     VALUES (?1, ?2, ?3, 'member', ?4)
                     ON CONFLICT(group_id, room_id, member_id) DO NOTHING",
                    params![
                        group_id.to_string(),
                        room_id,
                        target_member_id.to_string(),
                        now_ms_i64()
                    ],
                )?
            } else {
                transaction.execute(
                    "DELETE FROM room_members
                     WHERE group_id = ?1 AND room_id = ?2 AND member_id = ?3
                       AND role = 'member'",
                    params![group_id.to_string(), room_id, target_member_id.to_string()],
                )?
            };
            transaction.commit()?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn append_message(
        &self,
        group_id: Uuid,
        room_id: String,
        message_id: Uuid,
        sender: Peer,
        sent_at_ms: u64,
        text: String,
    ) -> Result<ChatRecord> {
        self.run(move |connection, key| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let sequence: i64 = transaction.query_row(
                "UPDATE rooms SET next_sequence = next_sequence + 1
                 WHERE room_id = ?1 AND group_id = ?2
                 RETURNING next_sequence - 1",
                params![room_id, group_id.to_string()],
                |row| row.get(0),
            )?;
            let sequence = u64::try_from(sequence).context("room sequence overflowed")?;
            let encrypted = encrypt_body(
                key,
                group_id,
                &room_id,
                message_id,
                sequence,
                text.as_bytes(),
            )?;
            transaction.execute(
                "INSERT INTO group_messages(
                    message_id, group_id, room_id, sequence, sender_session_id,
                    sender_member_id, sender_nickname, sent_at_ms, encrypted_body
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    message_id.to_string(),
                    group_id.to_string(),
                    room_id,
                    i64::try_from(sequence).context("room sequence exceeds SQLite range")?,
                    sender.session_id.to_string(),
                    sender.member_id.to_string(),
                    sender.nickname,
                    i64::try_from(sent_at_ms).unwrap_or(i64::MAX),
                    encrypted,
                ],
            )?;
            transaction.commit()?;
            Ok(ChatRecord {
                sequence,
                message_id,
                sender,
                room_id,
                sent_at_ms,
                text,
            })
        })
        .await
    }

    pub async fn history(
        &self,
        group_id: Uuid,
        room_id: String,
        limit: usize,
    ) -> Result<Vec<ChatRecord>> {
        let limit = limit.clamp(1, 1_000);
        self.run(move |connection, key| {
            let mut statement = connection.prepare(
                "SELECT message_id, sequence, sender_session_id, sender_member_id,
                        sender_nickname, sent_at_ms, encrypted_body
                 FROM group_messages
                 WHERE group_id = ?1 AND room_id = ?2
                 ORDER BY sequence DESC LIMIT ?3",
            )?;
            let rows = statement
                .query_map(
                    params![
                        group_id.to_string(),
                        room_id,
                        i64::try_from(limit).unwrap_or(1_000)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut history = rows
                .into_iter()
                .map(
                    |(
                        message_id,
                        sequence,
                        sender_id,
                        sender_member_id,
                        nickname,
                        sent_at_ms,
                        encrypted,
                    )| {
                        let message_id = Uuid::parse_str(&message_id)?;
                        let sequence = u64::try_from(sequence).context("negative room sequence")?;
                        let plaintext = decrypt_body(
                            key, group_id, &room_id, message_id, sequence, &encrypted,
                        )?;
                        let text = String::from_utf8(plaintext)
                            .context("stored message contains invalid UTF-8")?;
                        Ok(ChatRecord {
                            sequence,
                            message_id,
                            sender: Peer {
                                session_id: Uuid::parse_str(&sender_id)?,
                                member_id: Uuid::parse_str(&sender_member_id)?,
                                nickname,
                                direct: None,
                            },
                            room_id: room_id.clone(),
                            sent_at_ms: u64::try_from(sent_at_ms).unwrap_or_default(),
                            text,
                        })
                    },
                )
                .collect::<Result<Vec<_>>>()?;
            history.reverse();
            Ok(history)
        })
        .await
    }

    pub async fn history_before(
        &self,
        group_id: Uuid,
        room_id: String,
        before_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ChatRecord>> {
        let limit = limit.clamp(1, 1_000);
        self.run(move |connection, key| {
            let mut statement = connection.prepare(
                "SELECT message_id, sequence, sender_session_id, sender_member_id,
                        sender_nickname, sent_at_ms, encrypted_body
                 FROM group_messages
                 WHERE group_id = ?1 AND room_id = ?2 AND sequence < ?3
                 ORDER BY sequence DESC LIMIT ?4",
            )?;
            let rows = statement
                .query_map(
                    params![
                        group_id.to_string(),
                        room_id,
                        i64::try_from(before_sequence).unwrap_or(i64::MAX),
                        i64::try_from(limit).unwrap_or(1_000)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut history = rows
                .into_iter()
                .map(
                    |(
                        message_id,
                        sequence,
                        sender_id,
                        sender_member_id,
                        nickname,
                        sent_at_ms,
                        encrypted,
                    )| {
                        let message_id = Uuid::parse_str(&message_id)?;
                        let sequence = u64::try_from(sequence).context("negative room sequence")?;
                        let plaintext = decrypt_body(
                            key, group_id, &room_id, message_id, sequence, &encrypted,
                        )?;
                        Ok(ChatRecord {
                            sequence,
                            message_id,
                            sender: Peer {
                                session_id: Uuid::parse_str(&sender_id)?,
                                member_id: Uuid::parse_str(&sender_member_id)?,
                                nickname,
                                direct: None,
                            },
                            room_id: room_id.clone(),
                            sent_at_ms: u64::try_from(sent_at_ms).unwrap_or_default(),
                            text: String::from_utf8(plaintext)
                                .context("stored message contains invalid UTF-8")?,
                        })
                    },
                )
                .collect::<Result<Vec<_>>>()?;
            history.reverse();
            Ok(history)
        })
        .await
    }

    async fn run<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &[u8; 32]) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        task::spawn_blocking(move || {
            let mut connection = inner
                .connection
                .lock()
                .map_err(|_| anyhow::anyhow!("SQLite connection lock was poisoned"))?;
            operation(&mut connection, &inner.key)
        })
        .await
        .context("database task panicked")?
    }
}

pub async fn backup_gateway_data(
    source_dir: impl AsRef<Path>,
    destination_dir: impl AsRef<Path>,
) -> Result<()> {
    let source_dir = source_dir.as_ref().to_path_buf();
    let destination_dir = destination_dir.as_ref().to_path_buf();
    if !source_dir.join(DATABASE_FILE).is_file() {
        bail!(
            "{} does not contain a gateway database",
            source_dir.display()
        );
    }
    if destination_dir.exists() {
        bail!(
            "backup destination {} already exists",
            destination_dir.display()
        );
    }
    let store = GatewayStore::open(&source_dir).await?;
    create_private_directory(&destination_dir)?;
    let destination_database = destination_dir.join(DATABASE_FILE);
    let inner = Arc::clone(&store.inner);
    task::spawn_blocking(move || {
        let connection = inner
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("SQLite connection lock was poisoned"))?;
        connection
            .backup(rusqlite::MAIN_DB, &destination_database, None)
            .context("SQLite online backup failed")?;
        set_private_path_permissions(&destination_database)?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("database backup task panicked")??;
    copy_private_file(
        &source_dir.join(DATABASE_KEY_FILE),
        &destination_dir.join(DATABASE_KEY_FILE),
    )?;
    copy_private_file(
        &source_dir.join(NOISE_KEY_FILE),
        &destination_dir.join(NOISE_KEY_FILE),
    )?;
    Ok(())
}

fn initialize_connection(connection: &Connection) -> Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;",
    )?;
    Ok(())
}

fn initialize_schema(connection: &Connection) -> Result<()> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > 3 {
        bail!("gateway database schema {version} is newer than this binary supports");
    }
    if version == 0 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE gateway_meta (
                 key TEXT PRIMARY KEY NOT NULL,
                 value TEXT NOT NULL
             ) STRICT;
             CREATE TABLE groups (
                 group_id TEXT PRIMARY KEY NOT NULL,
                 name TEXT NOT NULL,
                 access_mode TEXT NOT NULL CHECK(access_mode IN ('public', 'invite', 'approval')),
                 admin_token_hash BLOB,
                 invite_token_hash BLOB,
                 created_at_ms INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE rooms (
                 room_id TEXT NOT NULL,
                 group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                 name TEXT NOT NULL,
                 visibility TEXT NOT NULL CHECK(visibility IN ('public', 'private')),
                 next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1),
                 created_at_ms INTEGER NOT NULL,
                 PRIMARY KEY(group_id, room_id),
                 UNIQUE(group_id, name)
             ) STRICT;
             CREATE TABLE group_messages (
                 message_id TEXT PRIMARY KEY NOT NULL,
                 group_id TEXT NOT NULL,
                 room_id TEXT NOT NULL,
                 sequence INTEGER NOT NULL CHECK(sequence >= 1),
                 sender_session_id TEXT NOT NULL,
                 sender_member_id TEXT NOT NULL,
                 sender_nickname TEXT NOT NULL,
                 sent_at_ms INTEGER NOT NULL,
                 encrypted_body BLOB NOT NULL,
                 FOREIGN KEY(group_id, room_id) REFERENCES rooms(group_id, room_id) ON DELETE CASCADE,
                 UNIQUE(group_id, room_id, sequence)
             ) STRICT;
             CREATE INDEX group_messages_room_sequence
                 ON group_messages(group_id, room_id, sequence);
             CREATE TABLE join_requests (
                 request_id TEXT PRIMARY KEY NOT NULL,
                 group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                 nickname TEXT NOT NULL,
                 request_token_hash BLOB NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
                 requested_at_ms INTEGER NOT NULL,
                 UNIQUE(group_id, request_token_hash)
             ) STRICT;
             CREATE INDEX join_requests_group_status
                 ON join_requests(group_id, status, requested_at_ms);
             CREATE TABLE group_members (
                 member_id TEXT PRIMARY KEY NOT NULL,
                 group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                 credential_hash BLOB NOT NULL,
                 role TEXT NOT NULL CHECK(role IN ('member', 'admin')),
                 status TEXT NOT NULL CHECK(status IN ('active', 'banned')),
                 last_nickname TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 UNIQUE(group_id, credential_hash)
             ) STRICT;
             CREATE INDEX group_members_group_status
                 ON group_members(group_id, status, last_nickname);
             CREATE TABLE room_members (
                 group_id TEXT NOT NULL,
                 room_id TEXT NOT NULL,
                 member_id TEXT NOT NULL REFERENCES group_members(member_id) ON DELETE CASCADE,
                 role TEXT NOT NULL CHECK(role IN ('owner', 'member')),
                 added_at_ms INTEGER NOT NULL,
                 PRIMARY KEY(group_id, room_id, member_id),
                 FOREIGN KEY(group_id, room_id)
                    REFERENCES rooms(group_id, room_id) ON DELETE CASCADE
             ) STRICT;
             CREATE INDEX room_members_member
                 ON room_members(group_id, member_id, room_id);
             CREATE UNIQUE INDEX groups_name_nocase ON groups(name COLLATE NOCASE);
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    }
    if version == 1 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE groups ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'public'
                 CHECK(access_mode IN ('public', 'invite', 'approval'));
             ALTER TABLE groups ADD COLUMN admin_token_hash BLOB;
             ALTER TABLE groups ADD COLUMN invite_token_hash BLOB;
             CREATE TABLE join_requests (
                 request_id TEXT PRIMARY KEY NOT NULL,
                 group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                 nickname TEXT NOT NULL,
                 request_token_hash BLOB NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
                 requested_at_ms INTEGER NOT NULL,
                 UNIQUE(group_id, request_token_hash)
             ) STRICT;
             CREATE INDEX join_requests_group_status
                 ON join_requests(group_id, status, requested_at_ms);
             ALTER TABLE rooms ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'
                 CHECK(visibility IN ('public', 'private'));
             ALTER TABLE group_messages ADD COLUMN sender_member_id TEXT NOT NULL
                 DEFAULT '00000000-0000-0000-0000-000000000000';
             CREATE TABLE group_members (
                 member_id TEXT PRIMARY KEY NOT NULL,
                 group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                 credential_hash BLOB NOT NULL,
                 role TEXT NOT NULL CHECK(role IN ('member', 'admin')),
                 status TEXT NOT NULL CHECK(status IN ('active', 'banned')),
                 last_nickname TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 UNIQUE(group_id, credential_hash)
             ) STRICT;
             CREATE INDEX group_members_group_status
                 ON group_members(group_id, status, last_nickname);
             CREATE TABLE room_members (
                 group_id TEXT NOT NULL,
                 room_id TEXT NOT NULL,
                 member_id TEXT NOT NULL REFERENCES group_members(member_id) ON DELETE CASCADE,
                 role TEXT NOT NULL CHECK(role IN ('owner', 'member')),
                 added_at_ms INTEGER NOT NULL,
                 PRIMARY KEY(group_id, room_id, member_id),
                 FOREIGN KEY(group_id, room_id)
                    REFERENCES rooms(group_id, room_id) ON DELETE CASCADE
             ) STRICT;
             CREATE INDEX room_members_member
                 ON room_members(group_id, member_id, room_id);
             CREATE UNIQUE INDEX groups_name_nocase ON groups(name COLLATE NOCASE);
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    }
    if version == 2 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE rooms ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'
                 CHECK(visibility IN ('public', 'private'));
             ALTER TABLE group_messages ADD COLUMN sender_member_id TEXT NOT NULL
                 DEFAULT '00000000-0000-0000-0000-000000000000';
             CREATE TABLE group_members (
                 member_id TEXT PRIMARY KEY NOT NULL,
                 group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                 credential_hash BLOB NOT NULL,
                 role TEXT NOT NULL CHECK(role IN ('member', 'admin')),
                 status TEXT NOT NULL CHECK(status IN ('active', 'banned')),
                 last_nickname TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 UNIQUE(group_id, credential_hash)
             ) STRICT;
             CREATE INDEX group_members_group_status
                 ON group_members(group_id, status, last_nickname);
             CREATE TABLE room_members (
                 group_id TEXT NOT NULL,
                 room_id TEXT NOT NULL,
                 member_id TEXT NOT NULL REFERENCES group_members(member_id) ON DELETE CASCADE,
                 role TEXT NOT NULL CHECK(role IN ('owner', 'member')),
                 added_at_ms INTEGER NOT NULL,
                 PRIMARY KEY(group_id, room_id, member_id),
                 FOREIGN KEY(group_id, room_id)
                    REFERENCES rooms(group_id, room_id) ON DELETE CASCADE
             ) STRICT;
             CREATE INDEX room_members_member
                 ON room_members(group_id, member_id, room_id);
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    }
    Ok(())
}

fn parse_access_mode(value: &str) -> Result<GroupAccessMode> {
    match value {
        "public" => Ok(GroupAccessMode::Public),
        "invite" => Ok(GroupAccessMode::Invite),
        "approval" => Ok(GroupAccessMode::Approval),
        _ => bail!("database contains an invalid group access mode"),
    }
}

fn parse_room_visibility(value: &str) -> Result<RoomVisibility> {
    match value {
        "public" => Ok(RoomVisibility::Public),
        "private" => Ok(RoomVisibility::Private),
        _ => bail!("database contains an invalid room visibility"),
    }
}

fn parse_group_role(value: &str) -> Result<GroupRole> {
    match value {
        "member" => Ok(GroupRole::Member),
        "admin" => Ok(GroupRole::Admin),
        _ => bail!("database contains an invalid group role"),
    }
}

fn parse_member_status(value: &str) -> Result<GroupMemberStatus> {
    match value {
        "active" => Ok(GroupMemberStatus::Active),
        "banned" => Ok(GroupMemberStatus::Banned),
        _ => bail!("database contains an invalid member status"),
    }
}

fn insert_group_member(
    connection: &Connection,
    group_id: Uuid,
    credential: &str,
    role: GroupRole,
    nickname: &str,
) -> Result<Uuid> {
    let member_id = Uuid::new_v4();
    connection.execute(
        "INSERT INTO group_members(
            member_id, group_id, credential_hash, role, status,
            last_nickname, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?6)",
        params![
            member_id.to_string(),
            group_id.to_string(),
            credential_hash(credential)?,
            match role {
                GroupRole::Member => "member",
                GroupRole::Admin => "admin",
            },
            nickname,
            now_ms_i64()
        ],
    )?;
    Ok(member_id)
}

fn issue_member(
    connection: &Connection,
    group_id: Uuid,
    nickname: &str,
) -> Result<JoinAuthorization> {
    let members: i64 = connection.query_row(
        "SELECT COUNT(*) FROM group_members WHERE group_id = ?1",
        [group_id.to_string()],
        |row| row.get(0),
    )?;
    if members >= MAX_GROUP_MEMBERS {
        return Ok(JoinAuthorization::MemberLimit);
    }
    let token = generate_credential("member")?;
    let member_id = insert_group_member(connection, group_id, &token, GroupRole::Member, nickname)?;
    Ok(JoinAuthorization::Allowed {
        role: GroupRole::Member,
        member_id,
        issued_member_token: Some(token),
    })
}

fn generate_credential(kind: &str) -> Result<String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).context("failed to generate a group credential")?;
    let encoded = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("lc_{kind}_{encoded}"))
}

fn credential_hash(credential: &str) -> Result<Vec<u8>> {
    if !is_valid_group_credential(credential) {
        bail!("group credential has an invalid format");
    }
    Ok(blake3::hash(credential.as_bytes()).as_bytes().to_vec())
}

fn hash_matches(supplied: &[u8], stored: &[u8]) -> bool {
    supplied.len() == stored.len() && bool::from(supplied.ct_eq(stored))
}

fn encrypt_body(
    key: &[u8; 32],
    group_id: Uuid,
    room_id: &str,
    message_id: Uuid,
    sequence: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).context("failed to generate a message encryption nonce")?;
    let aad = message_aad(group_id, room_id, message_id, sequence);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("failed to encrypt a stored group message"))?;
    let mut encoded = Vec::with_capacity(1 + NONCE_LENGTH + ciphertext.len());
    encoded.push(ENCRYPTED_BODY_VERSION);
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

fn decrypt_body(
    key: &[u8; 32],
    group_id: Uuid,
    room_id: &str,
    message_id: Uuid,
    sequence: u64,
    encoded: &[u8],
) -> Result<Vec<u8>> {
    if encoded.len() <= 1 + NONCE_LENGTH || encoded[0] != ENCRYPTED_BODY_VERSION {
        bail!("stored message has an unsupported encrypted body format");
    }
    let (nonce, ciphertext) = encoded[1..].split_at(NONCE_LENGTH);
    let aad = message_aad(group_id, room_id, message_id, sequence);
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("stored message authentication failed"))
}

fn message_aad(group_id: Uuid, room_id: &str, message_id: Uuid, sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + room_id.len() + 16 + 8);
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(room_id.as_bytes());
    aad.extend_from_slice(message_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

fn load_or_create_key(path: &Path) -> Result<[u8; 32]> {
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            let mut key = [0u8; 32];
            file.read_exact(&mut key)
                .context("gateway database key is truncated")?;
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 {
                bail!("gateway database key has an invalid length");
            }
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).context("failed to generate the gateway database key")?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            set_private_file_mode(&mut options);
            let mut file = options
                .open(path)
                .context("failed to create the gateway database key")?;
            file.write_all(&key)?;
            file.sync_all()?;
            Ok(key)
        }
        Err(error) => Err(error).context("failed to open the gateway database key"),
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create gateway data directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
}

fn copy_private_file(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to copy gateway secret {} into the backup",
            source.display()
        )
    })?;
    set_private_path_permissions(destination)
}

fn set_private_path_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn now_ms_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn messages_are_encrypted_and_survive_reopening() {
        let directory = tempfile::tempdir().unwrap();
        let store = GatewayStore::open(directory.path()).await.unwrap();
        let group = store
            .create_group("Persistent group".to_owned())
            .await
            .unwrap();
        let message_id = Uuid::new_v4();
        let sender = Peer {
            session_id: Uuid::new_v4(),
            member_id: Uuid::new_v4(),
            nickname: "Alice".to_owned(),
            direct: None,
        };
        store
            .append_message(
                group.group_id,
                DEFAULT_ROOM_ID.to_owned(),
                message_id,
                sender.clone(),
                42,
                "durable secret".to_owned(),
            )
            .await
            .unwrap();
        drop(store);

        let database = fs::read(directory.path().join(DATABASE_FILE)).unwrap();
        assert!(
            !database
                .windows(b"durable secret".len())
                .any(|window| window == b"durable secret")
        );

        let reopened = GatewayStore::open(directory.path()).await.unwrap();
        let history = reopened
            .history(group.group_id, DEFAULT_ROOM_ID.to_owned(), 200)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].text, "durable secret");
        assert_eq!(history[0].sender, sender);
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let store = GatewayStore::open_in_memory().unwrap();
        let group = store.create_group("Tamper test".to_owned()).await.unwrap();
        let message_id = Uuid::new_v4();
        store
            .append_message(
                group.group_id,
                DEFAULT_ROOM_ID.to_owned(),
                message_id,
                Peer {
                    session_id: Uuid::new_v4(),
                    member_id: Uuid::new_v4(),
                    nickname: "Alice".to_owned(),
                    direct: None,
                },
                1,
                "original".to_owned(),
            )
            .await
            .unwrap();
        {
            let connection = store.inner.connection.lock().unwrap();
            let mut encrypted: Vec<u8> = connection
                .query_row(
                    "SELECT encrypted_body FROM group_messages WHERE message_id = ?1",
                    [message_id.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            let last = encrypted.last_mut().unwrap();
            *last ^= 1;
            connection
                .execute(
                    "UPDATE group_messages SET encrypted_body = ?1 WHERE message_id = ?2",
                    params![encrypted, message_id.to_string()],
                )
                .unwrap();
        }
        assert!(
            store
                .history(group.group_id, DEFAULT_ROOM_ID.to_owned(), 200)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn online_backup_contains_database_and_required_keys() {
        let source = tempfile::tempdir().unwrap();
        crate::crypto::load_or_create_keypair(&source.path().join(NOISE_KEY_FILE)).unwrap();
        let store = GatewayStore::open(source.path()).await.unwrap();
        let gateway_id = store.gateway_id().await.unwrap();
        let group = store.create_group("Backup group".to_owned()).await.unwrap();
        store
            .append_message(
                group.group_id,
                DEFAULT_ROOM_ID.to_owned(),
                Uuid::new_v4(),
                Peer {
                    session_id: Uuid::new_v4(),
                    member_id: Uuid::new_v4(),
                    nickname: "Alice".to_owned(),
                    direct: None,
                },
                9,
                "inside backup".to_owned(),
            )
            .await
            .unwrap();
        let backup_parent = tempfile::tempdir().unwrap();
        let backup = backup_parent.path().join("snapshot");
        backup_gateway_data(source.path(), &backup).await.unwrap();

        let restored = GatewayStore::open(&backup).await.unwrap();
        assert_eq!(restored.gateway_id().await.unwrap(), gateway_id);
        let history = restored
            .history(group.group_id, DEFAULT_ROOM_ID.to_owned(), 20)
            .await
            .unwrap();
        assert_eq!(history[0].text, "inside backup");
        assert!(backup.join(NOISE_KEY_FILE).is_file());
    }

    #[tokio::test]
    async fn version_one_databases_migrate_existing_groups_to_public_access() {
        let directory = tempfile::tempdir().unwrap();
        load_or_create_key(&directory.path().join(DATABASE_KEY_FILE)).unwrap();
        let group_id = Uuid::new_v4();
        let connection = Connection::open(directory.path().join(DATABASE_FILE)).unwrap();
        initialize_connection(&connection).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TABLE gateway_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE groups (
                    group_id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE rooms (
                    room_id TEXT NOT NULL,
                    group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1),
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(group_id, room_id),
                    UNIQUE(group_id, name)
                 ) STRICT;
                 CREATE TABLE group_messages (
                    message_id TEXT PRIMARY KEY NOT NULL,
                    group_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK(sequence >= 1),
                    sender_session_id TEXT NOT NULL,
                    sender_nickname TEXT NOT NULL,
                    sent_at_ms INTEGER NOT NULL,
                    encrypted_body BLOB NOT NULL,
                    FOREIGN KEY(group_id, room_id) REFERENCES rooms(group_id, room_id) ON DELETE CASCADE,
                    UNIQUE(group_id, room_id, sequence)
                 ) STRICT;
                 INSERT INTO groups(group_id, name, created_at_ms)
                    VALUES ('{group_id}', 'Legacy', 1);
                 INSERT INTO rooms(room_id, group_id, name, next_sequence, created_at_ms)
                    VALUES ('general', '{group_id}', 'general', 1, 1);
                 PRAGMA user_version = 1;"
            ))
            .unwrap();
        drop(connection);

        let store = GatewayStore::open(directory.path()).await.unwrap();
        let groups = store.list_groups().await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].access_mode, GroupAccessMode::Public);
        assert!(matches!(
            store
                .authorize_join(group_id, None, "Legacy member".to_owned())
                .await
                .unwrap(),
            JoinAuthorization::Allowed {
                role: GroupRole::Member,
                ..
            }
        ));
        let version: u32 = store
            .inner
            .connection
            .lock()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[tokio::test]
    async fn version_two_databases_gain_members_and_private_room_schema() {
        let directory = tempfile::tempdir().unwrap();
        load_or_create_key(&directory.path().join(DATABASE_KEY_FILE)).unwrap();
        let group_id = Uuid::new_v4();
        let admin_token = "lc_admin_migration_test";
        let connection = Connection::open(directory.path().join(DATABASE_FILE)).unwrap();
        initialize_connection(&connection).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE gateway_meta (
                    key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE groups (
                    group_id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    access_mode TEXT NOT NULL CHECK(access_mode IN ('public', 'invite', 'approval')),
                    admin_token_hash BLOB,
                    invite_token_hash BLOB,
                    created_at_ms INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE rooms (
                    room_id TEXT NOT NULL,
                    group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1),
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(group_id, room_id),
                    UNIQUE(group_id, name)
                 ) STRICT;
                 CREATE TABLE group_messages (
                    message_id TEXT PRIMARY KEY NOT NULL,
                    group_id TEXT NOT NULL,
                    room_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK(sequence >= 1),
                    sender_session_id TEXT NOT NULL,
                    sender_nickname TEXT NOT NULL,
                    sent_at_ms INTEGER NOT NULL,
                    encrypted_body BLOB NOT NULL,
                    FOREIGN KEY(group_id, room_id) REFERENCES rooms(group_id, room_id) ON DELETE CASCADE,
                    UNIQUE(group_id, room_id, sequence)
                 ) STRICT;
                 CREATE TABLE join_requests (
                    request_id TEXT PRIMARY KEY NOT NULL,
                    group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
                    nickname TEXT NOT NULL,
                    request_token_hash BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
                    requested_at_ms INTEGER NOT NULL,
                    UNIQUE(group_id, request_token_hash)
                 ) STRICT;
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO groups(
                    group_id, name, access_mode, admin_token_hash, invite_token_hash, created_at_ms
                 ) VALUES (?1, 'Version two', 'public', ?2, NULL, 1)",
                params![group_id.to_string(), credential_hash(admin_token).unwrap()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO rooms(room_id, group_id, name, next_sequence, created_at_ms)
                 VALUES ('general', ?1, 'general', 1, 1)",
                [group_id.to_string()],
            )
            .unwrap();
        drop(connection);

        let store = GatewayStore::open(directory.path()).await.unwrap();
        let authorization = store
            .authorize_join(
                group_id,
                Some(admin_token.to_owned()),
                "Migrated admin".to_owned(),
            )
            .await
            .unwrap();
        let JoinAuthorization::Allowed {
            role: GroupRole::Admin,
            member_id,
            issued_member_token: None,
        } = authorization
        else {
            panic!("migrated administrator token was not recognized");
        };
        let rooms = store.rooms_for_member(group_id, member_id).await.unwrap();
        assert_eq!(rooms[0].visibility, RoomVisibility::Public);
        assert_eq!(store.group_members(group_id, 0).await.unwrap().0.len(), 1);
    }
}
