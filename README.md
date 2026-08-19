# lan-chat

`lan-chat` is a single Rust binary for anonymous chat on a local network. One
always-on gateway persists and forwards group messages. Private messages go
directly between two online clients and are end-to-end encrypted.

## Architecture

```text
                        group chat
client A  ── Noise ──> gateway ── encrypted body ──> SQLite
   │                       │
   └──── direct Noise ─────┴────────────────────────> client B
             private chat (the gateway is not a relay)
```

- A gateway hosts multiple groups and rooms in one SQLite database.
- A group is the persistent membership, security, and history boundary. Rooms
  are topics inside that group and can be public or have a private member list.
- Groups can be public, invite-token protected, or administrator-approved.
- Each admitted client receives a persistent anonymous member token. It powers
  reconnects, member bans, and private-room access without requiring accounts.
- Group history survives every client disconnecting or uninstalling.
- Gateway identity, fingerprint and database key survive gateway restarts.
- A fresh client loads recent history when it joins and loads older pages with
  `PageUp`.
- Private chats are memory-only. Both peers must be online and reachable.
- The private-chat initiator may send one opening message, then must wait for
  one reply before sending more.

The gateway remains a single availability point. Back it up and run it on a
NAS, home server, router, or another machine that is normally online.

## Build

```sh
cargo build --release
```

The resulting `target/release/lan-chat` is the only executable needed on both
gateway and client machines. The target machine does not need a Rust runtime or
a separately installed SQLite library.

Protocol v5 is intentionally incompatible with earlier clients because member
identities, private-room authorization, and token rotation are protocol-level
features. Existing schema-v1 and schema-v2 gateway databases are migrated to
schema v3 when first opened; take a backup before upgrading.

## Run a gateway

```sh
lan-chat gateway \
  --name "Office gateway" \
  --bind 0.0.0.0:7373 \
  --data ./lan-chat-data
```

The data directory contains:

```text
gateway.sqlite3     group/room metadata and encrypted message bodies
gateway-db.key      message-body encryption key
gateway-noise.key   stable gateway transport identity
```

All three files are required for a complete restore. Losing
`gateway-db.key` makes stored message bodies unrecoverable. Replacing
`gateway-noise.key` changes the gateway fingerprint seen by clients.

## Use the TUI

```sh
lan-chat --nickname Alice
```

Omit `--nickname` to generate a fresh anonymous Chinese nickname such as
`迷路的海獭` or `正在缓冲的机器人`. It remains unchanged for that process and
can still be edited with `N` in the lobby.

The lobby discovers gateways with IPv4 multicast, connects to each through
Noise, and obtains its current group list.

When creating a group, choose one access mode:

- **Public**: anyone who can reach the gateway may join.
- **Invite**: the creator receives a shareable invite token.
- **Approval**: a first join creates a pending request; an administrator must
  approve it before that same client credential can enter.

The creator receives a separate administrator token in every mode. A shared
invite or approved-request token is replaced locally by a personal member token
after the first successful join. Tokens are saved before the chat opens; the
gateway stores only their BLAKE3 hashes.

Rooms are either public to all active group members or private. A private room
is initially visible only to its creator and group administrators. Its creator
or a group administrator can add and remove persistent members. Group
administrators always retain access so a room cannot become unmanageable.

Lobby controls:

- `↑`/`↓`: select a group
- `Enter`: join the selected group
- `C`: create a group on the selected or first available gateway
- `J`: connect to a gateway by `IP:port` when multicast is unavailable
- `N`: change the anonymous nickname
- `R`: refresh gateway and group discovery
- `X`: forget the selected group's local credential
- `Q`/`Esc`: quit

Chat controls:

- type and press `Enter` to send
- your messages are right-aligned; messages from other members stay on the left
- `Tab`/`Shift+Tab`: focus input, rooms/conversations, or members
- select a room and press `Enter` to join/open it
- select an online member and press `Enter` to start a direct private chat
- `F2`: create and join a room
- `F4`: administrators review, approve, or reject pending group joins
- `F5`: manage the active private room's member list
- `F6`: administrators ban or unban persistent group members
- `F7`: rotate your member token; administrators rotate the administrator or
  shared invite token instead
- `Delete`: leave the selected non-general room
- `PageUp`: scroll and fetch an older bounded history page from the gateway
- `PageDown`/`End`: move toward the latest message
- `Esc`: return to the lobby; `Ctrl+Q`: quit the application

If a firewall blocks inbound LAN connections, peer-to-peer private chat can
fail. There is deliberately no gateway relay fallback in this release.

## Direct and automated commands

List gateways:

```sh
lan-chat discover
```

Create an invite-only group without entering the TUI:

```sh
lan-chat create 192.168.1.20:7373 "Weekend" --access invite
```

Join a gateway containing exactly one group:

```sh
lan-chat join 192.168.1.20:7373 --nickname Bob
```

Select a group explicitly when the gateway contains more than one:

```sh
lan-chat join 192.168.1.20:7373 \
  --group 6c280af4-6dd3-49bb-89e9-cd562f4ab1a8 \
  --fingerprint 1234:5678:90ab:cdef:1234:5678 \
  --credential lc_invite_...
```

`lan-chat host` remains a convenience command. It starts a persistent gateway,
creates a new group, and enters it immediately. Use `--access public`,
`--access invite`, or `--access approval`.

## Client credentials

The default client credential file is:

```text
$XDG_DATA_HOME/lan-chat/credentials.json
# or ~/.local/share/lan-chat/credentials.json
```

Set `LAN_CHAT_CLIENT_DATA_DIR` to choose another directory. On Unix the
directory is forced to mode `0700` and the file to `0600`. The tokens are
plaintext inside that OS-protected file, so include it in a secure personal
backup if administrator access must survive deletion of all client data.
Uninstalling only the binary normally leaves this file intact.

```sh
lan-chat credentials path
lan-chat credentials list
lan-chat credentials show GATEWAY_UUID GROUP_UUID
lan-chat credentials set GATEWAY_UUID GROUP_UUID lc_admin_...
lan-chat credentials remove GATEWAY_UUID GROUP_UUID
```

`show` and `set` expose a bearer secret in terminal or process history. Prefer
the TUI's automatic storage for normal use. Anyone holding an administrator
token can administer that group; anyone holding an active invite token can
create a new membership in its invite-mode group. `F7` saves a rotated token
before showing it and immediately invalidates the old value.

## Backup and restore

Create a consistent online SQLite snapshot plus both required key files:

```sh
lan-chat backup \
  --data ./lan-chat-data \
  --output ./backups/lan-chat-2026-08-19
```

The output path must not already exist. A backup contains decryption and
gateway identity keys, so protect it like the live data directory.

Gateway backup does not include each user's local `credentials.json`. Back up
that file separately when group administration access matters.

To restore, stop the gateway and use the backup directory as `--data`. Do not
merge individual SQLite, WAL, or key files from different snapshots.

## Storage behavior

- Group messages are retained in SQLite until the gateway data is deliberately
  removed. Automatic retention limits are not implemented yet.
- Message bodies use XChaCha20-Poly1305 before entering SQLite.
- Group names, room names, nicknames, sequence numbers and timestamps remain
  queryable metadata in SQLite.
- Group access mode, member status, private-room membership, credential hashes,
  and approval requests are also gateway metadata. Plaintext group tokens are
  not stored there.
- Private messages never enter SQLite and are not recoverable after both peers
  close the conversation.
- Deleting the gateway data directory and every backup permanently destroys
  group history.

See [SECURITY.md](SECURITY.md) for the trust model and explicit limitations.
