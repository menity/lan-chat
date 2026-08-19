# Security model

`lan-chat` treats discovery packets, protocol frames, nicknames, room names and
message content as untrusted input.

## Group chat

- Client-to-gateway transport uses
  `Noise_XX_25519_ChaChaPoly_BLAKE2s`.
- The gateway has a stable Noise identity stored in `gateway-noise.key`.
- Clients may pin that identity with `--fingerprint`.
- The gateway decrypts group messages before validating, persisting and
  forwarding them. The gateway administrator can therefore read or alter group
  chat.
- Message bodies are encrypted with XChaCha20-Poly1305 before they enter
  SQLite. Group, room, nickname, sequence and timestamp metadata is not
  encrypted.
- Database-body encryption protects a copied SQLite file without its key. It
  does not protect a compromised gateway or a stolen complete data directory.
- Message persistence and broadcast are one operation: a message that cannot
  be committed to SQLite is not delivered to the group.

## Group admission and credentials

- Public groups accept any client that completes the pinned gateway handshake.
- Invite groups require a high-entropy bearer invite token.
- Approval groups issue a high-entropy request token. It remains pending until
  a connected administrator approves it; only that same token can use the
  decision.
- On first admission, a client receives a high-entropy persistent anonymous
  member token. Subsequent reconnects update its display nickname but retain
  its member identity, ban state, and private-room grants.
- Every new group has a separate administrator bearer token. Administrator
  actions are authorized again at the gateway and cannot be performed merely
  by modifying the TUI.
- The gateway stores BLAKE3 token hashes and compares fixed-size hashes in
  constant time. It never persists plaintext group tokens.
- Client tokens are plaintext in an OS-protected local JSON file so the CLI can
  reconnect without an account. On Unix its directory is mode `0700` and file
  mode `0600`. Malware or another process running as the same OS user can read
  them.
- Nicknames are anonymous labels, not verified identities. An administrator
  must not treat a displayed approval nickname as proof of who requested it.
- Members can rotate their own member token. Administrators can rotate the
  administrator token and, for invite groups, the shared invite token. The old
  hash is replaced transactionally and other online sessions using the rotated
  member or administrator identity are disconnected.
- Administrators can persistently ban individual member identities. Active
  sessions for that identity are disconnected, and its member token cannot
  reconnect until the ban is removed. Administrator identities cannot be
  banned through the client protocol.
- A credential-bound ban is not an account-system ban. A public-group user can
  erase local credentials and join as a new identity. In an invite group, a
  banned user who still knows the shared invite token can do the same, so rotate
  that invite token when banning. In an approval group, administrators must not
  approve a replacement request from the banned person.

## Rooms

- Public rooms are visible to every active group member.
- Private rooms use a persistent gateway-side access list. The creator and all
  group administrators can list, join, and manage the room; they can add or
  remove other active member identities.
- A private room hides its existence and history from unauthorized clients and
  rejects modified clients at every list, join, history, and send boundary.
- Private-room group messages are not participant-to-participant end-to-end
  encrypted. They have the same gateway trust and SQLite storage properties as
  other group messages. The gateway operator and group administrators remain
  inside the trust boundary.

## Private chat

- Each connected client creates a new Noise static key and listens on a random
  LAN port for the lifetime of that group session.
- The gateway distributes the client's source IP, direct port and session
  fingerprint to other members of the same group.
- Peers verify the direct Noise fingerprint against the member record received
  through their pinned gateway connection.
- Private message content travels only over the direct peer connection and is
  never sent to the gateway or SQLite.
- The initiator can send one opening message. Until the recipient replies, the
  initiator UI and protocol state reject more sends, and the recipient drops a
  second opening message from a modified client.
- Both clients must be online and mutually reachable. No offline private
  mailbox or relay fallback exists.

A malicious or compromised gateway can forge member records, observe client IP
addresses, and attempt a private-chat man-in-the-middle attack. The current
model therefore trusts the pinned gateway for peer introduction. Direct peer
fingerprint comparison through a second channel would provide a stronger
assurance and is future work.

## Defensive limits

- Handshake, group selection, connection and private-hello operations have
  timeouts.
- Protocol frames, messages, lines, queues, connections, rooms and history
  pages are bounded.
- Repeated group-message rate violations disconnect the client.
- Approval groups cap pending requests at 256 and return at most 100 per review
  page to keep database and encrypted-frame use bounded.
- Groups cap persistent anonymous identities at 10,000. Member and private-room
  management results are paged 40 at a time.
- Direct links close when a peer exceeds their private-message rate limit.
- Historical records are dynamically fitted below the encrypted frame limit.
- Terminal control characters are filtered at server and client trust
  boundaries.
- SQLite uses WAL, full synchronous durability, foreign keys, strict tables,
  transactions and a busy timeout.
- Production Rust code forbids `unsafe` blocks.
- Secret key material is zeroized when its owning process objects are dropped.
- On Unix, the gateway data directory and newly created key files receive
  restrictive permissions.
- On Unix, the local client credential directory and file receive restrictive
  permissions, and a credential path that is a symbolic link is rejected.

## Discovery and anonymity limitations

Multicast discovery is unauthenticated. An attacker can advertise a fake
gateway and its own fingerprint. Compare the fingerprint out of band when
authenticity matters; discovery alone is not authentication.

"Anonymous" means there is no user account or globally persistent client
identity. It does not hide network metadata:

- the gateway sees client IP addresses, group membership and group content;
- a private-chat peer sees the other peer's IP address;
- network infrastructure can observe timing and message sizes.

This is not an anonymity network, and group chat is not participant-to-
participant end-to-end encrypted.

The TUI's `F3` focus mode hides gateway, group, room-list, member-list,
fingerprint, status and shortcut details from the screen. This is only visual
privacy against casual shoulder-surfing. It does not change message storage,
transport security, terminal scrollback, process visibility or network
metadata.

The gateway currently has no automatic retention or disk-quota policy. An
operator must monitor free space and choose when to archive or remove data.

## Backup boundary

`lan-chat backup` uses SQLite's online backup API and copies the database key
and gateway Noise key into a new directory. Anyone who obtains that complete
backup can run the gateway and decrypt group history. Store backups securely.

The gateway backup contains authorization hashes, not usable plaintext client
tokens. Back up the client credential file separately if administrator access
must survive removal of all client data. Losing the only administrator token
does not erase history, but it can make an approval group impossible to
administer with the current feature set.

If every gateway database and backup is deleted, group history cannot be
reconstructed. If the database encryption key is deleted, remaining SQLite
copies are intentionally unrecoverable.
