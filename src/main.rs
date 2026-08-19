use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use lan_chat::{
    client,
    credentials::CredentialStore,
    discovery,
    identity::random_nickname,
    protocol::GroupAccessMode,
    security::sanitize_chat_text,
    server::{GatewayConfig, spawn_gateway},
    storage::backup_gateway_data,
    tui,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "lan-chat",
    version,
    about = "Anonymous LAN group chat through a durable gateway"
)]
struct Cli {
    /// Anonymous nickname; generated as “xxx的xxx” when omitted.
    #[arg(long, global = true)]
    nickname: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AccessModeArg {
    Public,
    Invite,
    Approval,
}

impl From<AccessModeArg> for GroupAccessMode {
    fn from(value: AccessModeArg) -> Self {
        match value {
            AccessModeArg::Public => Self::Public,
            AccessModeArg::Invite => Self::Invite,
            AccessModeArg::Approval => Self::Approval,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the persistent LAN gateway on an always-on device.
    Gateway {
        #[arg(long, default_value = "LAN Chat Gateway")]
        name: String,
        #[arg(long, default_value = "0.0.0.0:7373")]
        bind: SocketAddr,
        #[arg(long, default_value = "lan-chat-data")]
        data: PathBuf,
        #[arg(long)]
        no_discovery: bool,
    },
    /// Create a consistent backup of the SQLite database and gateway keys.
    Backup {
        #[arg(long, default_value = "lan-chat-data")]
        data: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect or manage locally saved group credentials.
    Credentials {
        #[command(subcommand)]
        action: CredentialCommand,
    },
    /// Start a gateway, create a group, and enter its TUI.
    Host {
        #[arg(long, default_value = "LAN Chat")]
        group: String,
        #[arg(long, default_value = "0.0.0.0:7373")]
        bind: SocketAddr,
        #[arg(long, default_value = "lan-chat-data")]
        data: PathBuf,
        #[arg(long)]
        no_discovery: bool,
        #[arg(long, value_enum, default_value_t = AccessModeArg::Public)]
        access: AccessModeArg,
    },
    /// Join a gateway directly. Use the TUI for the normal workflow.
    Join {
        endpoint: SocketAddr,
        #[arg(long)]
        group: Option<Uuid>,
        /// Verify the gateway fingerprint before sending application data.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Invite, approval-request, or administrator token.
        #[arg(long)]
        credential: Option<String>,
    },
    /// Create a group on an existing gateway.
    Create {
        endpoint: SocketAddr,
        name: String,
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long, value_enum, default_value_t = AccessModeArg::Public)]
        access: AccessModeArg,
    },
    /// Find gateways advertising themselves on the local network.
    Discover {
        #[arg(long, default_value_t = 3)]
        seconds: u64,
    },
    /// Send one group message without opening the TUI.
    Send {
        endpoint: SocketAddr,
        message: String,
        #[arg(long)]
        group: Option<Uuid>,
        #[arg(long)]
        fingerprint: Option<String>,
        /// Invite, approval-request, or administrator token.
        #[arg(long)]
        credential: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    /// Print the private credential file path.
    Path,
    /// List groups with saved credentials without revealing tokens.
    List,
    /// Reveal one saved credential. Treat the output as a secret.
    Show { gateway: Uuid, group: Uuid },
    /// Import an invite, approval-request, or administrator token.
    Set {
        gateway: Uuid,
        group: Uuid,
        token: String,
        #[arg(long)]
        invite_token: Option<String>,
    },
    /// Remove one locally saved group credential.
    Remove { gateway: Uuid, group: Uuid },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let nickname = cli.nickname.map(Ok).unwrap_or_else(random_nickname)?;
    match cli.command {
        None => run_interactive(nickname).await,
        Some(Command::Gateway {
            name,
            bind,
            data,
            no_discovery,
        }) => {
            let gateway = spawn_gateway(GatewayConfig {
                bind,
                gateway_name: name,
                advertise: !no_discovery,
                data_dir: data,
            })
            .await?;
            println!("gateway:     {}", gateway.info.gateway_name);
            println!("gateway id:  {}", gateway.info.gateway_id);
            println!("listening:   {}", gateway.info.listen_addr);
            println!("fingerprint: {}", gateway.info.fingerprint);
            println!("data:        {}", gateway.info.data_dir.display());
            println!("press Ctrl+C to stop");
            tokio::signal::ctrl_c().await?;
            gateway.shutdown().await
        }
        Some(Command::Backup { data, output }) => {
            backup_gateway_data(&data, &output).await?;
            println!("backup created: {}", output.display());
            println!("store this directory securely; it contains gateway decryption keys");
            Ok(())
        }
        Some(Command::Credentials { action }) => manage_credentials(action),
        Some(Command::Host {
            group,
            bind,
            data,
            no_discovery,
            access,
        }) => {
            let mut credentials = CredentialStore::open_default()?;
            let gateway = spawn_gateway(GatewayConfig {
                bind,
                gateway_name: "LAN Chat Gateway".to_owned(),
                advertise: !no_discovery,
                data_dir: data,
            })
            .await?;
            let endpoint = local_join_address(gateway.info.listen_addr);
            let fingerprint = gateway.info.fingerprint.clone();
            let connection = match client::create_group_with_access(
                endpoint,
                &nickname,
                Some(&fingerprint),
                group,
                access.into(),
            )
            .await
            {
                Ok(connection) => connection,
                Err(error) => {
                    let _ = gateway.shutdown().await;
                    return Err(error);
                }
            };
            persist_connection_credentials(&mut credentials, &connection, None)?;
            let ui_result = tui::run_chat(connection, &mut credentials).await;
            let shutdown_result = gateway.shutdown().await;
            ui_result?;
            shutdown_result?;
            Ok(())
        }
        Some(Command::Join {
            endpoint,
            group,
            fingerprint,
            credential,
        }) => {
            let mut credentials = CredentialStore::open_default()?;
            let supplied = resolve_saved_credential(
                &credentials,
                endpoint,
                &nickname,
                fingerprint.as_deref(),
                group,
                credential,
            )
            .await?;
            let connection = connect_to_selected_group(
                endpoint,
                &nickname,
                fingerprint.as_deref(),
                group,
                supplied.clone(),
            )
            .await?;
            persist_connection_credentials(&mut credentials, &connection, supplied)?;
            if fingerprint.is_none() {
                eprintln!(
                    "gateway fingerprint (TOFU): {}",
                    connection.session.server_fingerprint
                );
            }
            tui::run_chat(connection, &mut credentials).await?;
            Ok(())
        }
        Some(Command::Create {
            endpoint,
            name,
            fingerprint,
            access,
        }) => {
            let mut credentials = CredentialStore::open_default()?;
            let connection = client::create_group_with_access(
                endpoint,
                &nickname,
                fingerprint.as_deref(),
                name,
                access.into(),
            )
            .await?;
            persist_connection_credentials(&mut credentials, &connection, None)?;
            println!("group:    {}", connection.session.group_name);
            println!("group id: {}", connection.session.group_id);
            if let Some(issued) = &connection.session.issued_credentials {
                println!("admin token:  {}", issued.admin_token);
                if let Some(invite) = &issued.invite_token {
                    println!("invite token: {invite}");
                }
                println!("credentials:  {}", credentials.path().display());
            }
            println!(
                "gateway fingerprint: {}",
                connection.session.server_fingerprint
            );
            Ok(())
        }
        Some(Command::Discover { seconds }) => {
            let gateways = discovery::discover(Duration::from_secs(seconds.clamp(1, 30))).await?;
            if gateways.is_empty() {
                println!("No compatible LAN gateways found.");
            } else {
                println!("GATEWAY\tENDPOINT\tPROTOCOL\tFINGERPRINT\tGROUPS");
                for gateway in gateways {
                    let groups = client::inspect_gateway(
                        gateway.endpoint,
                        &nickname,
                        Some(&gateway.server_fingerprint),
                    )
                    .await
                    .map(|snapshot| snapshot.groups.len().to_string())
                    .unwrap_or_else(|_| "unavailable".to_owned());
                    println!(
                        "{}\t{}\t{}-{}\t{}\t{}",
                        gateway.gateway_name,
                        gateway.endpoint,
                        gateway.protocol_min,
                        gateway.protocol_max,
                        gateway.server_fingerprint,
                        groups,
                    );
                }
            }
            Ok(())
        }
        Some(Command::Send {
            endpoint,
            message,
            group,
            fingerprint,
            credential,
        }) => {
            let message = sanitize_chat_text(&message)?;
            let mut credentials = CredentialStore::open_default()?;
            let supplied = resolve_saved_credential(
                &credentials,
                endpoint,
                &nickname,
                fingerprint.as_deref(),
                group,
                credential,
            )
            .await?;
            let mut connection = connect_to_selected_group(
                endpoint,
                &nickname,
                fingerprint.as_deref(),
                group,
                supplied.clone(),
            )
            .await?;
            persist_connection_credentials(&mut credentials, &connection, supplied)?;
            let delivered = client::send_message(&mut connection, message).await?;
            println!(
                "persisted as #{} by {}: {}",
                delivered.sequence, delivered.sender.nickname, delivered.text
            );
            Ok(())
        }
    }
}

async fn resolve_saved_credential(
    store: &CredentialStore,
    endpoint: SocketAddr,
    nickname: &str,
    fingerprint: Option<&str>,
    group_id: Option<Uuid>,
    provided: Option<String>,
) -> Result<Option<String>> {
    if provided.is_some() || group_id.is_none() {
        return Ok(provided);
    }
    let group_id = group_id.context("group id is required to resolve a saved credential")?;
    let snapshot = client::inspect_gateway(endpoint, nickname, fingerprint).await?;
    Ok(store
        .get(snapshot.gateway_id, group_id)
        .map(|record| record.join_token.clone()))
}

async fn connect_to_selected_group(
    endpoint: SocketAddr,
    nickname: &str,
    fingerprint: Option<&str>,
    group_id: Option<Uuid>,
    credential: Option<String>,
) -> Result<client::ClientConnection> {
    if let Some(group_id) = group_id {
        match client::join_group_with_credential(
            endpoint,
            nickname,
            fingerprint,
            group_id,
            credential,
        )
        .await?
        {
            client::JoinOutcome::Connected(connection) => Ok(*connection),
            client::JoinOutcome::Pending(pending) => anyhow::bail!(
                "join request {} is waiting for administrator approval; retry with credential {}",
                pending.request_id,
                pending.request_token
            ),
        }
    } else {
        if credential.is_some() {
            anyhow::bail!("--credential requires --group");
        }
        client::connect(endpoint, nickname, fingerprint).await
    }
}

async fn run_interactive(mut nickname: String) -> Result<()> {
    let mut credentials = CredentialStore::open_default()?;
    let mut lobby_notice = None;
    loop {
        let notice = lobby_notice.take();
        let known = credentials.known_groups();
        let action = tui::run_lobby(&nickname, notice.as_deref(), &known).await?;
        match action {
            tui::LobbyAction::Quit => return Ok(()),
            tui::LobbyAction::SetNickname(updated) => nickname = updated,
            tui::LobbyAction::ForgetCredential {
                gateway_id,
                group_id,
            } => {
                credentials.remove(gateway_id, group_id)?;
                lobby_notice =
                    Some("Saved credential removed; the next join will ask again".to_owned());
            }
            tui::LobbyAction::Join {
                endpoint,
                fingerprint,
                gateway_id,
                group_id,
                credential,
            } => {
                let stored = gateway_id.zip(group_id).and_then(|(gateway_id, group_id)| {
                    credentials
                        .get(gateway_id, group_id)
                        .map(|record| record.join_token.clone())
                });
                let supplied = credential.or(stored);
                let outcome = if let Some(group_id) = group_id {
                    client::join_group_with_credential(
                        endpoint,
                        &nickname,
                        fingerprint.as_deref(),
                        group_id,
                        supplied.clone(),
                    )
                    .await
                } else {
                    client::connect(endpoint, &nickname, fingerprint.as_deref())
                        .await
                        .map(|connection| client::JoinOutcome::Connected(Box::new(connection)))
                };
                match outcome {
                    Ok(client::JoinOutcome::Connected(connection)) => {
                        if let Err(error) =
                            persist_connection_credentials(&mut credentials, &connection, supplied)
                        {
                            lobby_notice = Some(format!("Could not save credential: {error:#}"));
                            continue;
                        }
                        match tui::run_chat(*connection, &mut credentials).await {
                            Ok(tui::ChatAction::BackToLobby) => {}
                            Ok(tui::ChatAction::QuitApplication) => return Ok(()),
                            Err(error) => lobby_notice = Some(format!("Chat closed: {error:#}")),
                        }
                    }
                    Ok(client::JoinOutcome::Pending(pending)) => {
                        credentials.set(
                            pending.gateway_id,
                            pending.group_id,
                            pending.request_token,
                            None,
                        )?;
                        lobby_notice = Some(format!(
                            "Join request {} submitted; select the group again after approval",
                            pending.request_id
                        ));
                    }
                    Err(error) => lobby_notice = Some(format!("Could not join: {error:#}")),
                }
            }
            tui::LobbyAction::Create {
                group_name,
                access_mode,
                endpoint,
                fingerprint,
            } => {
                match client::create_group_with_access(
                    endpoint,
                    &nickname,
                    Some(&fingerprint),
                    group_name,
                    access_mode,
                )
                .await
                {
                    Ok(connection) => {
                        persist_connection_credentials(&mut credentials, &connection, None)?;
                        match tui::run_chat(connection, &mut credentials).await {
                            Ok(tui::ChatAction::BackToLobby) => {}
                            Ok(tui::ChatAction::QuitApplication) => return Ok(()),
                            Err(error) => lobby_notice = Some(format!("Chat closed: {error:#}")),
                        }
                    }
                    Err(error) => lobby_notice = Some(format!("Could not create group: {error:#}")),
                }
            }
        }
    }
}

fn manage_credentials(action: CredentialCommand) -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    match action {
        CredentialCommand::Path => println!("{}", store.path().display()),
        CredentialCommand::List => {
            println!("GATEWAY\tGROUP\tINVITE_TOKEN");
            for record in store.records() {
                println!(
                    "{}\t{}\t{}",
                    record.gateway_id,
                    record.group_id,
                    if record.invite_token.is_some() {
                        "yes"
                    } else {
                        "no"
                    }
                );
            }
        }
        CredentialCommand::Show { gateway, group } => {
            let record = store
                .get(gateway, group)
                .ok_or_else(|| anyhow::anyhow!("no saved credential for that gateway and group"))?;
            eprintln!(
                "warning: the following values grant group access; do not share the admin token"
            );
            println!("join token: {}", record.join_token);
            if let Some(invite_token) = &record.invite_token {
                println!("invite token: {invite_token}");
            }
        }
        CredentialCommand::Set {
            gateway,
            group,
            token,
            invite_token,
        } => {
            store.set(gateway, group, token, invite_token)?;
            println!("credential saved in {}", store.path().display());
        }
        CredentialCommand::Remove { gateway, group } => {
            if store.remove(gateway, group)? {
                println!("credential removed");
            } else {
                println!("no saved credential matched");
            }
        }
    }
    Ok(())
}

fn persist_connection_credentials(
    store: &mut CredentialStore,
    connection: &client::ClientConnection,
    supplied: Option<String>,
) -> Result<()> {
    if let Some(issued) = &connection.session.issued_credentials
        && let Err(error) = store.set(
            connection.session.gateway_id,
            connection.session.group_id,
            issued.admin_token.clone(),
            issued.invite_token.clone(),
        )
    {
        let invite_recovery = issued
            .invite_token
            .as_deref()
            .map(|token| format!("; invite token: {token}"))
            .unwrap_or_default();
        anyhow::bail!(
            "could not save the new group's credentials ({error:#}); copy this administrator token now: {}{}",
            issued.admin_token,
            invite_recovery
        );
    }
    if let Some(member_token) = &connection.session.issued_member_token {
        let invite_token = store
            .get(connection.session.gateway_id, connection.session.group_id)
            .and_then(|record| record.invite_token.clone());
        if let Err(error) = store.set(
            connection.session.gateway_id,
            connection.session.group_id,
            member_token.clone(),
            invite_token,
        ) {
            anyhow::bail!(
                "could not save the newly issued member credential ({error:#}); copy this member token now: {member_token}"
            );
        }
    } else if connection.session.issued_credentials.is_none()
        && let Some(supplied) = supplied
        && store
            .get(connection.session.gateway_id, connection.session.group_id)
            .is_none()
    {
        store.set(
            connection.session.gateway_id,
            connection.session.group_id,
            supplied,
            None,
        )?;
    }
    Ok(())
}

fn local_join_address(listen: SocketAddr) -> SocketAddr {
    match listen.ip() {
        IpAddr::V4(address) if address.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port())
        }
        IpAddr::V6(address) if address.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), listen.port())
        }
        _ => listen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_listeners_use_loopback_for_the_local_tui() {
        let address: SocketAddr = "0.0.0.0:7373".parse().unwrap();
        assert_eq!(local_join_address(address).to_string(), "127.0.0.1:7373");
    }

    #[tokio::test]
    async fn selecting_without_an_id_requires_exactly_one_group() {
        let result =
            connect_to_selected_group("127.0.0.1:9".parse().unwrap(), "Alice", None, None, None)
                .await;
        assert!(result.is_err());
    }
}
