use std::{
    collections::BTreeMap,
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::security::is_valid_group_credential;

const CREDENTIAL_FILE_VERSION: u8 = 1;
const MAX_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredGroupCredential {
    pub gateway_id: Uuid,
    pub group_id: Uuid,
    pub join_token: String,
    pub invite_token: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct CredentialFile {
    version: u8,
    records: Vec<StoredGroupCredential>,
}

pub struct CredentialStore {
    path: PathBuf,
    records: BTreeMap<(Uuid, Uuid), StoredGroupCredential>,
}

impl CredentialStore {
    pub fn open_default() -> Result<Self> {
        let directory = if let Some(path) = env::var_os("LAN_CHAT_CLIENT_DATA_DIR") {
            PathBuf::from(path)
        } else if let Some(path) = env::var_os("XDG_DATA_HOME") {
            PathBuf::from(path).join("lan-chat")
        } else if let Some(path) = env::var_os("HOME") {
            PathBuf::from(path).join(".local/share/lan-chat")
        } else {
            bail!("cannot locate a client data directory; set LAN_CHAT_CLIENT_DATA_DIR or HOME");
        };
        Self::open_at(directory.join("credentials.json"))
    }

    pub fn open_at(path: PathBuf) -> Result<Self> {
        let mut records = BTreeMap::new();
        let parent = path
            .parent()
            .context("client credential path has no parent directory")?;
        create_private_directory(parent)?;
        if path.exists() {
            let metadata =
                fs::symlink_metadata(&path).context("failed to inspect client credentials")?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("client credential path must be a regular file, not a link");
            }
            if metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
                bail!("client credential file is unexpectedly large");
            }
            set_private_path_permissions(&path)?;
            let encoded = fs::read(&path).context("failed to read client credentials")?;
            let file: CredentialFile =
                serde_json::from_slice(&encoded).context("client credential file is invalid")?;
            if file.version != CREDENTIAL_FILE_VERSION {
                bail!("client credential file has an unsupported version");
            }
            for record in file.records {
                validate_record(&record)?;
                let key = (record.gateway_id, record.group_id);
                if records.insert(key, record).is_some() {
                    bail!("client credential file contains a duplicate group");
                }
            }
        }
        Ok(Self { path, records })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, gateway_id: Uuid, group_id: Uuid) -> Option<&StoredGroupCredential> {
        self.records.get(&(gateway_id, group_id))
    }

    pub fn contains(&self, gateway_id: Uuid, group_id: Uuid) -> bool {
        self.records.contains_key(&(gateway_id, group_id))
    }

    pub fn set(
        &mut self,
        gateway_id: Uuid,
        group_id: Uuid,
        join_token: String,
        invite_token: Option<String>,
    ) -> Result<()> {
        let record = StoredGroupCredential {
            gateway_id,
            group_id,
            join_token,
            invite_token,
        };
        validate_record(&record)?;
        self.records.insert((gateway_id, group_id), record);
        self.save()
    }

    pub fn remove(&mut self, gateway_id: Uuid, group_id: Uuid) -> Result<bool> {
        let removed = self.records.remove(&(gateway_id, group_id)).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    pub fn known_groups(&self) -> Vec<(Uuid, Uuid)> {
        self.records.keys().copied().collect()
    }

    pub fn records(&self) -> impl Iterator<Item = &StoredGroupCredential> {
        self.records.values()
    }

    fn save(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("client credential path has no parent directory")?;
        create_private_directory(parent)?;
        let file = CredentialFile {
            version: CREDENTIAL_FILE_VERSION,
            records: self.records.values().cloned().collect(),
        };
        let encoded = serde_json::to_vec_pretty(&file)?;
        let temporary = parent.join(format!(".credentials-{}.tmp", Uuid::new_v4().simple()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_file_mode(&mut options);
        let write_result = (|| -> Result<()> {
            let mut output = options
                .open(&temporary)
                .context("failed to create temporary client credential file")?;
            output.write_all(&encoded)?;
            output.sync_all()?;
            fs::rename(&temporary, &self.path)
                .context("failed to replace client credential file")?;
            set_private_path_permissions(&self.path)?;
            #[cfg(unix)]
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }
}

fn validate_record(record: &StoredGroupCredential) -> Result<()> {
    if !is_valid_group_credential(&record.join_token)
        || record
            .invite_token
            .as_deref()
            .is_some_and(|token| !is_valid_group_credential(token))
    {
        bail!("client credential file contains an invalid token");
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create client data directory {}", path.display()))?;
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

fn set_private_path_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip_without_becoming_public() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credentials.json");
        let gateway_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let mut store = CredentialStore::open_at(path.clone()).unwrap();
        store
            .set(
                gateway_id,
                group_id,
                "lc_admin_0123456789abcdef".to_owned(),
                Some("lc_invite_0123456789abcdef".to_owned()),
            )
            .unwrap();

        let reopened = CredentialStore::open_at(path.clone()).unwrap();
        let record = reopened.get(gateway_id, group_id).unwrap();
        assert_eq!(record.join_token, "lc_admin_0123456789abcdef");
        assert_eq!(
            record.invite_token.as_deref(),
            Some("lc_invite_0123456789abcdef")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
