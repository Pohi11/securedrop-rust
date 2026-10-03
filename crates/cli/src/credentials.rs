//! Local credential and state storage under `~/.securedrop` (or `$SECUREDROP_HOME`).

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub api_url: String,
    pub access_token: String,
    pub refresh_token: String,
}

/// Directory holding credentials and resumable-upload state.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    dir: PathBuf,
}

impl CredentialStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// `$SECUREDROP_HOME`, else `~/.securedrop`.
    pub fn default_location() -> anyhow::Result<Self> {
        if let Some(dir) = std::env::var_os("SECUREDROP_HOME") {
            return Ok(Self::new(dir));
        }
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .context("cannot determine home directory; set SECUREDROP_HOME")?;
        Ok(Self::new(PathBuf::from(home).join(".securedrop")))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn credentials_path(&self) -> PathBuf {
        self.dir.join("credentials.json")
    }

    pub fn load(&self) -> anyhow::Result<Option<Credentials>> {
        match fs::read(self.credentials_path()) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("corrupt credentials file")?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading credentials"),
        }
    }

    /// Write atomically (temp file + rename) and owner-only, since these are bearer tokens.
    pub fn save(&self, creds: &Credentials) -> anyhow::Result<()> {
        write_private(&self.credentials_path(), &serde_json::to_vec_pretty(creds)?)
    }

    pub fn clear(&self) -> anyhow::Result<()> {
        match fs::remove_file(self.credentials_path()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

/// Atomic, permission-restricted write.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().context("path has no parent")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}
