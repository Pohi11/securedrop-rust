use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use securedrop_cli::{
    ApiClient, CredentialStore,
    transfer::{self, UploadOptions, UploadOutcome},
};
use securedrop_common::CreateShareLinkRequest;
use uuid::Uuid;

/// SecureDrop: secure file transfer from the command line.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// API base URL.
    #[arg(
        long,
        env = "SECUREDROP_API",
        default_value = "http://127.0.0.1:8080",
        global = true
    )]
    api: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an account.
    Register { email: String },
    /// Log in and store tokens in ~/.securedrop/credentials.json.
    Login { email: String },
    /// Revoke this session and forget local tokens.
    Logout,
    /// Show the current user and storage usage.
    Whoami,
    /// Upload a file (large files use resumable multipart uploads).
    Upload {
        path: PathBuf,
        #[arg(long)]
        content_type: Option<String>,
        /// Parts uploaded in parallel.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
    },
    /// List your files (or files shared with you).
    Ls {
        #[arg(long)]
        shared: bool,
    },
    /// Download a file and verify its SHA-256.
    Download {
        file_id: Uuid,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Delete a file you own.
    Rm { file_id: Uuid },
    /// Give another user read access.
    Grant { file_id: Uuid, email: String },
    /// Create a share link (the token is printed once).
    Link {
        file_id: Uuid,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 86_400)]
        expires_in: u64,
        #[arg(long)]
        max_downloads: Option<u32>,
    },
    /// Download using a share link token (no login required).
    Redeem {
        token: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let store = CredentialStore::default_location()?;
    let client = ApiClient::new(&cli.api)?.with_store(store.clone())?;

    match cli.command {
        Command::Register { email } => {
            let password = read_password("Password: ")?;
            let user = client.register(&email, &password).await?;
            println!("registered {} ({})", user.email, user.id);
        }
        Command::Login { email } => {
            let password = read_password("Password: ")?;
            client.login(&email, &password).await?;
            println!("logged in as {email}");
        }
        Command::Logout => {
            client.logout().await?;
            println!("logged out");
        }
        Command::Whoami => {
            let me = client.me().await?;
            println!(
                "{} ({})\nused {} of {} bytes",
                me.email, me.id, me.storage_used_bytes, me.storage_quota_bytes
            );
        }
        Command::Upload {
            path,
            content_type,
            concurrency,
        } => {
            let opts = UploadOptions {
                content_type,
                concurrency,
                state_dir: store.dir().to_path_buf(),
                stop_after_parts: None,
                progress: true,
            };
            match transfer::upload(&client, &path, &opts).await? {
                UploadOutcome::Completed(file) => {
                    println!(
                        "uploaded {} ({} bytes, sha256 {})",
                        file.id, file.size_bytes, file.sha256
                    )
                }
                UploadOutcome::Interrupted {
                    file_id,
                    parts_remaining,
                } => {
                    println!(
                        "upload {file_id} paused with {parts_remaining} parts remaining; run again to resume"
                    )
                }
            }
        }
        Command::Ls { shared } => {
            let mut cursor = None;
            loop {
                let page = client.list_files(shared, cursor).await?;
                for f in &page.files {
                    println!(
                        "{}  {:>12}  {:<9}  {}",
                        f.id,
                        f.size_bytes,
                        format!("{:?}", f.status).to_lowercase(),
                        f.filename
                    );
                }
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
        }
        Command::Download {
            file_id,
            output,
            force,
        } => {
            let info = client.download_info(file_id).await?;
            let dest =
                output.unwrap_or_else(|| PathBuf::from(transfer::safe_local_name(&info.filename)));
            let path = transfer::download_to(&client, &info, &dest, force, true).await?;
            println!("saved {} (sha256 verified)", path.display());
        }
        Command::Rm { file_id } => {
            client.delete_file(file_id).await?;
            println!("deleted {file_id}");
        }
        Command::Grant { file_id, email } => {
            let grant = client.grant(file_id, &email).await?;
            println!("granted {} read access", grant.email);
        }
        Command::Link {
            file_id,
            expires_in,
            max_downloads,
        } => {
            let created = client
                .create_share_link(
                    file_id,
                    &CreateShareLinkRequest {
                        expires_in_secs: Some(expires_in),
                        max_downloads,
                    },
                )
                .await?;
            println!("share token (shown once): {}", created.token);
            println!("expires {}", created.link.expires_at);
        }
        Command::Redeem {
            token,
            output,
            force,
        } => {
            let info = client.redeem_share(&token).await?;
            let dest =
                output.unwrap_or_else(|| PathBuf::from(transfer::safe_local_name(&info.filename)));
            let path = transfer::download_to(&client, &info, &dest, force, true).await?;
            println!("saved {} (sha256 verified)", path.display());
        }
    }
    Ok(())
}

/// Read a password from `SECUREDROP_PASSWORD` (for scripts) or stdin.
/// (Input is echoed; a production CLI would use a no-echo prompt crate such as `rpassword`.)
fn read_password(prompt: &str) -> anyhow::Result<String> {
    if let Ok(pw) = std::env::var("SECUREDROP_PASSWORD") {
        return Ok(pw);
    }
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading password")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}
