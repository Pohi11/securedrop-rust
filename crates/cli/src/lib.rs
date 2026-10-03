//! SecureDrop client library. The `securedrop` binary is a thin `clap` front-end over this;
//! tests drive the same code paths directly.

pub mod client;
pub mod credentials;
pub mod transfer;

pub use client::{ApiClient, ApiError};
pub use credentials::CredentialStore;
