//! Authorization: the single place that decides who may do what to a file.
//!
//! Every file operation goes through [`load_authorized`]. Keeping the policy in one function
//! (instead of `if file.owner_id == user` sprinkled across handlers) means a reviewer can
//! audit the whole access-control model on one screen, and new endpoints can't forget a check:
//! there is no other way to obtain a `FileRecord` for a user.

use uuid::Uuid;

use super::{
    model::{FileRecord, STATUS_AVAILABLE},
    repo,
};
use crate::{
    error::{AppError, AppResult},
    shares,
    state::AppState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// See name, size, hash, status.
    ViewMetadata,
    /// Obtain a presigned download URL.
    Download,
    /// Presign parts, check progress, complete or abort an upload.
    ManageUpload,
    /// Grant access, create or revoke share links.
    Share,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    Owner,
    Grantee,
    None,
}

/// The policy as a pure function: easy to read, easy to unit-test exhaustively.
///
/// | relation | view | download | manage upload | share | delete |
/// |----------|------|----------|---------------|-------|--------|
/// | owner    |  ✓   |    ✓     |      ✓        |   ✓   |   ✓    |
/// | grantee  |  ✓*  |    ✓*    |      ✗        |   ✗   |   ✗    |
/// | other    |  ✗   |    ✗     |      ✗        |   ✗   |   ✗    |
///
/// `*` only once the file is available (grantees never see half-uploaded files).
pub fn decide(relation: Relation, action: Action, file_available: bool) -> Decision {
    match (relation, action) {
        (Relation::Owner, _) => Decision::Allow,
        (Relation::Grantee, Action::ViewMetadata | Action::Download) if file_available => {
            Decision::Allow
        }
        // A grantee already knows the file exists, so a 403 reveals nothing new.
        (Relation::Grantee, Action::ManageUpload | Action::Share | Action::Delete) => {
            Decision::Forbidden
        }
        // Everyone else (and grantees of not-yet-available files) gets a 404, never a 403:
        // a 403 would confirm that a guessed or leaked file id exists.
        _ => Decision::NotFound,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Forbidden,
    NotFound,
}

/// Load a file and check that `actor` may perform `action` on it.
pub async fn load_authorized(
    state: &AppState,
    actor: Uuid,
    file_id: Uuid,
    action: Action,
) -> AppResult<FileRecord> {
    let file = repo::find_by_id(&state.db, file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    let relation = if file.owner_id == actor {
        Relation::Owner
    } else if shares::repo::has_grant(&state.db, file.id, actor).await? {
        Relation::Grantee
    } else {
        Relation::None
    };

    match decide(relation, action, file.status == STATUS_AVAILABLE) {
        Decision::Allow => Ok(file),
        Decision::Forbidden => Err(AppError::Forbidden),
        Decision::NotFound => Err(AppError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Action; 5] = [
        Action::ViewMetadata,
        Action::Download,
        Action::ManageUpload,
        Action::Share,
        Action::Delete,
    ];

    #[test]
    fn owner_can_do_everything() {
        for action in ALL {
            for available in [true, false] {
                assert_eq!(decide(Relation::Owner, action, available), Decision::Allow);
            }
        }
    }

    #[test]
    fn strangers_get_not_found_for_everything() {
        for action in ALL {
            for available in [true, false] {
                assert_eq!(
                    decide(Relation::None, action, available),
                    Decision::NotFound
                );
            }
        }
    }

    #[test]
    fn grantees_can_only_read_available_files() {
        assert_eq!(
            decide(Relation::Grantee, Action::Download, true),
            Decision::Allow
        );
        assert_eq!(
            decide(Relation::Grantee, Action::ViewMetadata, true),
            Decision::Allow
        );
        assert_eq!(
            decide(Relation::Grantee, Action::Download, false),
            Decision::NotFound
        );
        for action in [Action::ManageUpload, Action::Share, Action::Delete] {
            assert_eq!(decide(Relation::Grantee, action, true), Decision::Forbidden);
        }
    }
}
