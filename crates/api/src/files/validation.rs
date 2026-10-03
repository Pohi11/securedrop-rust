//! Input validation for uploads. Everything a client declares is untrusted.

use crate::error::{AppError, AppResult};

/// How many leading bytes we fetch from S3 to sniff the real file type.
pub const SNIFF_LEN: u64 = 512;
const MAX_FILENAME_BYTES: usize = 255;

/// Turn a client-supplied filename into a safe *display* name.
///
/// The filename is never used as an S3 key or a filesystem path (keys are server-generated),
/// but it is shown to other users and placed in `Content-Disposition`, so we still:
/// * drop any directory components (`../../etc/passwd` becomes `passwd`, `C:\x\y.txt` becomes `y.txt`),
/// * strip control characters (header injection, terminal escape sequences),
/// * strip Unicode bidirectional overrides: `invoice_U+202Efdp.exe` *renders* as
///   `invoice_exe.pdf`, a classic trick to disguise executables,
/// * reject empty names, `.`/`..`, and names over 255 bytes.
pub fn sanitize_filename(raw: &str) -> AppResult<String> {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c) && *c != '\u{FEFF}')
        .collect();
    let cleaned = cleaned.trim().trim_end_matches('.').trim().to_string();

    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        return Err(AppError::validation("filename is empty or invalid"));
    }
    if cleaned.len() > MAX_FILENAME_BYTES {
        return Err(AppError::validation("filename is longer than 255 bytes"));
    }
    Ok(cleaned)
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Normalise a MIME type and check it against the allowlist (entries may be `type/*`).
pub fn validate_content_type(raw: &str, allowlist: &[String]) -> AppResult<String> {
    // Drop parameters such as `; charset=utf-8`, lowercase the rest.
    let essence = raw
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    // Strict token syntax. This value ends up in a signed `Content-Type` header, so CR/LF or
    // other separators must be impossible.
    let valid_token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    let Some((ty, subtype)) = essence.split_once('/') else {
        return Err(AppError::validation(
            "content_type must look like type/subtype",
        ));
    };
    if !valid_token(ty) || !valid_token(subtype) {
        return Err(AppError::validation(
            "content_type must look like type/subtype",
        ));
    }

    let allowed = allowlist.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        match entry.strip_suffix("/*") {
            Some(prefix) => prefix == ty,
            None => entry == essence,
        }
    });
    if !allowed {
        return Err(AppError::validation(format!(
            "content type '{essence}' is not allowed"
        )));
    }
    Ok(essence)
}

pub fn parse_sha256_hex(raw: &str) -> AppResult<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(raw.trim(), &mut out)
        .map_err(|_| AppError::validation("sha256 must be 64 hexadecimal characters"))?;
    Ok(out)
}

/// Compare the first bytes of the uploaded object with what the client claimed.
///
/// The API never sees file contents, but S3 lets us fetch just the first 512 bytes with a
/// ranged GET. That is enough to catch the two cases that matter:
/// 1. **Executables**, which are never accepted regardless of the declared type.
/// 2. **Type spoofing**: a declared type with a well-known signature (PNG, PDF, ...) whose
///    bytes don't match it.
///
/// This is *not* malware scanning. In AWS that is GuardDuty Malware Protection for S3 (see
/// Terraform). It is a cheap integrity check on metadata other users will rely on.
pub fn check_magic_bytes(declared: &str, prefix: &[u8]) -> Result<(), String> {
    const EXECUTABLES: &[(&[u8], &str)] = &[
        (b"\x7fELF", "ELF executable"),
        (b"MZ", "Windows PE executable"),
        (b"\xfe\xed\xfa\xce", "Mach-O executable"),
        (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
        (b"\xce\xfa\xed\xfe", "Mach-O executable"),
        (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
        (b"#!", "script with interpreter line"),
    ];
    for (magic, what) in EXECUTABLES {
        if prefix.starts_with(magic) {
            return Err(format!("{what} files are not accepted"));
        }
    }

    let expected: &[&[u8]] = match declared {
        "image/png" => &[b"\x89PNG\r\n\x1a\n"],
        "image/jpeg" => &[b"\xff\xd8\xff"],
        "image/gif" => &[b"GIF87a", b"GIF89a"],
        "image/webp" => &[b"RIFF"],
        "application/pdf" => &[b"%PDF-"],
        "application/gzip" => &[b"\x1f\x8b"],
        "application/zip"
        | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        | "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            &[b"PK\x03\x04", b"PK\x05\x06"]
        }
        _ => return Ok(()),
    };
    if expected.iter().any(|magic| prefix.starts_with(magic)) {
        Ok(())
    } else {
        Err(format!(
            "file contents do not match declared type {declared}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_strips_paths_and_dangerous_characters() {
        assert_eq!(sanitize_filename("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(
            sanitize_filename("C:\\Users\\x\\report.pdf").unwrap(),
            "report.pdf"
        );
        assert_eq!(sanitize_filename("in\u{202E}fdp.exe").unwrap(), "infdp.exe");
        assert_eq!(sanitize_filename("a\r\nb.txt").unwrap(), "ab.txt");
        assert_eq!(sanitize_filename("  notes.txt...  ").unwrap(), "notes.txt");
        for bad in ["", "..", "dir/", "\u{202E}", &"x".repeat(256)] {
            assert!(sanitize_filename(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn content_type_allowlist() {
        let allow = vec!["text/plain".to_string(), "image/*".to_string()];
        assert_eq!(
            validate_content_type("Text/Plain; charset=UTF-8", &allow).unwrap(),
            "text/plain"
        );
        assert_eq!(
            validate_content_type("image/png", &allow).unwrap(),
            "image/png"
        );
        assert!(validate_content_type("text/html", &allow).is_err());
        assert!(validate_content_type("text/plain\r\nX-Evil: 1", &allow).is_err());
        assert!(validate_content_type("nonsense", &allow).is_err());
    }

    #[test]
    fn sha256_parsing() {
        assert!(parse_sha256_hex(&"ab".repeat(32)).is_ok());
        assert!(parse_sha256_hex("abc").is_err());
        assert!(parse_sha256_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn magic_bytes() {
        assert!(check_magic_bytes("text/plain", b"hello").is_ok());
        assert!(check_magic_bytes("text/plain", b"\x7fELF\x02\x01").is_err());
        assert!(check_magic_bytes("application/pdf", b"MZ\x90\x00").is_err());
        assert!(check_magic_bytes("application/pdf", b"%PDF-1.7").is_ok());
        assert!(check_magic_bytes("image/png", b"GIF89a").is_err());
    }
}
