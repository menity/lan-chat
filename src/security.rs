use anyhow::{Result, bail};

pub const MAX_NICKNAME_CHARS: usize = 32;
pub const MAX_GROUP_NAME_CHARS: usize = 64;
pub const MAX_STATUS_CHARS: usize = 256;
pub const MAX_MESSAGE_BYTES: usize = 4096;
pub const MAX_MESSAGE_LINES: usize = 40;
pub const MAX_GROUP_CREDENTIAL_BYTES: usize = 128;

pub fn sanitize_nickname(raw: &str) -> Result<String> {
    sanitize_single_line(raw, "nickname", MAX_NICKNAME_CHARS)
}

pub fn sanitize_group_name(raw: &str) -> Result<String> {
    sanitize_single_line(raw, "group name", MAX_GROUP_NAME_CHARS)
}

pub fn sanitize_room_name(raw: &str) -> Result<String> {
    sanitize_single_line(raw, "room name", MAX_NICKNAME_CHARS)
}

pub fn sanitize_status_text(raw: &str) -> Result<String> {
    sanitize_single_line(raw, "status text", MAX_STATUS_CHARS)
}

pub fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub fn is_valid_fingerprint(value: &str) -> bool {
    value.len() == 29
        && value.char_indices().all(|(index, ch)| {
            if matches!(index, 4 | 9 | 14 | 19 | 24) {
                ch == ':'
            } else {
                ch.is_ascii_hexdigit()
            }
        })
}

pub fn is_valid_group_credential(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GROUP_CREDENTIAL_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn sanitize_group_credential(raw: &str) -> Result<String> {
    let credential = raw.trim();
    if !is_valid_group_credential(credential) {
        bail!("group credential has an invalid format");
    }
    Ok(credential.to_owned())
}

fn sanitize_single_line(raw: &str, field: &str, max_chars: usize) -> Result<String> {
    let sanitized: String = raw
        .trim()
        .chars()
        .filter(|ch| !is_forbidden_terminal_char(*ch))
        .map(|ch| {
            if ch == '\n' || ch == '\r' || ch == '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect();

    if sanitized.is_empty() {
        bail!("{field} cannot be empty");
    }
    if sanitized.chars().count() > max_chars {
        bail!("{field} is longer than {max_chars} characters");
    }
    Ok(sanitized)
}

pub fn sanitize_chat_text(raw: &str) -> Result<String> {
    if raw.len() > MAX_MESSAGE_BYTES {
        bail!("message is larger than {MAX_MESSAGE_BYTES} bytes");
    }

    let mut sanitized = String::with_capacity(raw.len());
    let mut lines = 1usize;
    for ch in raw.chars() {
        match ch {
            '\n' => {
                lines += 1;
                if lines > MAX_MESSAGE_LINES {
                    bail!("message has more than {MAX_MESSAGE_LINES} lines");
                }
                sanitized.push(ch);
            }
            '\t' => sanitized.push(ch),
            '\r' => {}
            ch if is_forbidden_terminal_char(ch) => {}
            ch => sanitized.push(ch),
        }
    }

    let sanitized = sanitized.trim().to_owned();
    if sanitized.is_empty() {
        bail!("message cannot be empty");
    }
    Ok(sanitized)
}

pub fn sanitize_paste_for_input(raw: &str) -> String {
    raw.chars()
        .filter(|ch| !is_forbidden_terminal_char(*ch))
        .map(|ch| {
            if ch == '\n' || ch == '\r' || ch == '\t' {
                ' '
            } else {
                ch
            }
        })
        .take(MAX_MESSAGE_BYTES)
        .collect()
}

fn is_forbidden_terminal_char(ch: char) -> bool {
    ch == '\u{1b}'
        || ch == '\u{7f}'
        || (ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t')
        || ('\u{80}'..='\u{9f}').contains(&ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_escape_sequences_are_neutralized() {
        let text = sanitize_chat_text("hello\u{1b}]52;c;payload\u{7}world").unwrap();
        assert_eq!(text, "hello]52;c;payloadworld");
        assert!(!text.chars().any(is_forbidden_terminal_char));
    }

    #[test]
    fn nickname_is_single_line() {
        assert_eq!(sanitize_nickname(" Alice\nAdmin ").unwrap(), "Alice Admin");
    }

    #[test]
    fn empty_messages_are_rejected() {
        assert!(sanitize_chat_text("\u{1b}\r").is_err());
    }

    #[test]
    fn fingerprints_have_a_strict_display_safe_shape() {
        assert!(is_valid_fingerprint("1234:5678:90ab:cdef:1234:5678"));
        assert!(!is_valid_fingerprint("1234:\u{1b}[31m:5678"));
        assert!(!is_valid_fingerprint("00:00"));
    }

    #[test]
    fn group_credentials_have_a_strict_display_safe_shape() {
        assert!(is_valid_group_credential("lc_invite_0123456789abcdef"));
        assert!(!is_valid_group_credential("token with spaces"));
        assert!(!is_valid_group_credential("token\u{1b}[31m"));
    }
}
