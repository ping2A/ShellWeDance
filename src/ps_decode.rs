//! Decode PowerShell -EncodedCommand / -enc base64 payloads.
//! PowerShell uses Base64(UTF-16LE(script)) for -EncodedCommand.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use regex::Regex;

/// Extract and decode the first -enc / -encodedcommand payload from a PowerShell command line.
/// Returns the decoded script as UTF-8 String, or None if no valid payload found.
pub fn decode_encoded_command(command_line: &str) -> Option<String> {
    let re = Regex::new(r#"(?i)-(?:enc(?:odedcommand)?|encodedcommand)\s+["']*\s*([A-Za-z0-9+/]+=*)"#)
        .ok()?;
    let cap = re.captures(command_line)?;
    let b64 = cap.get(1)?.as_str();
    decode_base64_utf16le(b64).ok()
}

/// Decode base64 string as PowerShell -EncodedCommand: Base64(UTF-16LE(bytes)) -> String.
fn decode_base64_utf16le(b64: &str) -> Result<String> {
    let bytes = STANDARD
        .decode(b64.as_bytes())
        .context("base64 decode")?;
    utf16le_to_string(&bytes)
}

/// Decode UTF-16LE bytes to String (with BOM and replacement char for invalid).
fn utf16le_to_string(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    // Skip BOM if present
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        i = 2;
    }
    while i + 1 < bytes.len() {
        let low = bytes[i] as u16;
        let high = bytes[i + 1] as u16;
        u16s.push(low | (high << 8));
        i += 2;
    }
    Ok(String::from_utf16_lossy(&u16s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_encoded_command() {
        // "echo \"Hello\"" in UTF-16LE then base64 (PowerShell -enc)
        let cmd = "powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIACgA=";
        let decoded = decode_encoded_command(cmd).expect("decode");
        assert!(decoded.contains("echo"));
        assert!(decoded.contains("Hello"));
    }

    #[test]
    fn test_decode_no_enc() {
        assert!(decode_encoded_command("powershell Get-Process").is_none());
    }
}
