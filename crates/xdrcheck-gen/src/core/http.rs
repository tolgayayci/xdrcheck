//! A minimal HTTP client for stellar-core's command and query servers on loopback.
//!
//! Core's servers speak HTTP/1.0 and close the connection after each reply; some clients (Node's `fetch`)
//! get `400 Bad Request` from them. This client sends one request per connection with
//! `Connection: close`, reads until the server closes, and returns the body of a `200` reply.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// How long one request may take. Generous: a `manualclose` applies a whole ledger before it replies.
const TIMEOUT: Duration = Duration::from_secs(120);

/// `GET /<path_and_query>` on `127.0.0.1:<port>`.
pub fn get(port: u16, path_and_query: &str) -> Result<String> {
    request(port, "GET", path_and_query, None, TIMEOUT)
}

/// [`get`] with another timeout (start-up polling).
pub fn get_with_timeout(port: u16, path_and_query: &str, timeout: Duration) -> Result<String> {
    request(port, "GET", path_and_query, None, timeout)
}

/// `POST /<path>` with a form-encoded body on `127.0.0.1:<port>`.
pub fn post_form(port: u16, path: &str, body: &str) -> Result<String> {
    request(port, "POST", path, Some(body), TIMEOUT)
}

fn request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> Result<String> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .with_context(|| format!("connect to stellar-core on port {port}"))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut req =
        format!("{method} /{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)
        .with_context(|| format!("read reply to {method} /{}", short(path)))?;
    let text = String::from_utf8_lossy(&raw);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        bail!(
            "malformed HTTP reply to /{}: {:?}",
            short(path),
            short(&text)
        );
    };
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("");
    if status != "200" {
        bail!("HTTP {status} from /{}: {}", short(path), short(body));
    }
    Ok(body.to_string())
}

/// Percent-encode everything but RFC 3986 unreserved characters.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The first 200 characters of `s`, for error messages.
pub fn short(s: &str) -> &str {
    match s.char_indices().nth(200) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_base64_and_passphrases() {
        assert_eq!(encode("a+b/c="), "a%2Bb%2Fc%3D");
        assert_eq!(encode("Test SDF ; x"), "Test%20SDF%20%3B%20x");
    }
}
