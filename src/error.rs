//! Turns low-level library errors into wording that makes sense in the interface.

use anyhow::Error;

/// rustls reports a TCP close without close_notify as an unexpected EOF.
const TLS_EOF: &str = "peer closed connection without sending TLS close_notify";
const TLS_EOF_REWRITE: &str = "the server closed the connection without a clean TLS shutdown";

/// Formats an error chain for display to the user.
pub fn friendly(error: &Error) -> String {
    friendly_text(&format!("{error:#}"))
}

/// Rewrites library-specific wording in an already formatted message.
pub fn friendly_text(text: &str) -> String {
    let mut message = strip_library_links(text).trim_end().to_owned();
    if let Some(index) = message.find(TLS_EOF) {
        message.replace_range(index..index + TLS_EOF.len(), TLS_EOF_REWRITE);
        if index == 0
            && let Some(first) = message.get_mut(0..1)
        {
            first.make_ascii_uppercase();
        }
    }
    message
}

/// Removes documentation links that libraries append to error messages.
fn strip_library_links(text: &str) -> String {
    const MARKER: &str = ": https://docs.rs/";
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(MARKER) {
        result.push_str(&rest[..index]);
        let after = &rest[index + MARKER.len()..];
        let url_end = after.find(char::is_whitespace).unwrap_or(after.len());
        rest = after[url_end..].trim_start();
        if !rest.is_empty() && !result.is_empty() {
            result.push(' ');
        }
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_rustls_eof_with_readable_text() {
        assert_eq!(
            friendly_text(
                "peer closed connection without sending TLS close_notify: \
                 https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
            ),
            "The server closed the connection without a clean TLS shutdown"
        );
    }

    #[test]
    fn keeps_surrounding_context() {
        assert_eq!(
            friendly_text(
                "Incomplete HTTP body: peer closed connection without sending TLS close_notify: \
                 https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
            ),
            "Incomplete HTTP body: the server closed the connection without a clean TLS shutdown"
        );
    }

    #[test]
    fn leaves_other_errors_untouched() {
        assert_eq!(
            friendly_text("Connect to example.com:443"),
            "Connect to example.com:443"
        );
    }
}
