use super::decode_editor;
use crate::{
    engine::{Intercepted, Stage},
    http::Message,
    model::{Destination, Exchange, RepeaterTab},
};
use std::time::{SystemTime, UNIX_EPOCH};

fn request_snapshot(
    request: Message,
    destination: Destination,
    tool: &str,
) -> anyhow::Result<Exchange> {
    let mut routed = request.clone();
    routed.prepare_request(&destination)?;
    Ok(Exchange {
        id: 0,
        timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
        tool: tool.into(),
        url: routed.url(&destination),
        destination,
        method: request.method().into(),
        request: request.encode(),
        response: vec![],
        status: 0,
        duration_ms: 0,
        error: None,
        omitted_response_body_bytes: None,
        streamed_response: None,
        note: String::new(),
    })
}

pub(super) fn repeater(tab: &RepeaterTab) -> anyhow::Result<Exchange> {
    request_snapshot(
        decode_editor(&tab.request, tab.request_hex)?,
        Destination::from_url(&tab.destination)?,
        "Repeater",
    )
}

pub(super) fn intercept(item: &Intercepted, text: &str, is_hex: bool) -> anyhow::Result<Exchange> {
    let edited = edited_intercept(item, text, is_hex, 32 * 1024 * 1024)?;
    if item.stage == Stage::Request {
        request_snapshot(edited, item.destination.clone(), "Proxy")
    } else {
        let request = item
            .request
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("No originating request for this response"))?;
        let mut snapshot = request_snapshot(request.clone(), item.destination.clone(), "Proxy")?;
        snapshot.url = item.url.clone();
        snapshot.status = edited.status();
        snapshot.response = edited.encode();
        Ok(snapshot)
    }
}

pub(super) fn intercept_forward(
    item: &Intercepted,
    text: &str,
    is_hex: bool,
    limit: usize,
) -> anyhow::Result<Message> {
    let edited = edited_intercept(item, text, is_hex, limit)?;
    if item.stage == Stage::Response
        && let Some(preview) = super::response_content::decoded(&item.message, limit)
        && edited == preview
    {
        // Inspecting a decoded preview without editing must forward the original bytes.
        return Ok(item.message.clone());
    }
    Ok(edited)
}

fn edited_intercept(
    item: &Intercepted,
    text: &str,
    is_hex: bool,
    limit: usize,
) -> anyhow::Result<Message> {
    let mut edited = decode_editor(text, is_hex)?;
    if super::response_content::intercept_omission(item, limit).is_some() {
        anyhow::ensure!(
            edited.body.is_empty(),
            "This body is hidden; edit only its HTTP headers"
        );
        edited.body = item.message.body.clone();
    }
    Ok(edited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn header_only_edits_of_omitted_bodies_never_forward_the_placeholder() {
        let mut response =
            Message::parse(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n").unwrap();
        response.body = vec![b'x'; super::super::response_content::DISPLAY_LIMIT + 1];
        response.normalize_length();
        let item = Intercepted {
            id: 9,
            stage: Stage::Response,
            destination: Destination::from_url("https://example.test").unwrap(),
            url: "https://example.test/".into(),
            message: response.clone(),
            request: None,
        };
        for is_hex in [false, true] {
            let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Edited: yes\r\n\r\n";
            let text = if is_hex {
                super::super::hex(headers.as_bytes())
            } else {
                headers.into()
            };
            let edited = intercept_forward(&item, &text, is_hex, 32 * 1024 * 1024).unwrap();
            assert_eq!(edited.header("X-Edited"), Some("yes"));
            assert_eq!(edited.body, response.body);
        }
        assert!(
            intercept_forward(
                &item,
                "HTTP/1.1 200 OK\n\n[Body too large to be displayed]",
                false,
                32 * 1024 * 1024
            )
            .is_err()
        );
        assert_eq!(item.message, response);
    }

    #[test]
    fn repeater_actions_use_current_edits_and_the_selected_destination() {
        let tab = RepeaterTab {
            destination: "https://example.test:8443".into(),
            request: "POST /edited?q=1 HTTP/1.1\nHost: virtual.test\n\nnew body".into(),
            ..Default::default()
        };
        let snapshot = repeater(&tab).unwrap();
        assert_eq!(snapshot.url, "https://example.test:8443/edited?q=1");
        assert_eq!(Message::parse(&snapshot.request).unwrap().body, b"new body");
        assert_eq!(
            Message::parse(&snapshot.request).unwrap().header("Host"),
            Some("virtual.test")
        );
    }

    #[test]
    fn intercepted_response_actions_retain_the_corresponding_request() {
        let request =
            Message::parse(b"POST /paired?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\nrequest body")
                .unwrap();
        let item = Intercepted {
            id: 1,
            stage: Stage::Response,
            destination: Destination::from_url("https://example.test").unwrap(),
            url: "https://example.test:443/paired?q=1".into(),
            message: Message::parse(b"HTTP/1.1 200 OK\r\n\r\nold body").unwrap(),
            request: Some(Arc::new(request.clone())),
        };
        let snapshot = intercept(&item, "HTTP/1.1 201 Created\n\nupdated response", false).unwrap();
        assert_eq!(snapshot.request, request.encode());
        assert_eq!(snapshot.url, item.url);
        assert_eq!(snapshot.status, 201);
        assert_eq!(
            Message::parse(&snapshot.response).unwrap().body,
            b"updated response"
        );
    }

    #[test]
    fn unedited_decoded_intercept_forwards_original_compressed_response() {
        use base64::Engine as _;
        let mut response = Message::parse(b"HTTP/2 200\r\nContent-Encoding: br\r\n\r\n").unwrap();
        response.body = base64::engine::general_purpose::STANDARD.decode(
            "G1oAiCwO7JiExdvQHBei9jGSglM8RF2W9iY3w8bkkqyNDhxywF7bzZKAWm5wommUFiTx8gM5l1pbhdSZtQmFGYZjiNZvnxUA"
        ).unwrap();
        let item = Intercepted {
            id: 7,
            stage: Stage::Response,
            destination: Destination::from_url("https://example.test").unwrap(),
            url: "https://example.test:443/".into(),
            message: response.clone(),
            request: None,
        };
        let mut preview = super::super::response_content::decoded(&response, 4096).unwrap();
        assert!(preview.body.starts_with(b"<!doctype html>"));
        assert_eq!(
            intercept_forward(
                &item,
                std::str::from_utf8(&preview.encode()).unwrap(),
                false,
                4096
            )
            .unwrap(),
            response
        );
        assert_eq!(
            intercept_forward(&item, &super::super::hex(&preview.encode()), true, 4096).unwrap(),
            response
        );
        preview.body = b"edited response".to_vec();
        let edited = intercept_forward(
            &item,
            std::str::from_utf8(&preview.encode()).unwrap(),
            false,
            4096,
        )
        .unwrap();
        assert_eq!(edited.body, b"edited response");
        assert!(edited.header("Content-Encoding").is_none());
        assert_eq!(item.message, response);
    }
}
