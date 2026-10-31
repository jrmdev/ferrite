//! Clipboard representations of a captured or currently edited request.
use crate::{http::Message, model::Exchange};
use anyhow::{Result, ensure};
use std::fmt::Write as _;

fn request(flow: &Exchange) -> Result<Message> {
    let mut request = Message::parse(&flow.request)?;
    let parts: Vec<_> = request.start.split_whitespace().collect();
    ensure!(
        parts.len() == 3
            && !parts[0].starts_with("HTTP/")
            && parts[0]
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'-'),
        "Cannot copy an invalid HTTP request"
    );
    ensure!(!flow.url.contains('\0'), "Cannot copy a URL containing NUL");
    // Bodies in the workbench are already dechunked. Recompute framing, including
    // when the user has edited a body without updating its Content-Length.
    request.normalize_length();
    Ok(request)
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

pub(super) fn curl(flow: &Exchange) -> Result<String> {
    let request = request(flow)?;
    let version = match request.start.split_whitespace().last() {
        Some("HTTP/1.0") => "--http1.0",
        Some("HTTP/2" | "HTTP/2.0") => "--http2",
        _ => "--http1.1",
    };
    let mut command = format!(
        "curl --globoff --path-as-is {version} \\\n  --request {} \\\n  --url {}",
        shell_quote(request.method()),
        shell_quote(&flow.url),
    );
    for (name, value) in &request.headers {
        // curl uses a semicolon to send an empty header; a colon suppresses it.
        let header = if value.is_empty() {
            format!("{name};")
        } else {
            format!("{name}: {value}")
        };
        write!(command, " \\\n  --header {}", shell_quote(&header))?;
    }
    // Suppress curl's defaults when the original request omitted these headers.
    for name in ["Accept", "User-Agent", "Content-Type"] {
        if request.header(name).is_none() {
            write!(
                command,
                " \\\n  --header {}",
                shell_quote(&format!("{name}:"))
            )?;
        }
    }
    if !request.body.is_empty() {
        match std::str::from_utf8(&request.body) {
            Ok(body) if !body.contains(['\0', '\r']) && !body.starts_with('@') => {
                write!(command, " \\\n  --data-binary {}", shell_quote(body))?;
            }
            _ => {
                // POSIX printf %b decodes octal without putting NUL in argv or
                // relying on bash-specific quoting or a separate payload file.
                let mut octal = String::new();
                for byte in &request.body {
                    write!(octal, "\\0{byte:03o}")?;
                }
                command = format!(
                    "printf '%b' {} | {command} \\\n  --data-binary @-",
                    shell_quote(&octal),
                );
            }
        }
    }
    Ok(command)
}

fn python_string(text: &str) -> String {
    // JSON string escapes are also valid in a Python string literal.
    serde_json::to_string(text).expect("serializing a string cannot fail")
}

fn python_bytes(bytes: &[u8]) -> String {
    let mut literal = String::from("b'");
    for byte in bytes {
        match byte {
            b'\'' => literal.push_str("\\'"),
            b'\\' => literal.push_str("\\\\"),
            b'\r' => literal.push_str("\\r"),
            b'\n' => literal.push_str("\\n"),
            b'\t' => literal.push_str("\\t"),
            0x20..=0x7e => literal.push(*byte as char),
            _ => write!(literal, "\\x{byte:02x}").unwrap(),
        }
    }
    literal.push('\'');
    literal
}

// Dictionaries cannot represent repeated header names; combine values in order.
fn combined_headers(request: &Message, include_cookies: bool) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in &request.headers {
        if !include_cookies && name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        if let Some((_, existing)) = headers
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            existing.push_str(if name.eq_ignore_ascii_case("cookie") {
                "; "
            } else {
                ", "
            });
            existing.push_str(value);
        } else {
            headers.push((name.clone(), value.clone()));
        }
    }
    headers
}

pub(super) fn python(flow: &Exchange) -> Result<String> {
    let request = request(flow)?;
    let mut script = format!(
        "import requests\n\nurl = {}\nbody = {}\nheaders = {{\n",
        python_string(&flow.url),
        python_bytes(&request.body),
    );
    for (name, value) in combined_headers(&request, false) {
        writeln!(
            script,
            "    {}: {},",
            python_string(&name),
            python_string(&value)
        )?;
    }
    script.push_str("}\ncookies = {\n");
    for (_, value) in request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
    {
        for cookie in value.split(';') {
            if let Some((name, value)) = cookie.trim().split_once('=') {
                writeln!(
                    script,
                    "    {}: {},",
                    python_string(name.trim()),
                    python_string(value.trim())
                )?;
            }
        }
    }
    write!(
        script,
        concat!(
            "}}\n\nprepared = requests.Request(method={}, url=url, headers=headers, cookies=cookies, data=body).prepare()\n",
            "prepared.url = url\n",
            "\n",
            "with requests.Session() as session:\n",
            "    response = session.send(prepared, allow_redirects=False, timeout=30)\n",
            "    print(response.status_code)\n",
            "    print(response.text)\n",
        ),
        python_string(request.method()),
    )?;
    Ok(script)
}

fn powershell_string(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

pub(super) fn powershell(flow: &Exchange) -> Result<String> {
    let request = request(flow)?;
    let mut script = format!("$url = {}\n$headers = @{{\n", powershell_string(&flow.url));
    for (name, value) in combined_headers(&request, true) {
        writeln!(
            script,
            "    {} = {}",
            powershell_string(&name),
            powershell_string(&value)
        )?;
    }
    script.push_str("}\n");
    if !request.body.is_empty() {
        script.push_str("$body = [byte[]] @(");
        for (index, byte) in request.body.iter().enumerate() {
            if index > 0 {
                script.push_str(", ");
            }
            write!(script, "{byte}")?;
        }
        script.push_str(")\n");
    }
    writeln!(script, "$request = [System.Net.WebRequest]::Create($url)")?;
    writeln!(
        script,
        "$request.Method = {}",
        powershell_string(request.method())
    )?;
    script.push_str(concat!(
        "$request.AllowAutoRedirect = $false\n",
        "$request.ServicePoint.Expect100Continue = $false\n",
        "foreach ($entry in $headers.GetEnumerator()) {\n",
        "    switch ($entry.Key.ToLowerInvariant()) {\n",
        "        'accept' { $request.Accept = $entry.Value }\n",
        "        'content-type' { $request.ContentType = $entry.Value }\n",
        "        'content-length' { $request.ContentLength = [long]$entry.Value }\n",
        "        'host' { $request.Host = $entry.Value }\n",
        "        'referer' { $request.Referer = $entry.Value }\n",
        "        'user-agent' { $request.UserAgent = $entry.Value }\n",
        "        'date' { $request.Date = [DateTimeOffset]::Parse($entry.Value).UtcDateTime }\n",
        "        'if-modified-since' { $request.IfModifiedSince = [DateTimeOffset]::Parse($entry.Value).UtcDateTime }\n",
        "        'connection' {\n",
        "            $tokens = @($entry.Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })\n",
        "            if ($tokens -contains 'close') { $request.KeepAlive = $false }\n",
        "            $other = @($tokens | Where-Object { $_ -notin @('keep-alive', 'close') })\n",
        "            if ($other.Count) { $request.Connection = $other -join ', ' }\n",
        "        }\n",
        "        'expect' {\n",
        "            $tokens = @($entry.Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })\n",
        "            if ($tokens -contains '100-continue') { $request.ServicePoint.Expect100Continue = $true }\n",
        "            $other = @($tokens | Where-Object { $_ -ne '100-continue' })\n",
        "            if ($other.Count) { $request.Expect = $other -join ', ' }\n",
        "        }\n",
        "        'range' {\n",
        "            if ($entry.Value -notmatch '^bytes=(.+)$') { throw 'Unsupported Range header' }\n",
        "            foreach ($part in ($Matches[1] -split ',')) {\n",
        "                if ($part.Trim() -notmatch '^(\\d*)-(\\d*)$' -or (!$Matches[1] -and !$Matches[2])) { throw 'Unsupported Range header' }\n",
        "                if (!$Matches[1]) { $request.AddRange(-[long]$Matches[2]) }\n",
        "                elseif (!$Matches[2]) { $request.AddRange([long]$Matches[1]) }\n",
        "                else { $request.AddRange([long]$Matches[1], [long]$Matches[2]) }\n",
        "            }\n",
        "        }\n",
        "        default { $request.Headers[$entry.Key] = $entry.Value }\n",
        "    }\n",
        "}\n",
    ));
    if !request.body.is_empty() {
        script.push_str(concat!(
            "$stream = $request.GetRequestStream()\n",
            "try { $stream.Write($body, 0, $body.Length) } finally { $stream.Dispose() }\n",
        ));
    }
    script.push_str(concat!(
        "try { $response = $request.GetResponse() }\n",
        "catch [System.Net.WebException] {\n",
        "    if (!$_.Exception.Response) { throw }\n",
        "    $response = $_.Exception.Response\n",
        "}\n",
        "try {\n",
        "    [int]$response.StatusCode\n",
        "    $reader = [System.IO.StreamReader]::new($response.GetResponseStream())\n",
        "    try { $reader.ReadToEnd() } finally { $reader.Dispose() }\n",
        "} finally { $response.Dispose() }\n",
    ));
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Destination;

    fn flow(body: &[u8]) -> Exchange {
        Exchange {
            id: 1,
            timestamp_ms: 0,
            tool: "Proxy".into(),
            destination: Destination::from_url("https://example.test").unwrap(),
            url: "https://example.test/a/../b?q=';$(echo injected)&x=1".into(),
            method: "POST".into(),
            request: [
                b"POST / HTTP/2\r\nHost: virtual.test\r\nX-Repeat: first\r\nX-Repeat: second\r\nX-Empty: \r\nCookie: id='secret'\r\nContent-Length: 999\r\n\r\n".as_slice(),
                body,
            ].concat(),
            response: vec![],
            status: 0,
            duration_ms: 0,
            error: None,
            note: String::new(),
        }
    }

    #[test]
    fn curl_preserves_headers_and_quotes_shell_metacharacters() {
        let command = curl(&flow(b"hello 'world'")).unwrap();
        assert!(command.contains("--request 'POST'"));
        assert!(command.contains("--http2"));
        assert!(!command.lines().any(|line| line.starts_with('+')));
        assert!(
            command.contains("--url 'https://example.test/a/../b?q='\"'\"';$(echo injected)&x=1'")
        );
        assert!(command.contains("--header 'Host: virtual.test'"));
        assert!(command.contains("--header 'X-Repeat: first'"));
        assert!(command.contains("--header 'X-Repeat: second'"));
        assert!(command.contains("--header 'X-Empty;'"));
        assert!(command.contains("--header 'Content-Length: 13'"));
        assert!(command.contains("--data-binary 'hello '\"'\"'world'\"'\"''"));
    }

    #[test]
    fn binary_and_at_prefixed_bodies_use_stdin_instead_of_shell_arguments_or_files() {
        for body in [b"\0\xff\r\n".as_slice(), b"@/private/file"] {
            let command = curl(&flow(body)).unwrap();
            assert!(command.starts_with("printf '%b' '"));
            assert!(command.ends_with("--data-binary @-"));
            assert!(!command.contains('\0'));
        }
        assert!(
            curl(&flow(b"\0\xff\r\n"))
                .unwrap()
                .contains("\\0000\\0377\\0015\\0012")
        );
    }

    #[test]
    fn python_uses_requests_dictionaries_and_preserves_binary_body() {
        let script = python(&flow(b"\0\xff'\\\r\n")).unwrap();
        assert!(script.contains("body = b'\\x00\\xff\\'\\\\\\r\\n'"));
        assert!(script.contains("\"X-Repeat\": \"first, second\""));
        assert!(script.contains("\"Content-Length\": \"6\""));
        assert!(script.contains("\"id\": \"'secret'\""));
        assert!(!script.contains("urllib"));
        assert!(script.contains("headers=headers, cookies=cookies, data=body"));
        assert!(script.contains("allow_redirects=False"));
        assert!(script.contains("\n    response = session.send("));
    }

    #[test]
    fn powershell_quotes_values_and_preserves_binary_body() {
        let script = powershell(&flow(b"\0\xff'\\\r\n")).unwrap();
        assert!(script.contains("'X-Repeat' = 'first, second'"));
        assert!(script.contains("'Cookie' = 'id=''secret'''"));
        assert!(script.contains("$body = [byte[]] @(0, 255, 39, 92, 13, 10)"));
        assert!(script.contains("$request.Method = 'POST'"));
        assert!(!script.contains("-SkipHttpErrorCheck"));
        assert!(!script.contains("-SkipHeaderValidation"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_powershell_sends_restricted_headers_cookies_and_binary_body() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            process::Command,
            time::Duration,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/test", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && start.elapsed() < Duration::from_secs(15) =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("No request received: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 4096];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(head) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    if bytes.len() >= head + 4 + 3 {
                        break;
                    }
                }
            }
            stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmissing").unwrap();
            bytes
        });
        let mut flow = flow(&[0, 254, 65]);
        flow.url = url;
        flow.request = b"POST /test HTTP/1.1\r\nHost: virtual.test\r\nConnection: keep-alive\r\nCookie: id=secret; token=a=b\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\n\r\n\0\xfeA".to_vec();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("request.ps1");
        std::fs::write(&file, powershell(&flow).unwrap()).unwrap();
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&file)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("404") && stdout.contains("missing"),
            "{stdout}"
        );
        let bytes = server.join().unwrap();
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        let headers = String::from_utf8_lossy(&bytes[..split]).to_ascii_lowercase();
        assert!(headers.contains("host: virtual.test"), "{headers}");
        assert!(
            headers.contains("cookie: id=secret; token=a=b"),
            "{headers}"
        );
        assert!(
            headers.contains("content-type: application/octet-stream"),
            "{headers}"
        );
        assert_eq!(&bytes[split + 4..], &[0, 254, 65]);
    }

    #[test]
    fn invalid_requests_fail_instead_of_copying_partial_commands() {
        let mut flow = flow(b"");
        flow.request = b"invalid".to_vec();
        assert!(curl(&flow).is_err());
        assert!(python(&flow).is_err());
        assert!(powershell(&flow).is_err());
    }
}
