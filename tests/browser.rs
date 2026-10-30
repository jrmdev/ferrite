//! End-to-end check of the managed browser against a live Ferrite listener.
//!
//! Requires a Chromium-family browser. Runs when FERRITE_BROWSER_TESTS=1
//! (optionally with FERRITE_BROWSER=/path/to/chrome); otherwise it is skipped.
use ferrite::{
    browser::{self, Browser, BrowserSettings, cdp},
    engine::Engine,
    http::{Message, read_request},
    project::Project,
    tls::Authority,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

fn enabled() -> bool {
    if std::env::var("FERRITE_BROWSER_TESTS").as_deref() != Ok("1") {
        eprintln!("skipping browser test; set FERRITE_BROWSER_TESTS=1 to run it");
        return false;
    }
    true
}

/// Minimal origin: HTML pages, a redirect, a cookie echo, and a cookie setter.
async fn serve_origin<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = tokio::io::BufReader::new(stream);
    let Ok(request) = read_request(&mut reader, 1 << 20).await else {
        return;
    };
    let path = request.target().to_string();
    let cookie = request.header("Cookie").unwrap_or("").to_string();
    let (status, extra, body) = match path.as_str() {
        "/page" => (
            "200 OK",
            "Set-Cookie: session=ferrite-e2e; Path=/; Secure; HttpOnly\r\n".to_string(),
            "<html><head><title>Ferrite origin</title></head><body><script>document.title += ' + js'</script></body></html>".to_string(),
        ),
        "/redirect" => ("302 Found", "Location: /page\r\n".into(), String::new()),
        "/echo" => (
            "200 OK",
            String::new(),
            format!("<html><head><title>cookie:{cookie}</title></head></html>"),
        ),
        _ => (
            "200 OK",
            String::new(),
            format!("<html><head><title>plain:{path}</title></head></html>"),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = reader.into_inner();
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn wait_for_title(devtools: &str, tab: &str, expected: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        if let Ok(value) = cdp::evaluate(devtools, tab, "document.title").await {
            last = value.as_str().unwrap_or_default().to_string();
            if last.contains(expected) {
                return last;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("tab never reached title {expected:?}; last title {last:?}");
}

fn test_settings() -> BrowserSettings {
    let mut args = vec![
        "--headless=new".to_string(),
        "--disable-gpu".into(),
        "--disable-dev-shm-usage".into(),
    ];
    #[cfg(unix)]
    if rustix::process::getuid().is_root() {
        // Chromium's sandbox cannot run as root, as in CI containers.
        args.push("--no-sandbox".into());
    }
    BrowserSettings {
        extra_args: args,
        ..Default::default()
    }
}

async fn devtools_url(browser: &Browser) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(url) = browser.devtools_url() {
            return url;
        }
        assert!(
            Instant::now() < deadline,
            "browser never announced DevTools: {:?}",
            browser.recent_output()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn managed_browser_intercepts_https_without_certificate_errors() {
    if !enabled() {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        // HTTPS origin with a certificate from an unrelated CA: only Ferrite sees it.
        let origin_ca = Authority::from_key(&Authority::generate_key().unwrap()).unwrap();
        let mut origin_tls = (*origin_ca.server_config("origin.test").unwrap()).clone();
        origin_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(origin_tls));
        let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https_port = https.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = https.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        serve_origin(tls).await;
                    }
                });
            }
        });
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_port = http.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = http.accept().await.unwrap();
                tokio::spawn(serve_origin(tcp));
            }
        });

        let engine = Engine::new(Project::temporary()).unwrap();
        let mut settings = engine.settings();
        settings.listen = "127.0.0.1:0".into();
        // The origin's certificate is self-issued; Ferrite's upstream leg is the
        // only place that decision applies. The browser still validates Ferrite.
        settings.verify_tls = false;
        settings
            .dns_overrides
            .insert("origin.test".into(), "127.0.0.1".into());
        engine.configure(settings).unwrap();
        let listener = engine.start().await.unwrap();
        let proxy = browser::proxy_for_listener(listener.address);
        let spki = engine.authority.spki_sha256_base64().unwrap();

        let settings = test_settings();
        let mut managed = Browser::launch(&settings, &proxy, &spki).unwrap();
        let devtools = devtools_url(&managed).await;
        let tab = cdp::pages(&devtools).await.unwrap()[0].target_id.clone();

        let secure = format!("https://origin.test:{https_port}");
        cdp::navigate(&devtools, &tab, &format!("{secure}/redirect"))
            .await
            .unwrap();
        let title = wait_for_title(&devtools, &tab, "Ferrite origin").await;
        assert_eq!(title, "Ferrite origin + js", "JavaScript must run");
        let href = cdp::evaluate(&devtools, &tab, "location.href")
            .await
            .unwrap();
        assert_eq!(href, format!("{secure}/page"), "redirect must be followed");

        cdp::navigate(&devtools, &tab, &format!("{secure}/echo"))
            .await
            .unwrap();
        wait_for_title(&devtools, &tab, "cookie:session=ferrite-e2e").await;

        // A second tab reaches a loopback HTTP origin through the proxy as well.
        let second = cdp::open(&devtools, &format!("http://127.0.0.1:{http_port}/plain"))
            .await
            .unwrap();
        wait_for_title(&devtools, &second, "plain:/plain").await;
        assert_eq!(cdp::pages(&devtools).await.unwrap().len(), 2);
        // IP-literal HTTPS targets need an IP subject alternative name.
        cdp::navigate(
            &devtools,
            &second,
            &format!("https://127.0.0.1:{https_port}/ip"),
        )
        .await
        .unwrap();
        wait_for_title(&devtools, &second, "plain:/ip").await;
        cdp::go(&devtools, &tab, -1).await.unwrap();
        wait_for_title(&devtools, &tab, "Ferrite origin").await;

        let flows = engine.project.lock().unwrap().list().unwrap();
        let find = |url: &str| {
            flows
                .iter()
                .find(|f| f.url == url && f.tool == "Proxy")
                .unwrap_or_else(|| {
                    panic!(
                        "{url} missing from history: {:#?}",
                        flows.iter().map(|f| &f.url).collect::<Vec<_>>()
                    )
                })
        };
        assert_eq!(find(&format!("{secure}/redirect")).status, 302);
        let page = find(&format!("{secure}/page"));
        assert_eq!(page.status, 200);
        assert!(page.error.is_none());
        let echo = Message::parse(&find(&format!("{secure}/echo")).request).unwrap();
        assert_eq!(echo.header("Cookie"), Some("session=ferrite-e2e"));
        assert_eq!(
            find(&format!("http://127.0.0.1:{http_port}/plain")).status,
            200
        );

        cdp::close_browser(&devtools).await.unwrap();
        managed.begin_close();
        assert!(
            managed.wait_timeout(Duration::from_secs(10)).is_some(),
            "browser must exit after Browser.close"
        );
        let profile = managed.profile_path().to_owned();
        drop(managed);
        assert!(!profile.exists(), "temporary profile must be deleted");

        // Negative control: pinning a different CA leaves Ferrite's
        // certificates untrusted, so trust is scoped to Ferrite's own CA.
        let other = Authority::from_key(&Authority::generate_key().unwrap()).unwrap();
        let mut untrusted =
            Browser::launch(&settings, &proxy, &other.spki_sha256_base64().unwrap()).unwrap();
        let devtools = devtools_url(&untrusted).await;
        let tab = cdp::pages(&devtools).await.unwrap()[0].target_id.clone();
        let error = cdp::navigate(&devtools, &tab, &format!("{secure}/page"))
            .await
            .expect_err("an unpinned CA must be rejected");
        assert!(
            format!("{error:#}").contains("ERR_CERT"),
            "unexpected navigation error: {error:#}"
        );
        untrusted.terminate();
        assert!(untrusted.wait_timeout(Duration::from_secs(10)).is_some());
        listener.stop().await;
    });
}
