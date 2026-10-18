//! The cloud remotes against small local stand-ins of the Dropbox and
//! Google Drive HTTP APIs (only what the remotes use), then a real folder
//! sync between two devices through each.

use super::*;
use crate::db::vault::{NewEntry, Vault};
use crate::sync::folder::{sync, FolderSyncOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).ok()?;
    let url = url::Url::parse(&format!("http://x{target}")).ok()?;
    Some(Request {
        method,
        path: url.path().to_string(),
        query: url.query_pairs().into_owned().collect(),
        headers,
        body,
    })
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// Serve `handler` on a free loopback port; returns the base URL.
fn serve<F>(handler: F) -> String
where
    F: Fn(Request) -> (u16, String, Vec<u8>) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handler = Arc::new(handler);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let handler = handler.clone();
            std::thread::spawn(move || {
                if let Some(req) = read_request(&mut stream) {
                    let (status, ct, body) = handler(req);
                    respond(&mut stream, status, &ct, &body);
                }
            });
        }
    });
    base
}

fn json_reply(status: u16, value: Value) -> (u16, String, Vec<u8>) {
    (
        status,
        "application/json".into(),
        value.to_string().into_bytes(),
    )
}

fn token() -> TokenSource {
    Box::new(|| Ok("test-token".to_string()))
}

// ── Dropbox stand-in: files by lower-cased path ─────────────────────────────

fn dropbox_server() -> String {
    let files: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
    serve(move |req| {
        if req.headers.get("authorization").map(String::as_str) != Some("Bearer test-token") {
            return json_reply(401, json!({"error": "invalid_access_token"}));
        }
        let mut files = files.lock().unwrap();
        let arg: Value = req
            .headers
            .get("dropbox-api-arg")
            .and_then(|a| serde_json::from_str(a).ok())
            .unwrap_or(Value::Null);
        match req.path.as_str() {
            "/2/files/list_folder" => {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                let dir = body["path"].as_str().unwrap().to_lowercase() + "/";
                let mut names: Vec<String> = files
                    .keys()
                    .filter_map(|p| p.strip_prefix(&dir))
                    .map(|rest| rest.split('/').next().unwrap().to_string())
                    .collect();
                names.sort();
                names.dedup();
                if names.is_empty() {
                    return json_reply(409, json!({"error_summary": "path/not_found/"}));
                }
                let entries: Vec<Value> = names.iter().map(|n| json!({"name": n})).collect();
                json_reply(
                    200,
                    json!({"entries": entries, "has_more": false, "cursor": "c"}),
                )
            }
            "/2/files/download" => {
                let path = arg["path"].as_str().unwrap().to_lowercase();
                match files.get(&path) {
                    Some(data) => (200, "application/octet-stream".into(), data.clone()),
                    None => json_reply(409, json!({"error_summary": "path/not_found/"})),
                }
            }
            "/2/files/upload" => {
                assert_eq!(arg["mode"], "overwrite");
                files.insert(arg["path"].as_str().unwrap().to_lowercase(), req.body);
                json_reply(200, json!({"name": "x"}))
            }
            "/2/users/get_current_account" => json_reply(200, json!({"email": "ana@example.com"})),
            other => json_reply(404, json!({"error": other})),
        }
    })
}

// ── Google Drive stand-in: files with ids and parents ───────────────────────

#[derive(Clone)]
struct DriveFile {
    name: String,
    parent: String,
    folder: bool,
    data: Vec<u8>,
}

/// `name = 'x' and 'p' in parents and trashed = false` or
/// `'p' in parents and trashed = false`.
fn parse_q(q: &str) -> (Option<String>, String) {
    let unquote = |s: &str| {
        s.trim()
            .trim_matches('\'')
            .replace("\\'", "'")
            .replace("\\\\", "\\")
    };
    let mut name = None;
    let mut parent = String::new();
    for clause in q.split(" and ") {
        if let Some(n) = clause.strip_prefix("name = ") {
            name = Some(unquote(n));
        } else if let Some(p) = clause.strip_suffix(" in parents") {
            parent = unquote(p);
        }
    }
    (name, parent)
}

fn drive_server() -> String {
    let files: Arc<Mutex<HashMap<String, DriveFile>>> = Arc::default();
    let next = Arc::new(Mutex::new(0u32));
    serve(move |req| {
        if req.headers.get("authorization").map(String::as_str) != Some("Bearer test-token") {
            return json_reply(401, json!({"error": "unauthorized"}));
        }
        let mut files = files.lock().unwrap();
        let new_id = || {
            let mut n = next.lock().unwrap();
            *n += 1;
            format!("id{n}")
        };
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/drive/v3/files") => {
                let (name, parent) = parse_q(&req.query["q"]);
                let found: Vec<Value> = files
                    .iter()
                    .filter(|(_, f)| {
                        f.parent == parent && name.as_ref().is_none_or(|n| *n == f.name)
                    })
                    .map(|(id, f)| json!({"id": id, "name": f.name}))
                    .collect();
                json_reply(200, json!({"files": found}))
            }
            ("POST", "/drive/v3/files") => {
                let meta: Value = serde_json::from_slice(&req.body).unwrap();
                assert_eq!(meta["mimeType"], FOLDER_MIME);
                let id = new_id();
                files.insert(
                    id.clone(),
                    DriveFile {
                        name: meta["name"].as_str().unwrap().into(),
                        parent: meta["parents"][0].as_str().unwrap().into(),
                        folder: true,
                        data: Vec::new(),
                    },
                );
                json_reply(200, json!({"id": id}))
            }
            ("POST", "/upload/drive/v3/files") => {
                assert_eq!(req.query["uploadType"], "multipart");
                let ct = &req.headers["content-type"];
                let boundary = ct.split("boundary=").nth(1).unwrap();
                let body = &req.body;
                let sep = format!("--{boundary}");
                let text = String::from_utf8_lossy(body);
                let meta_start = text.find("\r\n\r\n").unwrap() + 4;
                let meta_end = text[meta_start..].find("\r\n").unwrap() + meta_start;
                let meta: Value = serde_json::from_str(&text[meta_start..meta_end]).unwrap();
                // Content: after the second part's headers, up to the final
                // boundary (binary-safe, by byte positions).
                let second = find(body, sep.as_bytes(), meta_end).unwrap();
                let data_start = find(body, b"\r\n\r\n", second).unwrap() + 4;
                let data_end =
                    find(body, format!("\r\n--{boundary}--").as_bytes(), data_start).unwrap();
                let id = new_id();
                files.insert(
                    id.clone(),
                    DriveFile {
                        name: meta["name"].as_str().unwrap().into(),
                        parent: meta["parents"][0].as_str().unwrap().into(),
                        folder: false,
                        data: body[data_start..data_end].to_vec(),
                    },
                );
                json_reply(200, json!({"id": id}))
            }
            ("PATCH", path) if path.starts_with("/upload/drive/v3/files/") => {
                let id = path.rsplit('/').next().unwrap();
                files.get_mut(id).unwrap().data = req.body;
                json_reply(200, json!({"id": id}))
            }
            ("GET", path) if path.starts_with("/drive/v3/files/") => {
                let id = path.rsplit('/').next().unwrap();
                match files.get(id) {
                    Some(f) if !f.folder => {
                        (200, "application/octet-stream".into(), f.data.clone())
                    }
                    _ => json_reply(404, json!({"error": "notFound"})),
                }
            }
            ("GET", "/drive/v3/about") => {
                json_reply(200, json!({"user": {"emailAddress": "ana@example.com"}}))
            }
            other => json_reply(404, json!({"error": format!("{other:?}")})),
        }
    })
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

// ── The tests ───────────────────────────────────────────────────────────────

/// list/get/put basics, then two devices syncing through `remote()`.
fn exercise(remote: &dyn Fn() -> Box<dyn Remote>) {
    let r = remote();
    assert!(r.list("changes").unwrap().is_empty());
    assert_eq!(r.get("missing.bin").unwrap(), None);
    r.put("changes/dev a/0000000001.bin", b"one\x00\xff")
        .unwrap();
    r.put("changes/dev a/0000000001.bin", b"uno").unwrap();
    r.put("top.json", b"{}").unwrap();
    assert_eq!(r.list("changes").unwrap(), ["dev a"]);
    assert_eq!(r.list("changes/dev a").unwrap(), ["0000000001.bin"]);
    assert_eq!(
        r.get("changes/dev a/0000000001.bin").unwrap().unwrap(),
        b"uno"
    );
    // A fresh remote (another device) finds the same files.
    assert_eq!(remote().get("top.json").unwrap().unwrap(), b"{}");

    let dir = tempfile::tempdir().unwrap();
    let device = |name: &str| {
        let mut v = Vault::open(dir.path().join(format!("{name}.db"))).unwrap();
        v.set_master_password("correct horse battery").unwrap();
        v
    };
    let (phone, desk) = (device("phone"), device("desk"));
    phone
        .add(NewEntry {
            title: "Mail".into(),
            password: "p".into(),
            ..Default::default()
        })
        .unwrap();
    desk.add(NewEntry {
        title: "GitHub".into(),
        totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
        ..Default::default()
    })
    .unwrap();
    let master = Some("correct horse battery");
    let opts = FolderSyncOptions::default;
    // Each device its own remote object, as on two machines.
    let (phone_remote, desk_remote) = (remote(), remote());
    sync(&phone, phone_remote.as_ref(), master, opts()).unwrap();
    sync(&desk, desk_remote.as_ref(), master, opts()).unwrap();
    sync(&phone, phone_remote.as_ref(), None, opts()).unwrap();
    let titles = |v: &Vault| {
        let mut t: Vec<String> = v.list(None).unwrap().into_iter().map(|e| e.title).collect();
        t.sort();
        t
    };
    assert_eq!(titles(&phone), ["GitHub", "Mail"]);
    assert_eq!(titles(&desk), ["GitHub", "Mail"]);
}

#[test]
fn dropbox_folder_works_and_syncs() {
    let base = dropbox_server();
    let make = || -> Box<dyn Remote> {
        Box::new(DropboxFolder::with_endpoints(
            token(),
            "/AshyPass Sync",
            &base,
            &base,
        ))
    };
    assert_eq!(
        DropboxFolder::with_endpoints(token(), "/AshyPass Sync", &base, &base)
            .probe()
            .unwrap(),
        "ana@example.com"
    );
    exercise(&make);
    // A wrong token is a clear error.
    let bad = DropboxFolder::with_endpoints(Box::new(|| Ok("nope".into())), "/x", &base, &base);
    assert!(bad.put("a", b"x").unwrap_err().to_string().contains("401"));
}

#[test]
fn google_drive_folder_works_and_syncs() {
    let base = drive_server();
    let make = || -> Box<dyn Remote> {
        Box::new(DriveFolder::with_endpoints(token(), "AshyPass Sync", &base))
    };
    assert_eq!(
        DriveFolder::with_endpoints(token(), "AshyPass Sync", &base)
            .probe()
            .unwrap(),
        "ana@example.com"
    );
    exercise(&make);
}

#[test]
fn dropbox_arguments_escape_non_ascii() {
    let arg = DropboxFolder::arg(&json!({"path": "/Senhas/çã"}));
    assert!(arg.is_ascii());
    let back: Value = serde_json::from_str(&arg).unwrap();
    assert_eq!(back["path"], "/Senhas/çã");
}

#[test]
fn dropbox_sign_in_url_uses_pkce_without_redirect() {
    let auth = DropboxAuth::start("abc123");
    let url = auth.authorize_url();
    assert!(url.starts_with("https://www.dropbox.com/oauth2/authorize?"));
    for part in [
        "client_id=abc123",
        "code_challenge_method=S256",
        "token_access_type=offline",
    ] {
        assert!(url.contains(part), "{url}");
    }
    assert!(!url.contains("redirect_uri"));
    assert!(!url.contains(&auth.verifier));
    // Resumed later from the verifier alone: the same request.
    assert_eq!(
        DropboxAuth::resume("abc123", &auth.verifier).authorize_url(),
        url
    );
}
