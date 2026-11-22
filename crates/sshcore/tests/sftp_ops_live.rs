//! File operations end to end against an SFTP server running inside the test
//! (russh's server side, serving a temporary folder): rename, permissions,
//! replacing a file keeps its permissions, folder upload with and without
//! merging, and the folder plan. Runs by default (no external server needed).

#[path = "support/dir_sftp.rs"]
mod dir_sftp;

#[path = "support/files_server.rs"]
mod files_server;

use files_server::HOME;
use sshcore::sftp::{plan_dir_upload, EntryKind, SftpClient, NAME_BAD};
use sshcore::Error;
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("sftp-ops-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Starts a server over `root` and connects to it.
async fn connect(root: PathBuf) -> SftpClient {
    let port = files_server::start(root).await;
    SftpClient::connect(&files_server::host("127.0.0.1", port), &files_server::secrets()).await.expect("connects")
}

fn names(list: &[sshcore::sftp::RemoteEntry]) -> Vec<&str> {
    list.iter().map(|e| e.name.as_str()).collect()
}

#[tokio::test]
async fn rename_and_permissions() {
    let root = scratch("rename");
    let c = connect(root.clone()).await;
    assert_eq!(c.home(), HOME);
    let local = root.join("hello.sh");
    std::fs::write(&local, b"echo hi\n").unwrap();
    let remote = format!("{HOME}/hello.sh");
    c.put(&local, &remote, |_| true).await.unwrap();
    c.mkdir(&format!("{HOME}/bin")).await.unwrap();

    // Refused names and clashes never reach the server.
    assert!(matches!(c.rename(&remote, "a/b").await, Err(Error::Remote(m)) if m == NAME_BAD));
    let clash = c.rename(&remote, "bin").await.unwrap_err();
    assert_eq!(clash.to_string(), "“bin” is already in this folder.");

    let renamed = c.rename(&remote, "deploy.sh").await.unwrap();
    assert_eq!(renamed, format!("{HOME}/deploy.sh"));
    assert_eq!(names(&c.list(HOME).await.unwrap()), ["bin", "deploy.sh"]);
    // A case-only change is fine (the same entry).
    let cased = c.rename(&renamed, "Deploy.sh").await.unwrap();
    assert_eq!(names(&c.list(HOME).await.unwrap()), ["bin", "Deploy.sh"]);

    c.chmod(&cased, 0o755).await.unwrap();
    let e = c.entry(&cased).await.unwrap().unwrap();
    assert_eq!(e.permissions.map(|p| p & 0o7777), Some(0o755));
    assert!(c.chmod(&cased, 0o17777).await.is_err());

    // Replacing the file (an editor saving it) keeps its permissions.
    std::fs::write(&local, b"echo changed\n").unwrap();
    c.put(&local, &cased, |_| true).await.unwrap();
    let e = c.entry(&cased).await.unwrap().unwrap();
    assert_eq!(e.permissions.map(|p| p & 0o7777), Some(0o755));
    assert_eq!(e.size, 13);
    assert!(c.entry(&format!("{HOME}/nothing-here")).await.unwrap().is_none());
    c.close().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn folder_upload_asks_before_merging() {
    let root = scratch("folder");
    let src = root.join("local").join("site");
    std::fs::create_dir_all(src.join("css/vendor")).unwrap();
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::write(src.join("index.html"), b"<p>hi</p>").unwrap();
    std::fs::write(src.join("css/app.css"), b"body{}").unwrap();
    std::fs::write(src.join("css/vendor/x.css"), b"").unwrap();

    let plan = plan_dir_upload(&src).unwrap();
    assert_eq!(plan.dirs, ["css", "css/vendor", "empty"]);
    let files: Vec<_> = plan.files.iter().map(|(rel, _, size)| (rel.as_str(), *size)).collect();
    assert_eq!(files, [("css/app.css", 6), ("css/vendor/x.css", 0), ("index.html", 9)]);
    assert_eq!((plan.bytes, plan.skipped), (15, 0));

    let c = connect(root.join("server")).await;
    let mut last = None;
    let done = c.put_dir(&src, HOME, false, |p| {
        last = Some(p);
        true
    })
    .await
    .unwrap();
    assert_eq!((done.files, done.bytes, done.skipped), (3, 15, 0));
    assert_eq!(last.map(|p| (p.done, p.total)), Some((15, Some(15))));
    let site = format!("{HOME}/site");
    assert_eq!(names(&c.list(&site).await.unwrap()), ["css", "empty", "index.html"]);
    assert_eq!(names(&c.list(&format!("{site}/css/vendor")).await.unwrap()), ["x.css"]);

    // Again: the folder is there, so nothing happens until the caller says merge.
    std::fs::write(src.join("index.html"), b"<p>new</p>").unwrap();
    let again = c.put_dir(&src, HOME, false, |_| true).await.unwrap_err();
    assert!(matches!(&again, Error::FolderExists(n) if n == "site"));
    assert_eq!(again.to_string(), "A folder named “site” is already here.");
    c.mkdir(&format!("{site}/theirs")).await.unwrap();
    c.put_dir(&src, HOME, true, |_| true).await.unwrap();
    let listing = c.list(&site).await.unwrap();
    assert_eq!(names(&listing), ["css", "empty", "theirs", "index.html"]);
    assert_eq!(listing.iter().find(|e| e.name == "index.html").unwrap().size, 10);
    assert!(listing.iter().all(|e| !e.name.ends_with(".shellwick-part")));

    // A file of the folder's name is in the way: refused, never replaced.
    let file_src = root.join("local").join("notes");
    std::fs::create_dir_all(&file_src).unwrap();
    let dummy = root.join("local").join("dummy");
    std::fs::write(&dummy, b"x").unwrap();
    c.put(&dummy, &format!("{HOME}/notes"), |_| true).await.unwrap();
    let blocked = c.put_dir(&file_src, HOME, true, |_| true).await.unwrap_err();
    assert_eq!(blocked.to_string(), "A file named “notes” is already here.");
    assert_eq!(c.entry(&format!("{HOME}/notes")).await.unwrap().unwrap().kind, EntryKind::File);

    // Cancelling stops between files (nothing half-written is left).
    let big = root.join("local").join("big");
    std::fs::create_dir_all(&big).unwrap();
    for i in 0..3 {
        std::fs::write(big.join(format!("f{i}.bin")), vec![7u8; 200_000]).unwrap();
    }
    let err = c.put_dir(&big, HOME, false, |p| p.done < 250_000).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    let left = c.list(&format!("{HOME}/big")).await.unwrap();
    assert!(left.iter().all(|e| !e.name.ends_with(".shellwick-part")), "{:?}", names(&left));
    assert!(left.len() < 3);
    c.close().await;
    let _ = std::fs::remove_dir_all(&root);
}
