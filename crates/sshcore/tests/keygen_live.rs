//! Generate a key, add it to a real server's ~/.ssh/authorized_keys over SFTP,
//! then try signing in with it. Ignored by default:
//!
//!   SHELLWICK_TEST_SSH=user@host[:port] SHELLWICK_TEST_KEY=~/.ssh/test_key \
//!     cargo test -p sshcore --test keygen_live -- --ignored --nocapture
//!
//! The server's authorized_keys is put back exactly as it was afterwards
//! (deleted again if it didn't exist). Windows OpenSSH ignores that file for
//! administrators (they use C:\ProgramData\ssh\administrators_authorized_keys),
//! so there the sign-in check is expected to be refused.

use sshcore::keygen::generate_ed25519;
use sshcore::sftp::{join_remote, Authorized, SftpClient};
use sshcore::{check_sign_in, AuthMethod, Error, HostConfig, Secrets};

fn host(auth: AuthMethod) -> HostConfig {
    let target = std::env::var("SHELLWICK_TEST_SSH").expect("set SHELLWICK_TEST_SSH=user@host[:port]");
    let (user, rest) = target.split_once('@').expect("user@host[:port]");
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("port")),
        None => (rest.to_string(), 22),
    };
    HostConfig {
        id: "keygen-live".into(),
        name: "keygen-live".into(),
        host,
        port,
        user: user.into(),
        auth,
        host_key_fingerprint: None,
        startup_command: None,
        tags: vec![],
        environment: None,
        folder: None,
        forwards: vec![],
        jump_host: None,
        confirm_new_key: false,
        session_log: false,
        terminal_theme: None,
        proxy: None,
        forward_agent: false,
        keepalive_secs: None,
        legacy_algorithms: false,
    }
}

#[tokio::test]
#[ignore = "needs a live SSH server; see module docs"]
async fn generate_add_and_check() {
    let test_key = std::env::var("SHELLWICK_TEST_KEY").expect("set SHELLWICK_TEST_KEY=<private key path>");
    let dir = std::env::temp_dir().join(format!("shellwick-keygen-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = generate_ed25519(&dir, "id_new", "keygen-live", Some("pass phrase")).expect("generate");

    let sftp = SftpClient::connect(&host(AuthMethod::KeyFile { path: test_key }), &Secrets::default()).await.expect("SFTP with the test key");
    let path = join_remote(&join_remote(sftp.home(), ".ssh"), "authorized_keys");
    let backup = dir.join("authorized_keys.before");
    let existed = sftp.get(&path, &backup, |_| true).await.is_ok();

    let first = sftp.authorize_key(&key.public_line).await;
    let second = sftp.authorize_key(&key.public_line).await;

    // Try the new key (encrypted: needs its passphrase) before restoring.
    let new_key_host = host(AuthMethod::KeyFile { path: key.private_path.to_string_lossy().into_owned() });
    let secrets = Secrets { password: None, key_passphrase: Some("pass phrase".into()), proxy_password: None };
    let accepted = check_sign_in(&new_key_host, &secrets, &[]).await;

    // Put authorized_keys back as it was.
    if existed {
        sftp.put(&backup, &path, |_| true).await.expect("restore authorized_keys");
    } else {
        sftp.rm(&path).await.expect("remove the authorized_keys we created");
    }
    sftp.close().await;
    std::fs::remove_dir_all(&dir).unwrap();

    assert_eq!(first.expect("first add"), Authorized::Added);
    assert_eq!(second.expect("second add"), Authorized::AlreadyThere, "adding twice must not duplicate the line");
    match accepted {
        Ok(()) => eprintln!("the server accepts the new key"),
        Err(e @ Error::AuthFailed(_)) => eprintln!("added, but the server doesn't accept it here: {e}"),
        Err(e) => panic!("sign-in check failed for another reason: {e}"),
    }
}
