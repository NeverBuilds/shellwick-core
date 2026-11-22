//! SFTP over its own SSH connection.
//!
//! The file browser deliberately does not share the terminal's connection: the
//! shell session reconnects on its own schedule and owns its handle, and a
//! long transfer should not be torn down (or hold up) a shell reconnect. The
//! connection goes through the same [`connect_once`] path, so host-key
//! verification (TOFU) and authentication behave exactly like the terminal.
//!
//! Transfers never leave half-written files behind: downloads go to
//! `<name>.shellwick-part` next to the target and are renamed when complete;
//! uploads go to a temporary remote name and replace the target at the end.
//!
//! Remote paths are SFTP paths: always `/`-separated, whatever the local OS.

use crate::{connect_once, disconnect_all, Conn, Error, HostConfig, Jump, JumpConn, Secrets, TofuHandler};
use russh::client::Handle;
use russh::Disconnect;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read/write chunk size for transfers; progress is reported once per chunk.
const CHUNK: usize = 64 * 1024;
/// Suffix for files that are still being transferred.
const PART_SUFFIX: &str = ".shellwick-part";
/// A dropped folder with more files than this is refused (dropping a whole
/// drive by accident shouldn't start a day-long upload).
pub const MAX_UPLOAD_FILES: usize = 10_000;

pub const NAME_EMPTY: &str = "Type a name.";
pub const NAME_BAD: &str = "Names can't contain “/” or control characters, or be “.” or “..”.";
pub const TOO_MANY_FILES: &str = "That folder has more than 10,000 files. Upload smaller folders, or an archive.";
pub const MODE_BAD: &str = "Permissions are three or four octal digits, like 644 or 0755.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Dir,
    File,
    Symlink,
    Other,
}

impl From<FileType> for EntryKind {
    fn from(t: FileType) -> Self {
        match t {
            FileType::Dir => EntryKind::Dir,
            FileType::File => EntryKind::File,
            FileType::Symlink => EntryKind::Symlink,
            FileType::Other => EntryKind::Other,
        }
    }
}

/// One row of a remote directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteEntry {
    pub name: String,
    /// Full remote path (`/`-separated).
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    /// Modification time, seconds since the Unix epoch.
    pub modified: Option<u64>,
    /// POSIX mode bits as reported by the server.
    pub permissions: Option<u32>,
}

/// Transfer progress, reported after every chunk (and once at the start).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Progress {
    pub done: u64,
    /// Total size when the source reported one.
    pub total: Option<u64>,
}

/// What [`SftpClient::put_dir`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DirUploaded {
    pub files: usize,
    pub bytes: u64,
    /// Links and special files left out.
    pub skipped: usize,
}

/// A local folder to upload: folders to create and files to send (paths
/// relative to the folder, `/`-separated, parents before children).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DirPlan {
    pub dirs: Vec<String>,
    pub files: Vec<(String, PathBuf, u64)>,
    pub bytes: u64,
    /// Symbolic links (and junctions), special files and names that aren't Unicode.
    pub skipped: usize,
}

/// Walks a local folder for [`SftpClient::put_dir`]. Links are never
/// followed (no loops, nothing from outside the folder).
pub fn plan_dir_upload(local: &Path) -> std::io::Result<DirPlan> {
    fn walk(dir: &Path, rel: &str, plan: &mut DirPlan) -> std::io::Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                plan.skipped += 1;
                continue;
            };
            let child = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            let kind = e.file_type()?;
            if kind.is_symlink() {
                plan.skipped += 1;
            } else if kind.is_dir() {
                plan.dirs.push(child.clone());
                walk(&e.path(), &child, plan)?;
            } else if kind.is_file() {
                let size = e.metadata()?.len();
                plan.bytes += size;
                plan.files.push((child, e.path(), size));
                if plan.files.len() > MAX_UPLOAD_FILES {
                    return Err(std::io::Error::other(TOO_MANY_FILES));
                }
            } else {
                plan.skipped += 1;
            }
        }
        Ok(())
    }
    let mut plan = DirPlan::default();
    walk(local, "", &mut plan)?;
    Ok(plan)
}

/// Why a name typed for a new or renamed entry is refused, if it is.
pub fn check_remote_name(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        Some(NAME_EMPTY)
    } else if name == "." || name == ".." || name.contains('/') || name.chars().any(char::is_control) {
        Some(NAME_BAD)
    } else {
        None
    }
}

fn not_found(e: &russh_sftp::client::error::Error) -> bool {
    matches!(e, russh_sftp::client::error::Error::Status(s) if s.status_code == russh_sftp::protocol::StatusCode::NoSuchFile)
}

/// Outcome of [`SftpClient::authorize_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Authorized {
    Added,
    /// The key was already listed; nothing was written.
    AlreadyThere,
}

fn permissions(mode: u32) -> russh_sftp::client::fs::Metadata {
    FileAttributes { permissions: Some(mode), ..FileAttributes::empty() }
}

/// An open SFTP session. Drop or [`SftpClient::close`] it when the panel closes.
pub struct SftpClient {
    sftp: SftpSession,
    ssh: Handle<TofuHandler>,
    home: String,
    fingerprint: String,
    /// The jump-host connections `ssh` runs over (connection order).
    jumps: Vec<JumpConn>,
}

impl SftpClient {
    /// Connects, authenticates and starts the `sftp` subsystem.
    ///
    /// Fails with [`Error::HostKeyMismatch`] when the server key differs from
    /// `cfg.host_key_fingerprint`. When the host has no recorded fingerprint
    /// yet, the caller should persist [`SftpClient::fingerprint`] (TOFU).
    pub async fn connect(cfg: &HostConfig, secrets: &Secrets) -> Result<Self, Error> {
        Self::connect_via(cfg, secrets, &[]).await
    }

    /// Like [`SftpClient::connect`], through jump hosts (connection order;
    /// may be empty). Their keys are checked like the server's; persist
    /// [`SftpClient::jump_fingerprints`] for those that had none recorded.
    pub async fn connect_via(cfg: &HostConfig, secrets: &Secrets, jumps: &[Jump]) -> Result<Self, Error> {
        Self::connect_with_prompts(cfg, secrets, jumps, &crate::prompt::never_ask()).await
    }

    /// Like [`SftpClient::connect_via`]; sign-in questions (two-factor codes…)
    /// go to `ask` (the Files panel shows them like the terminal does).
    pub async fn connect_with_prompts(cfg: &HostConfig, secrets: &Secrets, jumps: &[Jump], ask: &crate::prompt::Ask) -> Result<Self, Error> {
        let Conn { handle: ssh, fingerprint, jumps } = connect_once(cfg, secrets, jumps, ask).await?;
        let started = async {
            let channel = ssh.channel_open_session().await?;
            channel.request_subsystem(true, "sftp").await?;
            let sftp = SftpSession::new(channel.into_stream()).await?;
            let home = sftp.canonicalize(".").await?;
            Ok::<_, Error>((sftp, home))
        }
        .await;
        match started {
            Ok((sftp, home)) => Ok(Self { sftp, ssh, home, fingerprint, jumps }),
            Err(e) => {
                let _ = ssh.disconnect(Disconnect::ByApplication, "", "en").await;
                disconnect_all(&jumps).await;
                Err(e)
            }
        }
    }

    /// The login directory, as an absolute remote path.
    pub fn home(&self) -> &str {
        &self.home
    }

    /// SHA-256 fingerprint of the server key this session verified.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// (host id, SHA-256 fingerprint) of each jump host this session went through.
    pub fn jump_fingerprints(&self) -> Vec<(&str, &str)> {
        self.jumps.iter().map(|j| (j.host_id.as_str(), j.fingerprint.as_str())).collect()
    }

    /// Lists `dir`: directories first, then by name (case-insensitive).
    /// `.` and `..` are left out.
    pub async fn list(&self, dir: &str) -> Result<Vec<RemoteEntry>, Error> {
        let entries = self
            .sftp
            .read_dir(dir)
            .await?
            .filter(|e| !matches!(e.file_name().as_str(), "." | ".."))
            .map(|e| {
                let meta = e.metadata();
                let name = e.file_name();
                RemoteEntry {
                    path: join_remote(dir, &name),
                    name,
                    kind: meta.file_type().into(),
                    size: meta.size.unwrap_or(0),
                    modified: meta.mtime.map(u64::from),
                    permissions: meta.permissions,
                }
            })
            .collect();
        Ok(sort_entries(entries))
    }

    /// True when `path` is a directory (does not follow symlinks).
    pub async fn is_dir(&self, path: &str) -> Result<bool, Error> {
        Ok(self.sftp.symlink_metadata(path).await?.file_type() == FileType::Dir)
    }

    /// Downloads a remote directory recursively into `local_dest` (which is
    /// created). Symlinks are skipped (never followed), and every segment is
    /// sanitized with [`safe_local_name`] so nothing can escape `local_dest`.
    pub async fn get_dir(
        &self,
        remote_dir: &str,
        local_dest: &Path,
        mut on_progress: impl FnMut(Progress) -> bool,
    ) -> Result<u64, Error> {
        let mut stack = vec![(remote_dir.to_string(), local_dest.to_path_buf())];
        let mut dirs = vec![local_dest.to_path_buf()];
        let mut files: Vec<(String, PathBuf, u64)> = Vec::new();
        let mut total_bytes: u64 = 0;

        while let Some((rdir, ldir)) = stack.pop() {
            for entry in self.sftp.read_dir(&rdir).await? {
                let name = entry.file_name();
                if matches!(name.as_str(), "." | "..") {
                    continue;
                }
                let safe = safe_local_name(&name);
                let rpath = join_remote(&rdir, &name);
                let lpath = ldir.join(&safe);
                match entry.file_type() {
                    FileType::Dir => {
                        dirs.push(lpath.clone());
                        stack.push((rpath, lpath));
                    }
                    FileType::File => {
                        let size = entry.metadata().size.unwrap_or(0);
                        total_bytes = total_bytes.saturating_add(size);
                        files.push((rpath, lpath, size));
                        if files.len() > MAX_UPLOAD_FILES {
                            return Err(Error::Remote(TOO_MANY_FILES.into()));
                        }
                    }
                    _ => {} // skip symlinks and special files
                }
            }
        }

        for dir in &dirs {
            tokio::fs::create_dir_all(dir).await?;
        }
        if !on_progress(Progress { done: 0, total: Some(total_bytes) }) {
            return Err(Error::Cancelled);
        }

        let mut done_before: u64 = 0;
        for (rpath, lpath, _) in files {
            let n = self
                .get(&rpath, &lpath, |p| on_progress(Progress { done: done_before + p.done, total: Some(total_bytes) }))
                .await?;
            done_before += n;
        }
        Ok(done_before)
    }

    /// Downloads `remote` to `local`, replacing `local` only once the whole
    /// file has arrived. Return `false` from `on_progress` to cancel; the
    /// partial file is removed and [`Error::Cancelled`] is returned.
    pub async fn get(
        &self,
        remote: &str,
        local: &Path,
        mut on_progress: impl FnMut(Progress) -> bool,
    ) -> Result<u64, Error> {
        let mut src = self.sftp.open(remote).await?;
        let total = src.metadata().await.ok().and_then(|m| m.size);
        let part = part_path(local);

        let result = async {
            let mut dst = tokio::fs::File::create(&part).await?;
            let n = copy_with_progress(&mut src, &mut dst, total, &mut on_progress).await?;
            dst.sync_all().await?;
            drop(dst);
            tokio::fs::rename(&part, local).await?;
            Ok(n)
        }
        .await;

        let _ = src.shutdown().await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&part).await;
        }
        result
    }

    /// Uploads `local` to `remote`. An existing remote file is replaced only
    /// after the upload completed; a failed or cancelled upload leaves it
    /// untouched and removes the temporary remote file.
    pub async fn put(
        &self,
        local: &Path,
        remote: &str,
        mut on_progress: impl FnMut(Progress) -> bool,
    ) -> Result<u64, Error> {
        let mut src = tokio::fs::File::open(local).await?;
        let meta = src.metadata().await?;
        if !meta.is_file() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "only regular files can be uploaded",
            )));
        }
        let total = Some(meta.len());
        let tmp = format!("{remote}{PART_SUFFIX}");
        // A replaced file keeps its permissions (an edited script stays executable).
        let old_mode = match self.sftp.metadata(remote).await {
            Ok(m) => m.permissions.map(|p| p & 0o7777),
            Err(e) if not_found(&e) => None,
            Err(e) => return Err(e.into()),
        };

        let result = async {
            let mut dst = self.sftp.create(tmp.as_str()).await?;
            let copied = copy_with_progress(&mut src, &mut dst, total, &mut on_progress).await;
            // Close the remote handle before renaming, even on failure.
            let closed = dst.shutdown().await;
            let n = copied?;
            closed?;
            // SFTP v3 rename refuses to overwrite, so replace in two steps.
            if self.sftp.try_exists(remote).await? {
                self.sftp.remove_file(remote).await?;
            }
            self.sftp.rename(tmp.as_str(), remote).await?;
            if let Some(mode) = old_mode {
                let _ = self.sftp.set_metadata(remote, permissions(mode)).await;
            }
            Ok(n)
        }
        .await;

        if result.is_err() {
            let _ = self.sftp.remove_file(tmp.as_str()).await;
        }
        result
    }

    /// Creates one directory (parents must exist).
    pub async fn mkdir(&self, path: &str) -> Result<(), Error> {
        Ok(self.sftp.create_dir(path).await?)
    }

    /// The entry at `path` (a link itself, not its target), or `None` when
    /// nothing is there.
    pub async fn entry(&self, path: &str) -> Result<Option<RemoteEntry>, Error> {
        match self.sftp.symlink_metadata(path).await {
            Ok(meta) => Ok(Some(RemoteEntry {
                name: path.rsplit('/').next().unwrap_or(path).to_string(),
                path: path.to_string(),
                kind: meta.file_type().into(),
                size: meta.size.unwrap_or(0),
                modified: meta.mtime.map(u64::from),
                permissions: meta.permissions,
            })),
            Err(e) if not_found(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Renames `path` within its folder and returns the new path. Never
    /// replaces an entry that is already there (a case-only change is fine).
    pub async fn rename(&self, path: &str, new_name: &str) -> Result<String, Error> {
        if let Some(why) = check_remote_name(new_name) {
            return Err(Error::Remote(why.into()));
        }
        let to = join_remote(&remote_parent(path), new_name);
        if to == path {
            return Ok(to);
        }
        if to.to_lowercase() != path.to_lowercase() && self.entry(&to).await?.is_some() {
            return Err(Error::Remote(format!("“{new_name}” is already in this folder.")));
        }
        self.sftp.rename(path, to.as_str()).await?;
        Ok(to)
    }

    /// Sets the permission bits of `path` (`mode` ≤ 0o7777; not recursive).
    pub async fn chmod(&self, path: &str, mode: u32) -> Result<(), Error> {
        if mode > 0o7777 {
            return Err(Error::Remote(MODE_BAD.into()));
        }
        Ok(self.sftp.set_metadata(path, permissions(mode)).await?)
    }

    /// Uploads the local folder `local` into `remote_dir` (as
    /// `remote_dir/<its name>`), with everything in it. When a folder of that
    /// name is already there, fails with [`Error::FolderExists`] unless
    /// `merge`: then files of the same name are replaced and the rest kept.
    /// Each file is replaced only once it has fully arrived; a cancelled
    /// upload keeps the files already sent. Progress counts all the bytes.
    pub async fn put_dir(
        &self,
        local: &Path,
        remote_dir: &str,
        merge: bool,
        mut on_progress: impl FnMut(Progress) -> bool,
    ) -> Result<DirUploaded, Error> {
        let name = local
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::Remote("The folder name is not valid Unicode.".into()))?
            .to_string();
        let target = join_remote(remote_dir, &name);
        match self.entry(&target).await? {
            Some(e) if e.kind == EntryKind::Dir && !merge => return Err(Error::FolderExists(name)),
            Some(e) if e.kind != EntryKind::Dir => {
                return Err(Error::Remote(format!("A file named “{name}” is already here.")));
            }
            Some(_) => {}
            None => self.sftp.create_dir(target.as_str()).await?,
        }
        let dir = local.to_path_buf();
        let plan = tokio::task::spawn_blocking(move || plan_dir_upload(&dir))
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        let total = Some(plan.bytes);
        for rel in &plan.dirs {
            let path = join_remote(&target, rel);
            match self.entry(&path).await? {
                Some(e) if e.kind == EntryKind::Dir => {}
                Some(_) => return Err(Error::Remote(format!("A file named “{rel}” is in the way."))),
                None => self.sftp.create_dir(path.as_str()).await?,
            }
        }
        if !on_progress(Progress { done: 0, total }) {
            return Err(Error::Cancelled);
        }
        let mut sent = 0u64;
        for (rel, path, _) in &plan.files {
            let base = sent;
            sent += self.put(path, &join_remote(&target, rel), |p| on_progress(Progress { done: base + p.done, total })).await?;
        }
        Ok(DirUploaded { files: plan.files.len(), bytes: sent, skipped: plan.skipped })
    }

    /// Adds `public_line` to `~/.ssh/authorized_keys` (like `ssh-copy-id`):
    /// creates `~/.ssh` (0700) and the file (0600) when missing, and only ever
    /// appends, so a failure can't truncate the keys already there.
    pub async fn authorize_key(&self, public_line: &str) -> Result<Authorized, Error> {
        let blob = crate::keygen::key_blob(public_line)?;
        let dir = join_remote(&self.home, ".ssh");
        if self.sftp.metadata(dir.clone()).await.is_err() {
            self.sftp.create_dir(dir.clone()).await?;
            let _ = self.sftp.set_metadata(dir.clone(), permissions(0o700)).await;
        }
        let path = join_remote(&dir, "authorized_keys");
        let existing = match self.sftp.read(path.clone()).await {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) if !self.sftp.try_exists(path.clone()).await.unwrap_or(true) => None,
            Err(e) => return Err(e.into()),
        };
        if existing.as_deref().is_some_and(|text| crate::keygen::authorized_keys_contains(text, &blob)) {
            return Ok(Authorized::AlreadyThere);
        }
        let addition = crate::keygen::authorized_keys_append(existing.as_deref().unwrap_or(""), public_line);
        let flags = OpenFlags::WRITE | OpenFlags::APPEND | OpenFlags::CREATE;
        let mut f = self.sftp.open_with_flags(path.clone(), flags).await?;
        f.write_all(addition.as_bytes()).await?;
        f.shutdown().await?;
        if existing.is_none() {
            let _ = self.sftp.set_metadata(path, permissions(0o600)).await;
        }
        Ok(Authorized::Added)
    }

    /// Removes a file, a symlink (not its target), or a directory (including
    /// non-empty subdirectories, iteratively without following symlinks).
    /// Refuses the root directory `/` as a safety guard.
    pub async fn rm(&self, path: &str) -> Result<(), Error> {
        let clean = path.trim_end_matches('/');
        if clean.is_empty() {
            return Err(Error::Remote("Refusing to remove the root folder.".into()));
        }
        let meta = self.sftp.symlink_metadata(path).await?;
        if meta.file_type() != FileType::Dir {
            self.sftp.remove_file(path).await?;
            return Ok(());
        }
        // Iterative post-order traversal: collect directories to remove deepest-first,
        // deleting regular files and symlinks as we go (never following symlinks).
        let mut stack = vec![clean.to_string()];
        let mut dirs = Vec::new();
        let mut visited: usize = 0;
        while let Some(dir) = stack.pop() {
            dirs.push(dir.clone());
            for entry in self.sftp.read_dir(&dir).await? {
                let name = entry.file_name();
                if matches!(name.as_str(), "." | "..") {
                    continue;
                }
                visited += 1;
                if visited > MAX_UPLOAD_FILES {
                    return Err(Error::Remote("That folder has too many items to delete from the Files panel. Delete it from the terminal instead.".into()));
                }
                let child = join_remote(&dir, &name);
                if entry.file_type() == FileType::Dir {
                    stack.push(child);
                } else {
                    self.sftp.remove_file(&child).await?;
                }
            }
        }
        for dir in dirs.into_iter().rev() {
            self.sftp.remove_dir(&dir).await?;
        }
        Ok(())
    }

    /// Ends the SFTP subsystem and the SSH connection. Takes `&self` so a
    /// session shared between concurrent transfers can still be closed.
    pub async fn close(&self) {
        let _ = self.sftp.close().await;
        let _ = self.ssh.disconnect(Disconnect::ByApplication, "", "en").await;
        disconnect_all(&self.jumps).await;
    }
}

/// Joins a remote directory and an entry name with `/`.
pub fn join_remote(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Parent of a remote path; the root is its own parent.
pub fn remote_parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) | None if path.starts_with('/') => "/".to_string(),
        Some(i) => trimmed[..i].to_string(),
        None => ".".to_string(),
    }
}

/// Turns a remote file name into one that is safe to create locally.
///
/// Remote names come from the server and may contain characters that are
/// path separators or illegal on Windows (`a\..\x`, `CON`, `name.`). Every
/// such character becomes `_`, so the result is always a single path
/// component inside the destination directory.
pub fn safe_local_name(remote_name: &str) -> String {
    let mut name: String = remote_name
        .chars()
        .map(|c| if c.is_control() || r#"<>:"/\|?*"#.contains(c) { '_' } else { c })
        .collect();
    // Windows silently drops trailing dots and spaces.
    let trimmed = name.trim_end_matches(['.', ' ']).len();
    name.truncate(trimmed);
    if name.is_empty() {
        return "download".to_string();
    }
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        name.insert(0, '_');
    }
    name
}

/// `dir/name`, or `dir/name (1).ext`, `dir/name (2).ext`… — the first one for
/// which `exists` is false. Downloads never overwrite an existing file.
pub fn unique_local_path(dir: &Path, name: &str, exists: impl Fn(&Path) -> bool) -> PathBuf {
    let first = dir.join(name);
    if !exists(&first) {
        return first;
    }
    let as_path = Path::new(name);
    let stem = as_path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = as_path.extension().and_then(|e| e.to_str());
    (1..)
        .map(|i| match ext {
            Some(ext) => dir.join(format!("{stem} ({i}).{ext}")),
            None => dir.join(format!("{stem} ({i})")),
        })
        .find(|p| !exists(p))
        .expect("an unused name exists")
}

fn sort_entries(mut entries: Vec<RemoteEntry>) -> Vec<RemoteEntry> {
    entries.sort_by(|a, b| {
        let a_dir = a.kind == EntryKind::Dir;
        let b_dir = b.kind == EntryKind::Dir;
        b_dir
            .cmp(&a_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.name.cmp(&b.name))
    });
    entries
}

fn part_path(local: &Path) -> PathBuf {
    let mut name = local.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(PART_SUFFIX);
    local.with_file_name(name)
}

async fn copy_with_progress<R, W>(
    src: &mut R,
    dst: &mut W,
    total: Option<u64>,
    on_progress: &mut impl FnMut(Progress) -> bool,
) -> Result<u64, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    if !on_progress(Progress { done, total }) {
        return Err(Error::Cancelled);
    }
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
        done += n as u64;
        if !on_progress(Progress { done, total }) {
            return Err(Error::Cancelled);
        }
    }
    dst.flush().await?;
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, kind: EntryKind) -> RemoteEntry {
        RemoteEntry {
            name: name.into(),
            path: join_remote("/srv", name),
            kind,
            size: 0,
            modified: None,
            permissions: None,
        }
    }

    #[test]
    fn join_uses_forward_slashes() {
        assert_eq!(join_remote("/home/me", "a.txt"), "/home/me/a.txt");
        assert_eq!(join_remote("/", "etc"), "/etc");
        assert_eq!(join_remote("/C:/Users/me/", "x"), "/C:/Users/me/x");
        assert_eq!(join_remote("", "rel"), "rel");
    }

    #[test]
    fn parent_walks_up_and_stops_at_root() {
        assert_eq!(remote_parent("/home/me/logs"), "/home/me");
        assert_eq!(remote_parent("/home/me/"), "/home");
        assert_eq!(remote_parent("/home"), "/");
        assert_eq!(remote_parent("/"), "/");
        assert_eq!(remote_parent("/C:/Users"), "/C:");
        assert_eq!(remote_parent("docs/a"), "docs");
        assert_eq!(remote_parent("docs"), ".");
    }

    #[test]
    fn listing_sorts_dirs_first_then_name_case_insensitive() {
        let sorted = sort_entries(vec![
            entry("zeta.log", EntryKind::File),
            entry("Beta", EntryKind::Dir),
            entry("alpha.txt", EntryKind::File),
            entry("alpha", EntryKind::Dir),
            entry("link", EntryKind::Symlink),
        ]);
        let names: Vec<_> = sorted.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["alpha", "Beta", "alpha.txt", "link", "zeta.log"]);
    }

    #[test]
    fn file_type_maps_to_entry_kind() {
        assert_eq!(EntryKind::from(FileType::Dir), EntryKind::Dir);
        assert_eq!(EntryKind::from(FileType::File), EntryKind::File);
        assert_eq!(EntryKind::from(FileType::Symlink), EntryKind::Symlink);
        assert_eq!(EntryKind::from(FileType::Other), EntryKind::Other);
    }

    #[test]
    fn part_file_sits_next_to_target() {
        let p = part_path(Path::new("downloads/report.pdf"));
        assert_eq!(p, Path::new("downloads/report.pdf.shellwick-part"));
    }

    #[test]
    fn remote_names_cannot_escape_the_download_dir() {
        assert_eq!(safe_local_name(r"..\..\evil.exe"), ".._.._evil.exe");
        assert_eq!(safe_local_name("a/b"), "a_b");
        assert_eq!(safe_local_name("..."), "download");
        assert_eq!(safe_local_name(".."), "download");
        assert_eq!(safe_local_name(""), "download");
        assert_eq!(safe_local_name("what?.txt"), "what_.txt");
        assert_eq!(safe_local_name("tab\there"), "tab_here");
        assert_eq!(safe_local_name("report. "), "report");
    }

    #[test]
    fn windows_reserved_names_are_prefixed() {
        assert_eq!(safe_local_name("CON"), "_CON");
        assert_eq!(safe_local_name("nul.txt"), "_nul.txt");
        assert_eq!(safe_local_name("com1.log"), "_com1.log");
        assert_eq!(safe_local_name("LPT9"), "_LPT9");
        assert_eq!(safe_local_name("console.log"), "console.log");
        assert_eq!(safe_local_name("COM10"), "COM10");
        assert_eq!(safe_local_name(".bashrc"), ".bashrc");
    }

    #[test]
    fn downloads_never_overwrite() {
        let dir = Path::new("dl");
        let taken = [dir.join("report.pdf"), dir.join("report (1).pdf"), dir.join(".env")];
        let exists = |p: &Path| taken.iter().any(|t| t == p);
        assert_eq!(unique_local_path(dir, "new.txt", exists), dir.join("new.txt"));
        assert_eq!(unique_local_path(dir, "report.pdf", exists), dir.join("report (2).pdf"));
        assert_eq!(unique_local_path(dir, ".env", exists), dir.join(".env (1)"));
    }

    #[test]
    fn names_are_checked() {
        assert_eq!(check_remote_name(""), Some(NAME_EMPTY));
        assert_eq!(check_remote_name("."), Some(NAME_BAD));
        assert_eq!(check_remote_name(".."), Some(NAME_BAD));
        assert_eq!(check_remote_name("a/b"), Some(NAME_BAD));
        assert_eq!(check_remote_name("tab\there"), Some(NAME_BAD));
        assert_eq!(check_remote_name(".env"), None);
        assert_eq!(check_remote_name("my notes (v2).txt"), None);
        assert_eq!(check_remote_name("a\\b"), None);
    }

    #[test]
    fn entry_serializes_kind_as_snake_case() {
        let json = serde_json::to_string(&entry("a", EntryKind::Dir)).unwrap();
        assert!(json.contains("\"kind\":\"dir\""), "{json}");
    }

    #[tokio::test]
    async fn copy_reports_progress_per_chunk() {
        let data = vec![7u8; CHUNK * 2 + 10];
        let mut src: &[u8] = &data;
        let mut dst = Vec::new();
        let mut seen = Vec::new();
        let n = copy_with_progress(&mut src, &mut dst, Some(data.len() as u64), &mut |p| {
            seen.push(p.done);
            true
        })
        .await
        .unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(dst, data);
        assert_eq!(seen.first(), Some(&0));
        assert_eq!(seen.last(), Some(&(data.len() as u64)));
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
    }

    #[tokio::test]
    async fn copy_stops_when_cancelled() {
        let data = vec![1u8; CHUNK * 4];
        let mut src: &[u8] = &data;
        let mut dst = Vec::new();
        let err = copy_with_progress(&mut src, &mut dst, None, &mut |p| p.done < CHUNK as u64)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Cancelled));
        assert!(dst.len() < data.len());
    }

    #[tokio::test]
    async fn copy_can_be_cancelled_before_any_bytes() {
        let mut src: &[u8] = b"secret-free payload";
        let mut dst = Vec::new();
        let err = copy_with_progress(&mut src, &mut dst, None, &mut |_| false).await.unwrap_err();
        assert!(matches!(err, Error::Cancelled));
        assert!(dst.is_empty());
    }
}
