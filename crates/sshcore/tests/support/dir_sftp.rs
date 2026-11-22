//! A read-write SFTP server over a local folder, for tests and the dev server
//! (`examples/otp_server.rs`). Remote paths are `/`-rooted inside `root`, so
//! nothing outside it can be reached (`..` stops at the root). POSIX modes are
//! kept in memory (Windows has none), shared by every connection that uses
//! the same `Modes`. No symlinks.

use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Mode bits set with `chmod`, by remote path.
pub type Modes = Arc<Mutex<HashMap<String, u32>>>;

enum Open {
    Dir { path: String, sent: bool },
    File(std::fs::File),
}

pub struct DirSftp {
    root: PathBuf,
    home: String,
    modes: Modes,
    handles: HashMap<String, Open>,
    next: u64,
}

impl DirSftp {
    /// Serves `root`; `home` (like "/home/shellwick") is created inside it and is
    /// where relative paths start.
    pub fn new(root: PathBuf, home: &str, modes: Modes) -> Self {
        let _ = std::fs::create_dir_all(root.join(home.trim_start_matches('/')));
        Self { root, home: home.to_string(), modes, handles: HashMap::new(), next: 0 }
    }

    /// The absolute remote form of `path` (`.` and `..` resolved, never above `/`).
    fn canonical(&self, path: &str) -> String {
        let full = if path.starts_with('/') { path.to_string() } else { format!("{}/{path}", self.home) };
        let mut parts: Vec<&str> = Vec::new();
        for p in full.split('/') {
            match p {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                p => parts.push(p),
            }
        }
        format!("/{}", parts.join("/"))
    }

    fn local(&self, path: &str) -> PathBuf {
        let c = self.canonical(path);
        let mut p = self.root.clone();
        for part in c.split('/').filter(|s| !s.is_empty()) {
            p.push(part);
        }
        p
    }

    fn attrs(&self, path: &str, meta: &std::fs::Metadata) -> FileAttributes {
        let c = self.canonical(path);
        let default = if meta.is_dir() { 0o755 } else { 0o644 };
        let mode = self.modes.lock().unwrap().get(&c).copied().unwrap_or(default);
        let kind = if meta.is_dir() { 0o040000 } else { 0o100000 };
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as u32);
        FileAttributes { size: Some(if meta.is_dir() { 0 } else { meta.len() }), permissions: Some(kind | mode), mtime, atime: mtime, ..FileAttributes::empty() }
    }

    fn handle(&mut self, open: Open) -> String {
        self.next += 1;
        let h = format!("h{}", self.next);
        self.handles.insert(h.clone(), open);
        h
    }
}

fn status(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

fn code(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl russh_sftp::server::Handler for DirSftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name { id, files: vec![File::dummy(self.canonical(&path))] })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::metadata(self.local(&path)).map_err(code)?;
        Ok(Attrs { id, attrs: self.attrs(&path, &meta) })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        match self.handles.get(&handle) {
            Some(Open::File(f)) => {
                let meta = f.metadata().map_err(code)?;
                let kind = 0o100000 | 0o644;
                Ok(Attrs { id, attrs: FileAttributes { size: Some(meta.len()), permissions: Some(kind), ..FileAttributes::empty() } })
            }
            Some(Open::Dir { path, .. }) => {
                let path = path.clone();
                self.stat(id, path).await
            }
            None => Err(StatusCode::Failure),
        }
    }

    async fn setstat(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        std::fs::metadata(self.local(&path)).map_err(code)?;
        if let Some(p) = attrs.permissions {
            self.modes.lock().unwrap().insert(self.canonical(&path), p & 0o7777);
        }
        Ok(status(id))
    }

    async fn fsetstat(&mut self, id: u32, _: String, _: FileAttributes) -> Result<Status, Self::Error> {
        Ok(status(id))
    }

    async fn open(&mut self, id: u32, filename: String, flags: OpenFlags, _: FileAttributes) -> Result<Handle, Self::Error> {
        let mut o = std::fs::OpenOptions::new();
        o.read(flags.contains(OpenFlags::READ))
            .write(flags.contains(OpenFlags::WRITE) || flags.contains(OpenFlags::APPEND))
            .append(flags.contains(OpenFlags::APPEND))
            .truncate(flags.contains(OpenFlags::TRUNCATE));
        if flags.contains(OpenFlags::CREATE) {
            if flags.contains(OpenFlags::EXCLUDE) {
                o.create_new(true);
            } else {
                o.create(true);
            }
        }
        let f = o.open(self.local(&filename)).map_err(code)?;
        Ok(Handle { id, handle: self.handle(Open::File(f)) })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let Some(Open::File(f)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        f.seek(SeekFrom::Start(offset)).map_err(code)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read(&mut buf).map_err(code)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        let Some(Open::File(f)) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        f.seek(SeekFrom::Start(offset)).map_err(code)?;
        f.write_all(&data).map_err(code)?;
        Ok(status(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if !std::fs::metadata(self.local(&path)).map_err(code)?.is_dir() {
            return Err(StatusCode::Failure);
        }
        let path = self.canonical(&path);
        Ok(Handle { id, handle: self.handle(Open::Dir { path, sent: false }) })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let path = match self.handles.get_mut(&handle) {
            Some(Open::Dir { path, sent }) if !*sent => {
                *sent = true;
                path.clone()
            }
            _ => return Err(StatusCode::Eof),
        };
        let mut files = Vec::new();
        for e in std::fs::read_dir(self.local(&path)).map_err(code)?.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
            if let Ok(meta) = e.metadata() {
                let child = if path == "/" { format!("/{name}") } else { format!("{path}/{name}") };
                files.push(File::new(name, self.attrs(&child, &meta)));
            }
        }
        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let p = self.local(&filename);
        if p.is_dir() {
            return Err(StatusCode::Failure);
        }
        std::fs::remove_file(p).map_err(code)?;
        self.modes.lock().unwrap().remove(&self.canonical(&filename));
        Ok(status(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, _: FileAttributes) -> Result<Status, Self::Error> {
        std::fs::create_dir(self.local(&path)).map_err(|_| StatusCode::Failure)?;
        Ok(status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        // Like most servers: a vague Failure for a folder that isn't empty.
        std::fs::remove_dir(self.local(&path)).map_err(|_| StatusCode::Failure)?;
        Ok(status(id))
    }

    async fn rename(&mut self, id: u32, old: String, new: String) -> Result<Status, Self::Error> {
        let (from, to) = (self.local(&old), self.local(&new));
        // SFTP v3: never replaces an existing entry (case-only renames excepted).
        if to.exists() && old.to_lowercase() != new.to_lowercase() {
            return Err(StatusCode::Failure);
        }
        std::fs::rename(from, to).map_err(code)?;
        let mut modes = self.modes.lock().unwrap();
        if let Some(m) = modes.remove(&self.canonical(&old)) {
            modes.insert(self.canonical(&new), m);
        }
        Ok(status(id))
    }
}
