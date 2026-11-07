//! Keeping the Miniserver token between runs, in one file.
//!
//! A stored token lets a new process log in with `authwithtoken` instead of the password.
//! The file is bound to the endpoint and the user name: a token saved for one Miniserver or
//! user is never offered to another. Anything that does not read back cleanly (missing,
//! corrupt, wrong binding) counts as "no token", and the login falls back to the password.
//!
//! The file holds bearer material equivalent to the password. It is written atomically and,
//! on Unix, created with mode 0600 in a directory with mode 0700.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Secret;
use super::token::TokenState;
use crate::transport::url::{Endpoint, Scheme};

/// What is written to the file.
#[derive(Serialize, Deserialize)]
struct Record {
    binding: String,
    token: String,
    valid_until: f64,
    key: Option<String>,
    hash_alg: Option<String>,
    unsecure_password: bool,
    token_rights: Option<u32>,
}

/// A token file for one Miniserver and user.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenFile {
    path: PathBuf,
}

impl std::fmt::Debug for TokenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenFile")
            .field("path", &self.path)
            .finish()
    }
}

impl TokenFile {
    /// A token file at `path`. Nothing is read or created until [`TokenFile::load`] or
    /// [`TokenFile::save`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The stored token, if the file holds one for this endpoint and user.
    /// Any read or parse problem gives `None`.
    pub fn load(&self, endpoint: &Endpoint, user: &str) -> Option<TokenState> {
        let text = fs::read_to_string(&self.path).ok()?;
        let record: Record = serde_json::from_str(&text).ok()?;
        if record.binding != binding(endpoint, user) {
            return None;
        }
        let mut state = TokenState::new(record.token, record.valid_until).ok()?;
        state.key = record.key.map(Secret::new);
        state.hash_alg = record.hash_alg;
        state.unsecure_password = record.unsecure_password;
        state.token_rights = record.token_rights;
        Some(state)
    }

    /// Replace the stored token. Written to a temporary file in the same directory and then
    /// renamed over the old one, so a crash never leaves a half-written file.
    pub fn save(&self, endpoint: &Endpoint, user: &str, token: &TokenState) -> io::Result<()> {
        let record = Record {
            binding: binding(endpoint, user),
            token: token.token().expose().to_owned(),
            valid_until: token.valid_until(),
            key: token.key.as_ref().map(|k| k.expose().to_owned()),
            hash_alg: token.hash_alg.clone(),
            unsecure_password: token.unsecure_password,
            token_rights: token.token_rights,
        };
        let json = serde_json::to_vec(&record).map_err(io::Error::other)?;

        let dir = parent_dir(&self.path);
        create_private_dir(dir)?;
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| io::Error::other("token file path has no file name"))?;
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(".tmp-{}", std::process::id()));
        let tmp = dir.join(tmp_name);

        let written = write_private(&tmp, &json).and_then(|()| fs::rename(&tmp, &self.path));
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
    }
}

/// A token file together with the endpoint and user it belongs to. Sessions hold one of these
/// and save every token they obtain (login and renewal) through it.
#[derive(Clone, Debug)]
pub struct TokenStore {
    file: TokenFile,
    endpoint: Endpoint,
    user: String,
}

impl TokenStore {
    /// A store for `endpoint` and `user`, kept in `file`.
    pub fn new(file: TokenFile, endpoint: Endpoint, user: impl Into<String>) -> Self {
        Self {
            file,
            endpoint,
            user: user.into(),
        }
    }

    /// Save a token. Best effort: a failed write only means the next start logs in with the
    /// password, so the error is not returned.
    pub fn save(&self, token: &TokenState) {
        let _ = self.file.save(&self.endpoint, &self.user, token);
    }

    /// The same as [`TokenStore::save`], but the file I/O runs on a blocking thread, so an
    /// async caller does not hold up the runtime (fsync can be slow on a network disk).
    pub async fn save_off_thread(&self, token: TokenState) {
        let store = self.clone();
        let _ = tokio::task::spawn_blocking(move || store.save(&token)).await;
    }
}

/// Write `bytes` to `path` atomically: a temporary file in the same directory, then a
/// rename. The directory is created private; on Unix the file is 0600.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = parent_dir(path);
    create_private_dir(dir)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::other("file path has no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp-{}", std::process::id()));
    let tmp = dir.join(tmp_name);
    let written = write_private(&tmp, bytes).and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// What a stored token is bound to: the endpoint and the user name.
fn binding(endpoint: &Endpoint, user: &str) -> String {
    let scheme = match endpoint.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    format!(
        "{scheme}://{}:{}{}|{user}",
        endpoint.host, endpoint.port, endpoint.path
    )
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Create the directory if it does not exist. A directory created here is made private
/// (0700, the leaf only). An existing directory keeps its mode: it may belong to something
/// else, such as the home directory when the file name has no directory part.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write the file as a new inode with, on Unix, mode 0600 from the start. A leftover file
/// with the same name is removed first, so its old mode cannot carry over, and `create_new`
/// refuses to follow a symlink planted at that name.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rs-loxone-store-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn endpoint(host: &str) -> Endpoint {
        Endpoint::parse(&format!("https://{host}")).unwrap()
    }

    fn token() -> TokenState {
        let mut t = TokenState::new("tok-abc", 700_000_000.0).unwrap();
        t.key = Some(Secret::new("4142"));
        t.hash_alg = Some("SHA256".into());
        t.unsecure_password = true;
        t.token_rights = Some(4);
        t
    }

    #[test]
    fn round_trip_keeps_every_field() {
        let d = dir("roundtrip");
        let file = TokenFile::new(d.join("token.json"));
        file.save(&endpoint("192.0.2.1"), "admin", &token())
            .unwrap();

        let back = file.load(&endpoint("192.0.2.1"), "admin").unwrap();
        assert_eq!(back, token());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn other_endpoint_or_user_gives_none() {
        let d = dir("binding");
        let file = TokenFile::new(d.join("token.json"));
        file.save(&endpoint("192.0.2.1"), "admin", &token())
            .unwrap();

        assert!(file.load(&endpoint("192.0.2.2"), "admin").is_none());
        assert!(file.load(&endpoint("192.0.2.1"), "other").is_none());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn missing_or_corrupt_file_gives_none() {
        let d = dir("corrupt");
        let path = d.join("token.json");
        let file = TokenFile::new(&path);
        assert!(file.load(&endpoint("192.0.2.1"), "admin").is_none());

        fs::write(&path, b"{ not json").unwrap();
        assert!(file.load(&endpoint("192.0.2.1"), "admin").is_none());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn invalid_token_in_file_gives_none() {
        let d = dir("invalid");
        let path = d.join("token.json");
        let bound = binding(&endpoint("192.0.2.1"), "admin");
        let json = serde_json::json!({
            "binding": bound, "token": "", "valid_until": 1.0,
            "key": null, "hash_alg": null,
            "unsecure_password": false, "token_rights": null
        });
        fs::write(&path, json.to_string()).unwrap();
        assert!(
            TokenFile::new(&path)
                .load(&endpoint("192.0.2.1"), "admin")
                .is_none()
        );
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn save_overwrites_and_leaves_no_temp_file() {
        let d = dir("overwrite");
        let file = TokenFile::new(d.join("token.json"));
        file.save(&endpoint("192.0.2.1"), "admin", &token())
            .unwrap();
        let newer = TokenState::new("tok-new", 800_000_000.0).unwrap();
        file.save(&endpoint("192.0.2.1"), "admin", &newer).unwrap();

        let back = file.load(&endpoint("192.0.2.1"), "admin").unwrap();
        assert_eq!(back.token().expose(), "tok-new");
        let names: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["token.json".to_owned()]);
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("perms");
        let path = d.join("token.json");
        TokenFile::new(&path)
            .save(&endpoint("192.0.2.1"), "admin", &token())
            .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn debug_shows_only_the_path() {
        let text = format!("{:?}", TokenFile::new("/x/token.json"));
        assert!(text.contains("token.json"));
        assert!(!text.contains("tok-"));
    }

    #[cfg(unix)]
    #[test]
    fn existing_directory_keeps_its_mode() {
        // A token file in a directory we did not create (for example the home directory
        // for a bare file name) must not change that directory's permissions.
        use std::os::unix::fs::PermissionsExt;
        let d = dir("existing-mode");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        TokenFile::new(d.join("token.json"))
            .save(&endpoint("192.0.2.1"), "admin", &token())
            .unwrap();
        let mode = fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stale_temp_file_does_not_keep_its_mode() {
        // A leftover temp file with the same name (same process id) and mode 0644 must not
        // become the token file with those permissions.
        use std::os::unix::fs::PermissionsExt;
        let d = dir("stale-tmp");
        let path = d.join("token.json");
        let stale = d.join(format!(".token.json.tmp-{}", std::process::id()));
        fs::write(&stale, b"old").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).unwrap();
        TokenFile::new(&path)
            .save(&endpoint("192.0.2.1"), "admin", &token())
            .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(d).unwrap();
    }
}
