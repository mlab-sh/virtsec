//! A minimal qemu-guest-agent client over PVE's per-VM socket
//! (`/var/run/qemu-server/<vmid>.qga`): one JSON command per line.
//!
//! The guest is untrusted: answers are size-capped, and nothing it sends is
//! written to the host except through [`safe_dirs`] (no symlink is followed).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::os::OsRelease;

/// Largest answer line accepted (QGA caps captured output at 16 MiB, base64 grows it by 4/3).
const MAX_LINE: u64 = 24 * 1024 * 1024;

pub struct Agent {
    reader: BufReader<UnixStream>,
}

/// A finished `guest-exec`.
pub struct ExecOutput {
    pub code: i64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

impl Agent {
    pub fn connect(vmid: u32) -> Result<Self> {
        let path = format!("/var/run/qemu-server/{vmid}.qga");
        let stream =
            UnixStream::connect(&path).with_context(|| format!("cannot connect to {path}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut agent = Self {
            reader: BufReader::new(stream),
        };
        // Answers to a previous client may still be queued: sync on a fresh id.
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64 % 1_000_000_000);
        agent.send("guest-sync", json!({ "id": id }))?;
        for _ in 0..16 {
            if agent.read()?.get("return") == Some(&json!(id)) {
                return Ok(agent);
            }
        }
        bail!("guest agent of VM {vmid} did not sync (not running in the guest?)")
    }

    fn send(&mut self, cmd: &str, args: Value) -> Result<()> {
        let mut line = serde_json::to_vec(&json!({ "execute": cmd, "arguments": args }))?;
        line.push(b'\n');
        self.reader.get_mut().write_all(&line)?;
        Ok(())
    }

    fn read(&mut self) -> Result<Value> {
        let mut line = Vec::new();
        (&mut self.reader)
            .take(MAX_LINE)
            .read_until(b'\n', &mut line)
            .context("guest agent did not answer")?;
        if !line.ends_with(b"\n") {
            bail!("guest agent answer truncated or larger than {MAX_LINE} bytes");
        }
        Ok(serde_json::from_slice(&line)?)
    }

    pub fn call(&mut self, cmd: &str, args: Value) -> Result<Value> {
        self.send(cmd, args)?;
        let v = self.read()?;
        if let Some(e) = v.get("error") {
            bail!("{cmd}: {}", e["desc"].as_str().unwrap_or("error"));
        }
        Ok(v["return"].clone())
    }

    /// `guest-get-osinfo`, as an os-release.
    pub fn os_info(&mut self) -> Result<OsRelease> {
        let v = self.call("guest-get-osinfo", json!({}))?;
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        Ok(OsRelease {
            id: s("id"),
            version_id: s("version-id"),
            pretty_name: s("pretty-name"),
        })
    }

    /// Run `sh -c script` in the guest and wait for it (at most `timeout`).
    pub fn exec_sh(&mut self, script: &str, timeout: Duration) -> Result<ExecOutput> {
        let pid = self.call(
            "guest-exec",
            json!({ "path": "/bin/sh", "arg": ["-c", script], "capture-output": true }),
        )?["pid"]
            .as_i64()
            .context("guest-exec returned no pid")?;
        let start = Instant::now();
        loop {
            let st = self.call("guest-exec-status", json!({ "pid": pid }))?;
            if st["exited"].as_bool() == Some(true) {
                let data = |k: &str| st[k].as_str().map(b64decode).transpose();
                return Ok(ExecOutput {
                    code: st["exitcode"].as_i64().unwrap_or(-1),
                    stdout: data("out-data")?.unwrap_or_default(),
                    stderr: data("err-data")?.unwrap_or_default(),
                    truncated: st["out-truncated"].as_bool() == Some(true),
                });
            }
            if start.elapsed() > timeout {
                bail!("guest command still running after {}s", timeout.as_secs());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn b64decode(s: &str) -> Result<Vec<u8>> {
    let val = |c: u8| -> Result<u32> {
        Ok(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => bail!("invalid base64 from the guest agent"),
        } as u32)
    };
    let bytes: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let data: Vec<u8> = chunk.iter().copied().take_while(|&c| c != b'=').collect();
        let mut n = 0u32;
        for (i, &c) in data.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.extend_from_slice(&n.to_be_bytes()[1..data.len().max(1)]);
    }
    Ok(out)
}

/// Create `rel`'s directories under `root`, refusing to go through anything
/// but a real directory: a guest-supplied symlink never redirects a write to the host.
pub fn safe_dirs(root: &Path, rel: &Path) -> Result<()> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        let Component::Normal(c) = c else {
            if matches!(c, Component::RootDir | Component::CurDir) {
                continue;
            }
            bail!("unsafe path {}", rel.display());
        };
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("{} is not a directory", cur.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&cur)?,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Unpack a guest-made `tar.gz` into `root`: regular files and symlinks only,
/// relative paths without `..`, parents created by [`safe_dirs`].
pub fn unpack(root: &Path, tgz: &[u8]) -> Result<usize> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tgz));
    let mut n = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if !path.components().all(|c| matches!(c, Component::Normal(_))) {
            continue;
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_symlink()) {
            continue;
        }
        if let Some(parent) = path.parent() {
            safe_dirs(root, parent)?;
        }
        let dest = root.join(&path);
        if std::fs::symlink_metadata(&dest).is_ok() {
            continue; // first entry wins, never overwrite through a link
        }
        if kind.is_symlink() {
            let Some(target) = entry.link_name()? else {
                continue;
            };
            // Stored as is: Rootfs resolves it anchored at `root`, never on the host.
            std::os::unix::fs::symlink(target, &dest)?;
        } else {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&dest)?;
            std::io::copy(&mut entry, &mut f)?;
        }
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        assert_eq!(b64decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64decode("aGVsbG8hIQ==").unwrap(), b"hello!!");
        assert_eq!(b64decode("YWJj").unwrap(), b"abc");
        assert_eq!(b64decode("").unwrap(), b"");
        assert!(b64decode("a*==").is_err());
    }

    #[test]
    fn unpack_refuses_escapes() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let add_link = |b: &mut tar::Builder<Vec<u8>>, name: &str, target: &str| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, name, target).unwrap();
        };
        add_link(&mut b, "lib", outside.path().to_str().unwrap());
        add_link(&mut b, "bin", "usr/bin");
        let file = |b: &mut tar::Builder<Vec<u8>>, name: &str| {
            let mut h = tar::Header::new_gnu();
            h.set_size(2);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, &b"hi"[..]).unwrap();
        };
        file(&mut b, "lib/evil");
        file(&mut b, "var/lib/dpkg/status");
        let tgz = {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&b.into_inner().unwrap()).unwrap();
            gz.finish().unwrap()
        };
        assert!(
            unpack(dir.path(), &tgz).is_err(),
            "lib/evil must not go through the lib link"
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);

        // Without the hostile entry, files and links land in place.
        let mut b = tar::Builder::new(Vec::new());
        add_link(&mut b, "bin", "usr/bin");
        file(&mut b, "var/lib/dpkg/status");
        let tgz = {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&b.into_inner().unwrap()).unwrap();
            gz.finish().unwrap()
        };
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(unpack(dir.path(), &tgz).unwrap(), 2);
        assert_eq!(
            std::fs::read_link(dir.path().join("bin")).unwrap(),
            Path::new("usr/bin")
        );
        assert_eq!(
            std::fs::read(dir.path().join("var/lib/dpkg/status")).unwrap(),
            b"hi"
        );
    }
}
