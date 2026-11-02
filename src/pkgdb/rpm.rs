//! rpm: the SQLite rpmdb (`/var/lib/rpm/rpmdb.sqlite`, RHEL/Rocky/Alma 9+,
//! Fedora 33+). Each row of `Packages` is a binary rpm header blob.
//! Berkeley DB / NDB rpmdbs (EL8 and older) are not supported.

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

use crate::rootfs::{read_file_limited, Rootfs};

use super::{OsPackage, MAX_DB_SIZE};

const NAME: u32 = 1000;
const VERSION: u32 = 1001;
const RELEASE: u32 = 1002;
const EPOCH: u32 = 1003;
const ARCH: u32 = 1022;
const SOURCERPM: u32 = 1044;
const DIRINDEXES: u32 = 1116;
const BASENAMES: u32 = 1117;
const DIRNAMES: u32 = 1118;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_STRING_ARRAY: u32 = 8;
const TYPE_I18NSTRING: u32 = 9;

pub fn read(fs: &Rootfs) -> Option<Result<Vec<OsPackage>>> {
    let path = fs.host_path("/var/lib/rpm/rpmdb.sqlite")?;
    Some(read_copy(&path))
}

/// SQLite canonicalizes the db path, and `/proc/<pid>/root` is a magic link
/// to `/`: opened in place it would read the *host's* rpmdb. Read a copy.
fn read_copy(path: &std::path::Path) -> Result<Vec<OsPackage>> {
    let bytes = read_file_limited(path, MAX_DB_SIZE).context("cannot read rpmdb.sqlite")?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!(
        "virtsec-rpmdb-{}-{nanos}.sqlite",
        std::process::id()
    ));
    std::fs::write(&tmp, bytes).context("cannot copy rpmdb.sqlite to a temp file")?;
    let result = read_db(&tmp);
    let _ = std::fs::remove_file(&tmp);
    result
}

fn read_db(path: &std::path::Path) -> Result<Vec<OsPackage>> {
    // Read-only and immutable: no locks, no -wal/-shm side files.
    let uri = format!("file:{}?immutable=1", path.display());
    let conn = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .context("failed to open rpmdb.sqlite")?;
    let mut stmt = conn
        .prepare("SELECT blob FROM Packages")
        .context("rpmdb.sqlite has no Packages table")?;
    let blobs = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    Ok(blobs
        .filter_map(|b| b.ok().and_then(|b| parse_header(&b)))
        .filter(|p| p.name != "gpg-pubkey")
        .collect())
}

/// Parse an rpm header blob (as stored in rpmdb, without the 8-byte magic):
/// `il:u32 dl:u32`, then `il` index entries `tag type offset count`, then data.
pub fn parse_header(blob: &[u8]) -> Option<OsPackage> {
    let be = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(blob.get(at..at + 4)?.try_into().ok()?))
    };
    let il = be(0)? as usize;
    let dl = be(4)? as usize;
    let data_start = 8 + il.checked_mul(16)?;
    let data = blob.get(data_start..data_start.checked_add(dl)?)?;

    let strings = |tag: u32| -> Vec<String> {
        (0..il)
            .find_map(|i| {
                let e = 8 + i * 16;
                (be(e)? == tag).then_some(())?;
                let (ty, off, count) = (be(e + 4)?, be(e + 8)? as usize, be(e + 12)? as usize);
                let tail = data.get(off..)?;
                match ty {
                    TYPE_STRING | TYPE_STRING_ARRAY | TYPE_I18NSTRING => Some(
                        tail.split(|&b| b == 0)
                            .take(count.max(1))
                            .map(|s| String::from_utf8_lossy(s).into_owned())
                            .collect(),
                    ),
                    TYPE_INT32 => Some(
                        tail.chunks_exact(4)
                            .take(count)
                            .map(|c| u32::from_be_bytes(c.try_into().unwrap()).to_string())
                            .collect(),
                    ),
                    _ => None,
                }
            })
            .unwrap_or_default()
    };

    let one = |v: Vec<String>| v.into_iter().next();
    let name = one(strings(NAME))?;
    let version = one(strings(VERSION))?;
    let release = one(strings(RELEASE))?;
    let epoch = one(strings(EPOCH));
    let arch = one(strings(ARCH)).unwrap_or_default();
    let source = one(strings(SOURCERPM)).and_then(|s| source_name(&s));

    let dirs = strings(DIRNAMES);
    let files = strings(BASENAMES)
        .into_iter()
        .zip(strings(DIRINDEXES))
        .filter_map(|(base, idx)| Some(format!("{}{base}", dirs.get(idx.parse::<usize>().ok()?)?)))
        .collect();

    let evr = match epoch {
        Some(e) if e != "0" => format!("{e}:{version}-{release}"),
        _ => format!("{version}-{release}"),
    };
    Some(OsPackage {
        name,
        version: evr,
        arch,
        source,
        source_version: None,
        files,
    })
}

/// `openssl-3.0.7-27.el9.src.rpm` → `openssl`.
fn source_name(srpm: &str) -> Option<String> {
    let stem = srpm.strip_suffix(".src.rpm")?;
    let mut parts = stem.rsplitn(3, '-');
    let (_release, _version) = (parts.next()?, parts.next()?);
    parts.next().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header blob from `(tag, type, payload, count)` entries.
    fn header(entries: &[(u32, u32, Vec<u8>, u32)]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for (tag, ty, payload, count) in entries {
            while *ty == TYPE_INT32 && data.len() % 4 != 0 {
                data.push(0);
            }
            for v in [*tag, *ty, data.len() as u32, *count] {
                index.extend(v.to_be_bytes());
            }
            data.extend(payload);
        }
        let mut blob = Vec::new();
        blob.extend((entries.len() as u32).to_be_bytes());
        blob.extend((data.len() as u32).to_be_bytes());
        blob.extend(index);
        blob.extend(data);
        blob
    }

    fn s(v: &str) -> Vec<u8> {
        format!("{v}\0").into_bytes()
    }

    #[test]
    fn parses_header_with_files_and_epoch() {
        let blob = header(&[
            (NAME, TYPE_STRING, s("openssl-libs"), 1),
            (VERSION, TYPE_STRING, s("3.0.7"), 1),
            (RELEASE, TYPE_STRING, s("27.el9"), 1),
            (EPOCH, TYPE_INT32, 1u32.to_be_bytes().to_vec(), 1),
            (ARCH, TYPE_STRING, s("x86_64"), 1),
            (SOURCERPM, TYPE_STRING, s("openssl-3.0.7-27.el9.src.rpm"), 1),
            (
                DIRNAMES,
                TYPE_STRING_ARRAY,
                [s("/usr/lib64/"), s("/etc/")].concat(),
                2,
            ),
            (
                BASENAMES,
                TYPE_STRING_ARRAY,
                [s("libssl.so.3"), s("ssl.cnf")].concat(),
                2,
            ),
            (
                DIRINDEXES,
                TYPE_INT32,
                [0u32.to_be_bytes(), 1u32.to_be_bytes()].concat(),
                2,
            ),
        ]);
        let p = parse_header(&blob).unwrap();
        assert_eq!(p.name, "openssl-libs");
        assert_eq!(p.version, "1:3.0.7-27.el9");
        assert_eq!(p.source.as_deref(), Some("openssl"));
        assert_eq!(p.files, ["/usr/lib64/libssl.so.3", "/etc/ssl.cnf"]);
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert!(parse_header(&[0, 0, 0, 9, 0, 0, 0, 1]).is_none());
        assert!(parse_header(&[]).is_none());
    }
}
