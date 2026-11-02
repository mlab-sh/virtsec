//! Go build info (`.go.buildinfo`): the toolchain version and module list
//! embedded in every Go ≥ 1.18 binary, as `go version -m` prints it.

const MAGIC: &[u8] = b"\xff Go buildinf:";
/// `flags & 2`: version and modinfo are inline varint-prefixed strings (1.18+).
const FLAG_INLINE: u8 = 0x2;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoBuild {
    /// `1.22.1` (the `go` prefix stripped, as OSV's `stdlib` versions are).
    pub go_version: String,
    /// `(module path, version)` of every dependency, replacements applied.
    pub deps: Vec<(String, String)>,
}

/// Find and decode the build info in an executable's bytes.
pub fn parse(bin: &[u8]) -> Option<GoBuild> {
    // The header sits 16-byte aligned in the data segment, as Go's own reader assumes.
    let start = (0..bin.len().saturating_sub(32))
        .step_by(16)
        .find(|&i| bin[i..].starts_with(MAGIC))?;
    let flags = bin[start + 15];
    if flags & FLAG_INLINE == 0 {
        return None; // pre-1.18 pointer-based layout: not supported
    }
    let mut rest = &bin[start + 32..];
    let version = read_varint_str(&mut rest)?;
    let mut modinfo = read_varint_str(&mut rest)?;
    // modinfo is wrapped in 16-byte sentinels.
    if modinfo.len() >= 33 && modinfo.as_bytes()[modinfo.len() - 17] == b'\n' {
        modinfo = modinfo[16..modinfo.len() - 16].to_string();
    }

    let mut deps: Vec<(String, String)> = Vec::new();
    for line in modinfo.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["dep", path, ver, ..] => deps.push((path.to_string(), ver.to_string())),
            // `=>` replaces the dep on the line before it.
            ["=>", path, ver, ..] if !ver.is_empty() => {
                if let Some(last) = deps.last_mut() {
                    *last = (path.to_string(), ver.to_string());
                }
            }
            _ => {}
        }
    }
    Some(GoBuild {
        go_version: version.trim_start_matches("go").to_string(),
        deps,
    })
}

fn read_varint_str(buf: &mut &[u8]) -> Option<String> {
    let (mut len, mut shift) = (0usize, 0);
    loop {
        let (&b, rest) = buf.split_first()?;
        *buf = rest;
        len |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    let s = buf.get(..len)?;
    *buf = &buf[len..];
    Some(String::from_utf8_lossy(s).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_str(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut n = s.len();
        while n >= 0x80 {
            out.push((n as u8) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
        out.extend(s.as_bytes());
        out
    }

    fn fake_binary(modinfo: &str) -> Vec<u8> {
        let mut bin = b"\x7fELF".to_vec();
        bin.resize(48, 0); // header lands at 48: 16-aligned
        bin.extend(MAGIC);
        bin.extend([8, FLAG_INLINE]);
        bin.resize(48 + 32, 0);
        bin.extend(varint_str("go1.22.1"));
        let sentinel = "0123456789abcdef";
        bin.extend(varint_str(&format!("{sentinel}{modinfo}{sentinel}")));
        bin.extend([0; 64]);
        bin
    }

    #[test]
    fn decodes_version_deps_and_replacements() {
        let modinfo = "path\texample.com/app\nmod\texample.com/app\t(devel)\t\n\
dep\tgithub.com/gin-gonic/gin\tv1.9.1\th1:x=\n\
dep\tgolang.org/x/net\tv0.17.0\th1:y=\n\
=>\tgolang.org/x/net\tv0.23.0\th1:z=\n\
build\t-compiler=gc\n";
        let info = parse(&fake_binary(modinfo)).unwrap();
        assert_eq!(info.go_version, "1.22.1");
        assert_eq!(
            info.deps,
            vec![
                ("github.com/gin-gonic/gin".to_string(), "v1.9.1".to_string()),
                ("golang.org/x/net".to_string(), "v0.23.0".to_string()),
            ]
        );
    }

    #[test]
    fn non_go_binary() {
        assert_eq!(parse(b"\x7fELF just some C program"), None);
        assert_eq!(parse(&[]), None);
    }
}
