//! IP → country for the explorer's node map (`--geoip`).
//!
//! Reads DB-IP's free "IP to Country Lite" database in CSV form (`start,end,country` per line,
//! IPv4 and IPv6, optionally gzip-compressed), as published monthly at
//! <https://db-ip.com/db/download/ip-to-country-lite> under CC BY 4.0. The explorer credits
//! DB-IP where it shows countries.

use anyhow::{Context, Result, bail};
use std::{io::Read, net::IpAddr, path::Path};

/// A loaded database: range starts in ascending order with their country codes.
#[derive(Debug, Default)]
pub struct GeoIp {
    v4: Vec<(u32, [u8; 2])>,
    v6: Vec<(u128, [u8; 2])>,
    /// File name, shown by the explorer (e.g. `dbip-country-lite-2026-10.csv.gz`).
    pub source: String,
}

impl GeoIp {
    /// Loads a DB-IP country CSV (`.csv` or `.csv.gz`).
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let text = if raw.starts_with(&[0x1f, 0x8b]) {
            let mut s = String::new();
            flate2::read::GzDecoder::new(raw.as_slice()).read_to_string(&mut s)?;
            s
        } else {
            String::from_utf8(raw)?
        };
        let mut g = Self::parse(&text)?;
        g.source = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        Ok(g)
    }

    /// Parses CSV text: `start,end,CC` per line (ranges may come in any order).
    pub fn parse(text: &str) -> Result<Self> {
        let mut g = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut f = line.split(',').map(|x| x.trim().trim_matches('"'));
            let (Some(start), Some(_end), Some(cc)) = (f.next(), f.next(), f.next()) else {
                bail!("line {}: expected start,end,country", n + 1);
            };
            let cc: [u8; 2] = match cc.as_bytes() {
                [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                    [a.to_ascii_uppercase(), b.to_ascii_uppercase()]
                }
                _ => continue,
            };
            match start.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => g.v4.push((u32::from(ip), cc)),
                Ok(IpAddr::V6(ip)) => g.v6.push((u128::from(ip), cc)),
                Err(_) if n == 0 => continue, // a header line
                Err(_) => bail!("line {}: bad address {start}", n + 1),
            }
        }
        if g.v4.is_empty() && g.v6.is_empty() {
            bail!("no ranges");
        }
        g.v4.sort_unstable_by_key(|r| r.0);
        g.v6.sort_unstable_by_key(|r| r.0);
        Ok(g)
    }

    /// ISO 3166 country code of `ip` (`None` when unknown; DB-IP's `ZZ` means unknown too).
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        fn find<T: Ord + Copy>(v: &[(T, [u8; 2])], x: T) -> Option<[u8; 2]> {
            let i = v.partition_point(|r| r.0 <= x);
            (i > 0).then(|| v[i - 1].1)
        }
        let cc = match ip {
            IpAddr::V4(ip) => find(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(v4) => find(&self.v4, u32::from(v4)),
                None => find(&self.v6, u128::from(ip)),
            },
        }?;
        (cc != *b"ZZ").then(|| String::from_utf8_lossy(&cc).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "0.0.0.0,0.255.255.255,ZZ\n1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n\
        211.22.0.0,211.23.255.255,TW\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n";

    #[test]
    fn looks_up_countries() {
        let g = GeoIp::parse(SAMPLE).unwrap();
        let c = |s: &str| g.country(s.parse().unwrap());
        assert_eq!(c("211.22.118.149").as_deref(), Some("TW"));
        assert_eq!(c("1.0.2.9").as_deref(), Some("CN"));
        assert_eq!(c("0.1.2.3"), None);
        assert_eq!(c("2001:4860::8888").as_deref(), Some("US"));
        assert_eq!(c("::ffff:1.0.0.1").as_deref(), Some("AU"));
        assert_eq!(c("::1"), None);
    }

    #[test]
    fn reads_gzip() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("dbip-country-lite-2026-10.csv.gz");
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(SAMPLE.as_bytes()).unwrap();
        std::fs::write(&p, e.finish().unwrap()).unwrap();
        let g = GeoIp::load(&p).unwrap();
        assert_eq!(g.source, "dbip-country-lite-2026-10.csv.gz");
        assert_eq!(g.country("211.23.1.1".parse().unwrap()).as_deref(), Some("TW"));
    }
}
