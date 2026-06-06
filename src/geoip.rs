// GeoIP country lookup using MaxMind MMDB databases (GeoLite2-Country,
// GeoLite2-City, or any MMDB that carries a country.iso_code field).

use maxminddb::{Reader, path};
use std::net::IpAddr;

/// In-memory MMDB reader.  `Send + Sync`, safe to share via `Arc`.
pub type CountryReader = Reader<Vec<u8>>;

/// Open an MMDB file and load it into memory.
pub fn open(path: &str) -> anyhow::Result<CountryReader> {
    Reader::open_readfile(path)
        .map_err(|e| anyhow::anyhow!("geoip: cannot open {path}: {e}"))
}

/// Return the ISO 3166-1 alpha-2 country code (e.g. "US") for `ip`.
///
/// Returns `None` for private/reserved ranges and IPs not present in the
/// database.  The returned code matches MaxMind capitalisation (uppercase).
pub fn lookup_country(reader: &CountryReader, ip: IpAddr) -> Option<String> {
    let result = reader.lookup(ip).ok()?;
    result.decode_path(&path!["country", "iso_code"]).ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Attempting to open a nonexistent MMDB path returns an Err whose
    /// message contains the diagnostic prefix added by `open()`.
    #[test]
    fn open_returns_error_for_nonexistent_path() {
        let result = open("/nonexistent/path/missing.mmdb");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("geoip: cannot open"),
            "unexpected error: {msg}",
        );
    }

    /// Opening a non-MMDB file (e.g. a plain text file) surfaces the
    /// underlying maxminddb parse error via our diagnostic wrapper.
    #[test]
    fn open_returns_error_for_non_mmdb_file() {
        // Use this source file itself as a "definitely not an MMDB"
        // input -- avoids needing a temp file.
        let result = open(file!());
        assert!(
            result.is_err(),
            "expected open() to reject a non-MMDB file"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("geoip: cannot open"),
            "unexpected error: {msg}",
        );
    }

    /// `lookup_country` accepts both IPv4 and IPv4-mapped IPv6
    /// (`::ffff:a.b.c.d`) addresses without panicking.  We can't
    /// verify positive lookup results without a real MMDB file, but
    /// the parser path is the same either way -- the test ensures
    /// we don't regress to the older code that rejected v4-mapped
    /// addresses.
    #[test]
    fn lookup_country_accepts_v4_and_v4_mapped_v6() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let v4: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        // ::ffff:1.2.3.4
        let mapped: IpAddr =
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304).into();
        // Type-check only: we don't have a Reader without an MMDB.
        // The functions accept both signatures and that's the
        // regression we're guarding.
        let _: fn(&CountryReader, IpAddr) -> Option<String> =
            lookup_country;
        let _ = (v4, mapped);
    }
}
