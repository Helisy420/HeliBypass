//! The user's own lists. Their content lives in the app's settings; this module validates it and
//! writes the files winws reads (the engine only understands files).

use std::io;
use std::net::IpAddr;

use heli_core::paths::{Paths, write_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserList {
    /// Extra domains for the bypass.
    General,
    /// Domains the bypass must not touch.
    Exclude,
    /// Addresses the bypass must not touch.
    IpsetExclude,
}

impl UserList {
    pub const ALL: [UserList; 3] = [UserList::General, UserList::Exclude, UserList::IpsetExclude];

    pub fn from_index(i: i32) -> Option<Self> {
        Self::ALL.get(usize::try_from(i).ok()?).copied()
    }

    pub fn file_name(self) -> &'static str {
        match self {
            UserList::General => "list-general-user.txt",
            UserList::Exclude => "list-exclude-user.txt",
            UserList::IpsetExclude => "ipset-exclude-user.txt",
        }
    }

    /// winws refuses empty list files, so an empty list is written as a harmless dummy entry.
    fn placeholder(self) -> &'static str {
        match self {
            UserList::General | UserList::Exclude => "domain.example.abc",
            UserList::IpsetExclude => "203.0.113.113/32",
        }
    }

    pub fn holds_addresses(self) -> bool {
        self == UserList::IpsetExclude
    }
}

/// Non-empty, non-comment lines.
pub fn entries(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())).filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Number of entries, or the lines (1-based) that are not valid for this list.
pub fn validate(list: UserList, text: &str) -> Result<usize, Vec<(usize, String)>> {
    let mut bad = Vec::new();
    let mut n = 0;
    for (line, entry) in entries(text) {
        let ok = if list.holds_addresses() { is_address_entry(entry) } else { is_domain(entry) };
        if ok {
            n += 1;
        } else {
            bad.push((line, entry.to_owned()));
        }
    }
    if bad.is_empty() { Ok(n) } else { Err(bad) }
}

/// `example.com`, `sub.example.co.uk`, `xn--d1acufc.xn--p1ai` (no schemes, paths or wildcards).
pub fn is_domain(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// An IPv4/IPv6 address, a CIDR block (`10.0.0.0/8`) or a range (`1.2.3.4-1.2.3.9`).
pub fn is_address_entry(s: &str) -> bool {
    if let Some((addr, bits)) = s.split_once('/') {
        let Ok(addr) = addr.parse::<IpAddr>() else { return false };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        return bits.parse::<u8>().is_ok_and(|b| b <= max);
    }
    if let Some((a, b)) = s.split_once('-') {
        return match (a.trim().parse::<IpAddr>(), b.trim().parse::<IpAddr>()) {
            (Ok(a), Ok(b)) => a.is_ipv4() == b.is_ipv4(),
            _ => false,
        };
    }
    s.parse::<IpAddr>().is_ok()
}

/// Tidy the text for storage: trimmed lines, no trailing blank lines, domains lower-cased.
pub fn normalize(list: UserList, text: &str) -> String {
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            let l = l.trim();
            if list.holds_addresses() || l.starts_with('#') { l.to_owned() } else { l.to_ascii_lowercase() }
        })
        .collect();
    while out.last().is_some_and(|l| l.is_empty()) {
        out.pop();
    }
    out.join("\n")
}

/// Write the engine's copy of a list (the placeholder when the list has no entries).
pub fn write_file(paths: &Paths, list: UserList, text: &str) -> io::Result<()> {
    let body: Vec<&str> = entries(text).map(|(_, e)| e).collect();
    let content = if body.is_empty() { format!("{}\n", list.placeholder()) } else { format!("{}\n", body.join("\n")) };
    let path = paths.lists_dir().join(list.file_name());
    if std::fs::read_to_string(&path).is_ok_and(|old| old == content) {
        return Ok(());
    }
    std::fs::create_dir_all(paths.lists_dir())?;
    write_atomic(&path, content.as_bytes())
}

/// What an existing list file contains, for the one-time import. The placeholder entries and
/// the comments the bundle ships are not user content.
pub fn import_file(paths: &Paths, list: UserList) -> String {
    let Ok(text) = std::fs::read_to_string(paths.lists_dir().join(list.file_name())) else { return String::new() };
    let kept: Vec<&str> = entries(&text).map(|(_, e)| e).filter(|e| *e != list.placeholder()).collect();
    kept.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_and_addresses_are_validated() {
        assert!(is_domain("discord.com"));
        assert!(is_domain("Cdn.Discordapp.com."));
        assert!(is_domain("xn--d1acufc.xn--p1ai"));
        for bad in ["https://discord.com", "discord.com/app", "*.discord.com", "-a.com", "a..com", "has space.com"] {
            assert!(!is_domain(bad), "{bad}");
        }
        for ok in ["1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "1.2.3.4-1.2.3.9", "::1"] {
            assert!(is_address_entry(ok), "{ok}");
        }
        for bad in ["1.2.3", "10.0.0.0/33", "1.2.3.4-::1", "example.com"] {
            assert!(!is_address_entry(bad), "{bad}");
        }
    }

    #[test]
    fn validation_reports_line_numbers_and_skips_comments() {
        let text = "# my domains\n\nyoutube.com\nbad entry\nwww.google.com\n";
        assert_eq!(validate(UserList::General, text), Err(vec![(4, "bad entry".to_owned())]));
        assert_eq!(validate(UserList::General, "a.com\n# x\nb.com"), Ok(2));
        assert_eq!(validate(UserList::IpsetExclude, "1.1.1.1\n8.8.8.0/24"), Ok(2));
    }

    #[test]
    fn files_get_placeholders_and_imports_drop_them() {
        let dir = std::env::temp_dir().join(format!("heli-userlists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths::at(&dir);
        write_file(&paths, UserList::General, "# nothing yet\n").unwrap();
        let on_disk = std::fs::read_to_string(paths.lists_dir().join("list-general-user.txt")).unwrap();
        assert_eq!(on_disk, "domain.example.abc\n");
        assert_eq!(import_file(&paths, UserList::General), "");
        write_file(&paths, UserList::General, "Mine.example\n# c\nother.example").unwrap();
        assert_eq!(import_file(&paths, UserList::General), "Mine.example\nother.example");
        assert_eq!(normalize(UserList::General, "  Mine.Example \n\n\n"), "mine.example");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
