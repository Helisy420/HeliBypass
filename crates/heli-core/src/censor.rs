//! Masks host names in log text so shared logs/screenshots do not reveal user-owned
//! Cloudflare domains. `telegram.org` hosts and `.log` file names stay readable.
//! Port of the Python `DomainCensorFilter`.

const FILE_EXTENSIONS: &[&str] =
    &["txt", "log", "bat", "cmd", "exe", "dll", "sys", "bin", "json", "toml", "ini", "cfg", "md", "ps1", "backup"];

fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.'
}

pub fn censor_domains(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if !is_domain_char(bytes[i]) {
            // copy one (possibly multi-byte) char
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&text[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_domain_char(bytes[i]) {
            i += 1;
        }
        // Don't treat a hyphenated/underscored identifier suffix as part of the previous token.
        let token = &text[start..i];
        let preceded_by_word = start > 0 && (bytes[start - 1] == b'_' || bytes[start - 1] == b'-');
        let followed_by_word = i < bytes.len() && bytes[i] == b'_';
        if preceded_by_word || followed_by_word {
            out.push_str(token);
            continue;
        }
        out.push_str(&censor_token(token));
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

fn censor_token(token: &str) -> String {
    let trimmed = token.trim_end_matches('.');
    let trailing = &token[trimmed.len()..];
    if !looks_like_domain(trimmed) {
        return token.to_owned();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "telegram.org" || lower.ends_with(".telegram.org") {
        return token.to_owned();
    }
    // file names ("ipset-all.txt", "proxy.log") are not host names
    let ext = lower.rsplit('.').next().unwrap_or("");
    if FILE_EXTENSIONS.contains(&ext) {
        return token.to_owned();
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    let last = labels.len() - 1;
    let masked: Vec<String> = labels
        .iter()
        .enumerate()
        .map(|(i, l)| {
            if i == last {
                (*l).to_owned()
            } else {
                let keep = l.len() / 2;
                format!("{}{}", &l[..keep], "*".repeat(l.len() - keep))
            }
        })
        .collect();
    format!("{}{}", masked.join("."), trailing)
}

fn looks_like_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let ok_label = |l: &str| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
    };
    if !labels.iter().all(|l| ok_label(l)) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_user_domains_but_not_telegram() {
        assert_eq!(censor_domains("CF proxy failed: kws2.example.com"), "CF proxy failed: kw**.exa****.com");
        assert_eq!(censor_domains("ws kws2.web.telegram.org ok"), "ws kws2.web.telegram.org ok");
        assert_eq!(censor_domains("listening 127.0.0.1:1443"), "listening 127.0.0.1:1443");
        assert_eq!(censor_domains("see proxy.log"), "see proxy.log");
        assert_eq!(censor_domains("ipset-all.txt updated"), "ipset-all.txt updated");
        assert_eq!(censor_domains("тест kws1.abc.co.uk."), "тест kw**.a**.c*.uk.");
    }
}
