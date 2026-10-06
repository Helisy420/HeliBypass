//! Translations for text produced on the Rust side. The Slint UI has its own bundled
//! translations; both read the same `lang/<code>/LC_MESSAGES/heli-bypass.po` files, so a phrase
//! is translated in exactly one place.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

const RU_PO: &str = include_str!("../lang/ru/LC_MESSAGES/heli-bypass.po");

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Language {
    English = 0,
    Russian = 1,
}

impl Language {
    pub fn code(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::Russian => "ru",
        }
    }

    pub fn from_code(code: &str) -> Self {
        if code.eq_ignore_ascii_case("ru") { Language::Russian } else { Language::English }
    }

    pub fn from_index(i: i32) -> Self {
        if i == 1 { Language::Russian } else { Language::English }
    }

    pub fn index(self) -> i32 {
        self as i32
    }

    /// The system UI language, used for the very first start.
    pub fn system_default() -> Self {
        let name = std::env::var("LANG").or_else(|_| std::env::var("LC_ALL")).unwrap_or_default();
        if name.starts_with("ru") || system_is_russian() { Language::Russian } else { Language::English }
    }
}

#[cfg(windows)]
fn system_is_russian() -> bool {
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
    // SAFETY: no arguments, returns a LANGID. The primary language id is the low 10 bits.
    let id = unsafe { GetUserDefaultUILanguage() };
    (id & 0x3ff) == 0x19 // LANG_RUSSIAN
}

#[cfg(not(windows))]
fn system_is_russian() -> bool {
    false
}

static CURRENT: AtomicU8 = AtomicU8::new(0);

pub fn set_language(lang: Language) {
    CURRENT.store(lang as u8, Ordering::Relaxed);
}

pub fn language() -> Language {
    if CURRENT.load(Ordering::Relaxed) == 1 { Language::Russian } else { Language::English }
}

fn russian() -> &'static HashMap<String, String> {
    static T: OnceLock<HashMap<String, String>> = OnceLock::new();
    T.get_or_init(|| parse_po(RU_PO))
}

/// Translate `msgid` into the current language (falls back to the English text).
pub fn tr(msgid: &str) -> String {
    match language() {
        Language::English => msgid.to_owned(),
        Language::Russian => russian().get(msgid).cloned().unwrap_or_else(|| msgid.to_owned()),
    }
}

/// Translate and fill `{}` placeholders in order.
pub fn trf(msgid: &str, args: &[&str]) -> String {
    let mut out = tr(msgid);
    for a in args {
        if let Some(pos) = out.find("{}") {
            out.replace_range(pos..pos + 2, a);
        }
    }
    out
}

/// Like [`tr`], but also matches catalog entries that contain `{}` placeholders against text
/// with dynamic parts (service names, paths, counts) produced by the lower crates.
pub fn tr_dyn(text: &str) -> String {
    if language() == Language::English || text.is_empty() {
        return text.to_owned();
    }
    let table = russian();
    if let Some(hit) = table.get(text) {
        return hit.clone();
    }
    for (key, value) in table.iter().filter(|(k, _)| k.contains("{}")) {
        if let Some(args) = match_pattern(key, text) {
            let mut out = value.clone();
            for a in args {
                if let Some(pos) = out.find("{}") {
                    out.replace_range(pos..pos + 2, a);
                }
            }
            return out;
        }
    }
    text.to_owned()
}

/// Match `text` against `pattern` where each `{}` stands for any substring; returns the pieces.
fn match_pattern<'a>(pattern: &str, text: &'a str) -> Option<Vec<&'a str>> {
    let parts: Vec<&str> = pattern.split("{}").collect();
    let (first, rest) = parts.split_first()?;
    let mut remaining = text.strip_prefix(first)?;
    let mut args = Vec::new();
    for (i, lit) in rest.iter().enumerate() {
        let last = i == rest.len() - 1;
        let at = if last { remaining.ends_with(lit).then(|| remaining.len() - lit.len())? } else { remaining.find(lit)? };
        args.push(&remaining[..at]);
        remaining = &remaining[at + lit.len()..];
    }
    Some(args)
}

fn parse_po(text: &str) -> HashMap<String, String> {
    #[derive(PartialEq)]
    enum Cur {
        None,
        Id,
        Str,
    }
    let mut map = HashMap::new();
    let (mut id, mut val, mut cur) = (String::new(), String::new(), Cur::None);
    let mut flush = |id: &mut String, val: &mut String| {
        if !id.is_empty() && !val.is_empty() {
            map.insert(std::mem::take(id), std::mem::take(val));
        } else {
            id.clear();
            val.clear();
        }
    };
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("msgid ") {
            flush(&mut id, &mut val);
            id = unquote(rest);
            cur = Cur::Id;
        } else if let Some(rest) = line.strip_prefix("msgstr ") {
            val = unquote(rest);
            cur = Cur::Str;
        } else if line.starts_with('"') {
            match cur {
                Cur::Id => id.push_str(&unquote(line)),
                Cur::Str => val.push_str(&unquote(line)),
                Cur::None => {}
            }
        }
    }
    flush(&mut id, &mut val);
    map
}

fn unquote(s: &str) -> String {
    let s = s.trim().trim_start_matches('"').trim_end_matches('"');
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(o) => {
                    out.push('\\');
                    out.push(o);
                }
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// "5 min ago"-style relative time.
pub fn ago(secs: u64) -> String {
    match secs {
        0..=59 => tr("just now"),
        60..=3599 => trf("{} min ago", &[&(secs / 60).to_string()]),
        3600..=86399 => trf("{} h ago", &[&(secs / 3600).to_string()]),
        _ => trf("{} d ago", &[&(secs / 86400).to_string()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The language is process-global; tests that switch it must not run concurrently.
    static LANG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn parses_the_bundled_catalog() {
        let t = russian();
        assert_eq!(t.get("Overview").map(String::as_str), Some("Обзор"));
        assert_eq!(t.get("Use “{}”").map(String::as_str), Some("Выбрать «{}»"));
        assert!(t.len() > 150, "{}", t.len());
    }

    #[test]
    fn translates_with_fallback_and_placeholders() {
        let _guard = LANG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_language(Language::Russian);
        assert_eq!(tr("Quit"), "Выход");
        assert_eq!(tr("not in the catalog"), "not in the catalog");
        assert_eq!(trf("{} of {}", &["5", "8"]), "5 из 8");
        assert_eq!(ago(30), "только что");
        assert_eq!(ago(7200), "2 ч назад");
        set_language(Language::English);
        assert_eq!(tr("Quit"), "Quit");
        assert_eq!(trf("{} of {}", &["5", "8"]), "5 of 8");
    }

    #[test]
    fn translates_messages_with_dynamic_parts() {
        let _guard = LANG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_language(Language::Russian);
        assert_eq!(tr_dyn("Conflicting services installed: GoodbyeDPI, winws1"), "Конфликтующие службы установлены: GoodbyeDPI, winws1");
        assert_eq!(tr_dyn("Quit"), "Выход");
        assert_eq!(tr_dyn("totally unknown"), "totally unknown");
        assert_eq!(match_pattern("a {} b {} c", "a 1 b 2 c"), Some(vec!["1", "2"]));
        assert_eq!(match_pattern("a {} c", "x 1 c"), None);
        set_language(Language::English);
        assert_eq!(tr_dyn("Conflicting services installed: x"), "Conflicting services installed: x");
    }

    #[test]
    fn catalog_covers_every_slint_message() {
        // Every @tr("...") in the UI must have a Russian entry, so nothing silently stays English.
        let ui = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
        let mut missing = Vec::new();
        let mut stack = vec![ui];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "slint") {
                    let text = std::fs::read_to_string(&p).unwrap();
                    for part in text.split("@tr(\"").skip(1) {
                        let mut end = 0;
                        let b = part.as_bytes();
                        while end < b.len() && !(b[end] == b'"' && (end == 0 || b[end - 1] != b'\\')) {
                            end += 1;
                        }
                        let id = &part[..end];
                        if !russian().contains_key(id) {
                            missing.push(id.to_owned());
                        }
                    }
                }
            }
        }
        assert!(missing.is_empty(), "untranslated UI strings: {missing:#?}");
    }
}
