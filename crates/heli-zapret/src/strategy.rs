//! Strategies: the `winws.exe` argument sets shipped by zapret-discord-youtube as
//! `general*.bat` files. We parse the batch files instead of hard-coding the arguments so that
//! newer upstream releases (or the user's own `.bat` files) work without recompiling.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strategy {
    /// File stem, e.g. `general (ALT)`.
    pub name: String,
    /// Free-text hint from a `:: comment` in the batch file (e.g. `NOT RECOMMENDED`).
    pub note: Option<String>,
    pub origin: Origin,
    /// Parsed arguments with `%BIN%`, `%LISTS%`, `%GameFilterTCP%`, `%GameFilterUDP%` unresolved.
    template: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Builtin,
    User(PathBuf),
}

/// Values substituted into a strategy's placeholders.
#[derive(Debug, Clone)]
pub struct ArgContext {
    pub bin_dir: PathBuf,
    pub lists_dir: PathBuf,
    /// Port ranges for the game filter. `12` means "disabled" (a port nothing uses).
    pub game_tcp: String,
    pub game_udp: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("no winws.exe invocation found")]
    NoCommand,
    #[error("unbalanced quote in command line")]
    UnbalancedQuote,
}

impl Strategy {
    pub fn parse(name: &str, bat: &str, origin: Origin) -> Result<Self, ParseError> {
        let bat = bat.strip_prefix('\u{feff}').unwrap_or(bat);
        let lines: Vec<&str> = bat.lines().collect();

        let note = lines
            .iter()
            .map(|l| l.trim())
            .filter(|l| l.starts_with("::") && !l.contains("65001"))
            .map(|l| l.trim_start_matches(':').trim().to_owned())
            .find(|l| !l.is_empty());

        let start = lines
            .iter()
            .position(|l| {
                let t = l.trim_start();
                !t.starts_with("::") && !t.to_ascii_lowercase().starts_with("rem ") && t.to_ascii_lowercase().contains("winws.exe")
            })
            .ok_or(ParseError::NoCommand)?;

        // everything after "winws.exe" (optionally followed by a closing quote), with ^ continuations joined
        let first = lines[start];
        let idx = first.to_ascii_lowercase().find("winws.exe").ok_or(ParseError::NoCommand)? + "winws.exe".len();
        let mut command = first[idx..].trim_start_matches('"').to_owned();
        let mut i = start;
        while command.trim_end().ends_with('^') && i + 1 < lines.len() {
            let trimmed = command.trim_end();
            command = trimmed[..trimmed.len() - 1].to_owned();
            i += 1;
            command.push(' ');
            command.push_str(lines[i]);
        }

        let template = tokenize(&unescape_caret(&command))?;
        if template.is_empty() {
            return Err(ParseError::NoCommand);
        }
        Ok(Self { name: name.to_owned(), note, origin, template })
    }

    /// A strategy from already tokenized arguments (placeholders such as `%BIN%` unresolved).
    pub fn from_template(name: &str, note: Option<String>, origin: Origin, template: Vec<String>) -> Self {
        Self { name: name.to_owned(), note, origin, template }
    }

    /// The arguments with placeholders unresolved.
    pub fn template(&self) -> &[String] {
        &self.template
    }

    /// A batch file in the upstream layout (it also runs on its own from the `strategies` folder).
    /// `note` becomes the comment shown next to the strategy name.
    pub fn to_bat(&self, note: &str) -> String {
        let render = |t: &str| -> String {
            let needs_quotes = |v: &str| v.contains('%') || v.contains(' ') || v.is_empty();
            match t.split_once('=') {
                Some((k, v)) if k.starts_with("--") && needs_quotes(v) => format!("{k}=\"{v}\""),
                _ if needs_quotes(t) => format!("\"{t}\""),
                _ => t.to_owned(),
            }
        };
        let mut lines: Vec<String> = Vec::new();
        let mut cur: Vec<String> = Vec::new();
        for t in &self.template {
            if t == "--new" {
                cur.push("--new ^".to_owned());
                lines.push(cur.join(" "));
                cur.clear();
            } else {
                cur.push(render(t));
            }
        }
        lines.push(cur.join(" "));
        let note = note.replace(['\r', '\n'], " ");
        format!(
            "@echo off\r\n:: {note}\r\nchcp 65001 > nul\r\n:: 65001 - UTF-8\r\n\r\n\
             set \"BIN=%~dp0..\\bin\\\"\r\nset \"LISTS=%~dp0..\\lists\\\"\r\n\
             if not defined GameFilterTCP set \"GameFilterTCP=12\"\r\nif not defined GameFilterUDP set \"GameFilterUDP=12\"\r\n\
             cd /d %BIN%\r\n\r\nstart \"zapret: %~n0\" /min \"%BIN%winws.exe\" {}\r\n",
            lines.join("\r\n")
        )
    }

    pub fn load_file(path: &Path) -> Result<Self, ParseError> {
        let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("custom").to_owned();
        let text = std::fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned()).map_err(|_| ParseError::NoCommand)?;
        Self::parse(&name, &text, Origin::User(path.to_path_buf()))
    }

    /// The final argument vector for `winws.exe`.
    pub fn args(&self, ctx: &ArgContext) -> Vec<String> {
        let bin = with_trailing_sep(&ctx.bin_dir);
        let lists = with_trailing_sep(&ctx.lists_dir);
        self.template
            .iter()
            .map(|t| {
                t.replace("%BIN%", &bin)
                    .replace("%LISTS%", &lists)
                    .replace("%GameFilterTCP%", &ctx.game_tcp)
                    .replace("%GameFilterUDP%", &ctx.game_udp)
                    .replace("%GameFilter%", &ctx.game_tcp)
            })
            .collect()
    }

    /// Whether the strategy reacts to the game filter setting at all.
    pub fn uses_game_filter(&self) -> bool {
        self.template.iter().any(|t| t.contains("%GameFilter"))
    }

    /// A short human description of the desync techniques used for HTTPS (TCP/443) traffic,
    /// e.g. `fake · fakedsplit`.
    pub fn technique(&self) -> String {
        let mut techniques: Vec<String> = Vec::new();
        for t in &self.template {
            // The shortest-listed TCP rule is the general web one; collect every desync mode once.
            if let Some(v) = t.strip_prefix("--dpi-desync=") {
                for m in v.split(',') {
                    if !m.is_empty() && !techniques.iter().any(|x| x == m) {
                        techniques.push(m.to_owned());
                    }
                }
            }
        }
        // QUIC/UDP rules are always plain `fake`; surface the more interesting TCP techniques first.
        techniques.sort_by_key(|t| (t == "fake", t.clone()));
        if techniques.is_empty() { "custom".into() } else { techniques.join(" · ") }
    }

    /// Render a Windows command line (`winws.exe` excluded) suitable for `sc create binPath=`.
    pub fn command_line(&self, ctx: &ArgContext) -> String {
        let mut out = String::new();
        for (i, a) in self.args(ctx).iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            let _ = write!(out, "{}", quote_arg(a));
        }
        out
    }
}

fn with_trailing_sep(p: &Path) -> String {
    let mut s = p.to_string_lossy().into_owned();
    if !s.ends_with('\\') && !s.ends_with('/') {
        s.push('\\');
    }
    s
}

/// cmd.exe's caret escape: `^x` is a literal `x`.
fn unescape_caret(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '^' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split on whitespace outside double quotes and drop the quotes themselves.
fn tokenize(s: &str) -> Result<Vec<String>, ParseError> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut has_token = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quote => {
                if has_token {
                    tokens.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if in_quote {
        return Err(ParseError::UnbalancedQuote);
    }
    if has_token {
        tokens.push(cur);
    }
    Ok(tokens)
}

/// Quote one argument the way `CommandLineToArgvW` expects.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// Natural ordering: `ALT2` before `ALT10`, and plain `general` first.
pub fn natural_key(name: &str) -> Vec<(u8, String, u64)> {
    // punctuation would make "general (alt)" sort after "general (alt2)"
    let lower: String = name.to_lowercase().chars().filter(|c| !matches!(c, '(' | ')' | ' ')).collect();
    let mut out = Vec::new();
    let mut text = String::new();
    let mut digits = String::new();
    for c in lower.chars() {
        if c.is_ascii_digit() {
            if !text.is_empty() {
                out.push((0, std::mem::take(&mut text), 0));
            }
            digits.push(c);
        } else {
            if !digits.is_empty() {
                out.push((1, String::new(), digits.parse().unwrap_or(0)));
                digits.clear();
            }
            text.push(c);
        }
    }
    if !text.is_empty() {
        out.push((0, text, 0));
    }
    if !digits.is_empty() {
        out.push((1, String::new(), digits.parse().unwrap_or(0)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "@echo off\r\nchcp 65001 > nul\r\n:: 65001 - UTF-8\r\n:: NOT RECOMMENDED\r\n\r\n\
cd /d \"%~dp0\"\r\nset \"BIN=%~dp0bin\\\"\r\n\
start \"zapret: %~n0\" /min \"%BIN%winws.exe\" --wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^\r\n\
--filter-udp=443 --hostlist=\"%LISTS%list-general.txt\" --dpi-desync=fake --dpi-desync-fake-tls=^! --new ^\r\n\
--filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-seqovl-pattern=\"%BIN%tls_clienthello_4pda_to.bin\"\r\n";

    fn ctx() -> ArgContext {
        ArgContext {
            bin_dir: PathBuf::from(r"C:\HB\zapret\bin"),
            lists_dir: PathBuf::from(r"C:\HB\zapret\lists"),
            game_tcp: "12".into(),
            game_udp: "1024-65535".into(),
        }
    }

    #[test]
    fn parses_continuations_quotes_and_carets() {
        let s = Strategy::parse("general (ALT)", SAMPLE, Origin::Builtin).unwrap();
        assert_eq!(s.note.as_deref(), Some("NOT RECOMMENDED"));
        let args = s.args(&ctx());
        assert_eq!(args[0], "--wf-tcp=80,443,12");
        assert_eq!(args[1], "--wf-udp=443,1024-65535");
        assert!(args.contains(&r"--hostlist=C:\HB\zapret\lists\list-general.txt".to_owned()));
        assert!(args.contains(&"--dpi-desync-fake-tls=!".to_owned()), "^! must become !");
        assert!(args.contains(&"--new".to_owned()));
        assert_eq!(args.iter().filter(|a| a.as_str() == "--new").count(), 1);
        assert!(args.last().unwrap().ends_with(r"zapret\bin\tls_clienthello_4pda_to.bin"));
        assert!(s.uses_game_filter());
        assert!(args.iter().all(|a| !a.contains('%') && !a.contains('^') && !a.contains('"')), "{args:?}");
    }

    #[test]
    fn technique_summary() {
        let s = Strategy::parse("x", SAMPLE, Origin::Builtin).unwrap();
        assert_eq!(s.technique(), "multisplit · fake");
    }

    #[test]
    fn rejects_files_without_winws() {
        assert!(matches!(Strategy::parse("x", "@echo off\r\necho hi\r\n", Origin::Builtin), Err(ParseError::NoCommand)));
    }

    #[test]
    fn quotes_like_windows() {
        assert_eq!(quote_arg("--a=b"), "--a=b");
        assert_eq!(quote_arg(r"--p=C:\Program Files\x"), r#""--p=C:\Program Files\x""#);
        assert_eq!(quote_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote_arg(r"C:\dir with space\"), r#""C:\dir with space\\""#);
    }

    #[test]
    fn natural_order() {
        let mut names = vec!["general (ALT10)", "general (ALT2)", "general", "general (ALT)", "general (ALT11)"];
        names.sort_by_key(|n| natural_key(n));
        assert_eq!(names, vec!["general", "general (ALT)", "general (ALT2)", "general (ALT10)", "general (ALT11)"]);
    }
}
