//! Strategy Studio (BETA): makes strategy candidates for the smart search and composes a
//! strategy from settings chosen by hand. The result is saved as [`BUILT_NAME`].
//!
//! A strategy is a list of `--new`-separated profiles. Only the profiles that carry ordinary
//! web traffic (TCP 80/443 through the general host list or the IP set) are generated here;
//! QUIC and Discord voice can be tuned by hand, and the Google profile and the game filter keep
//! the base strategy's settings. The web settings tried first are the ones every upstream
//! strategy uses for that traffic (so each is known to be valid for this winws build); the
//! refinement stage then varies the best of them one setting at a time.

use std::collections::HashSet;

use crate::strategy::{Origin, Strategy};

/// Name of the strategy the Studio saves.
pub const BUILT_NAME: &str = "customhelibypass";
/// Upper bound on screening candidates (stage 1).
pub const MAX_CANDIDATES: usize = 18;
/// Upper bound on refinement variations (stage 2, on top of the three finalists).
pub const REFINE_LIMIT: usize = 12;

/// Fake ClientHello payloads shipped in `bin/` (tried as the fake TLS packet and seqovl pattern).
pub const TLS_FAKES: [&str; 5] =
    ["tls_clienthello_www_google_com.bin", "tls_clienthello_4pda_to.bin", "tls_clienthello_max_ru.bin", "tls_clienthello_sochi_park.bin", "tls_clienthello_5ka_ru.bin"];

fn split_profiles(template: &[String]) -> Vec<Vec<String>> {
    let mut out = vec![Vec::new()];
    for t in template {
        if t == "--new" {
            out.push(Vec::new());
        } else {
            out.last_mut().expect("never empty").push(t.clone());
        }
    }
    out
}

fn join_profiles(profiles: &[Vec<String>]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, p) in profiles.iter().enumerate() {
        if i > 0 {
            out.push("--new".to_owned());
        }
        out.extend(p.iter().cloned());
    }
    out
}

fn is_desync_arg(t: &str) -> bool {
    t.starts_with("--dpi-desync") || t.starts_with("--ip-id") || t.starts_with("--dup")
}

/// Ordinary web traffic: TCP 80/443 matched by the general host list or the IP set.
fn is_web_profile(p: &[String]) -> bool {
    let tcp = p.iter().find_map(|t| t.strip_prefix("--filter-tcp="));
    let web_ports = tcp.is_some_and(|v| v.split(',').any(|x| x == "443") && !v.contains("%GameFilter"));
    let general = p.iter().any(|t| t.contains("list-general.txt") || t.contains("ipset-all.txt"));
    web_ports && general
}

/// QUIC (UDP 443) profiles.
fn is_quic_profile(p: &[String]) -> bool {
    p.iter().any(|t| t == "--filter-udp=443")
}

/// Discord voice (UDP, recognised by the `discord`/`stun` payload).
fn is_voice_profile(p: &[String]) -> bool {
    p.iter().any(|t| t.starts_with("--filter-l7=") && t.contains("discord"))
}

/// The desync settings of a strategy's first web profile.
pub fn web_recipe(s: &Strategy) -> Option<Vec<String>> {
    split_profiles(s.template())
        .into_iter()
        .find(|p| is_web_profile(p))
        .map(|p| p.into_iter().filter(|t| is_desync_arg(t)).collect::<Vec<_>>())
        .filter(|r| !r.is_empty())
}

fn with_recipe(base: &Strategy, recipe: &[String]) -> Vec<String> {
    let profiles: Vec<Vec<String>> = split_profiles(base.template())
        .into_iter()
        .map(|p| {
            if !is_web_profile(&p) {
                return p;
            }
            let mut kept: Vec<String> = p.into_iter().filter(|t| !is_desync_arg(t)).collect();
            kept.extend(recipe.iter().cloned());
            kept
        })
        .collect();
    join_profiles(&profiles)
}

fn get<'a>(recipe: &'a [String], key: &str) -> Option<&'a str> {
    recipe.iter().find_map(|t| t.strip_prefix(key))
}

/// Short label for a recipe: `fake,multisplit · ts · seqovl 681 · ×6`.
pub fn describe(recipe: &[String]) -> String {
    let mut parts = vec![get(recipe, "--dpi-desync=").unwrap_or("?").to_owned()];
    if let Some(f) = get(recipe, "--dpi-desync-fooling=") {
        parts.push(f.to_owned());
    }
    if let Some(p) = get(recipe, "--dpi-desync-split-pos=") {
        parts.push(format!("pos {p}"));
    }
    if let Some(s) = get(recipe, "--dpi-desync-split-seqovl=") {
        parts.push(format!("seqovl {s}"));
    }
    if let Some(r) = get(recipe, "--dpi-desync-repeats=") {
        parts.push(format!("×{r}"));
    }
    parts.join(" · ")
}

/// How much a strategy disturbs the traffic: fake packets sent, overlap and split points.
/// Lower is gentler, which keeps long connections healthy and is less conspicuous to the DPI,
/// so it breaks ties in the smart search.
pub fn footprint(s: &Strategy) -> u32 {
    split_profiles(s.template())
        .iter()
        .filter(|p| is_web_profile(p))
        .map(|p| {
            let r: Vec<String> = p.iter().filter(|t| is_desync_arg(t)).cloned().collect();
            let mode = get(&r, "--dpi-desync=").unwrap_or("");
            let fakes = if mode.contains("fake") { get(&r, "--dpi-desync-repeats=").and_then(|v| v.parse().ok()).unwrap_or(1u32) } else { 0 };
            let splits = get(&r, "--dpi-desync-split-pos=").map_or(0, |v| v.split(',').count() as u32);
            let overlap = u32::from(get(&r, "--dpi-desync-split-seqovl=").is_some());
            fakes * 2 + splits + overlap * 2
        })
        .sum()
}

/// Variations of a recipe, one setting at a time.
fn mutations(recipe: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let replace = |key: &str, value: &str| -> Vec<String> {
        recipe.iter().map(|t| if t.starts_with(key) { format!("{key}{value}") } else { t.clone() }).collect()
    };
    if let Some(r) = get(recipe, "--dpi-desync-repeats=").and_then(|r| r.parse::<u32>().ok()) {
        for n in [r.saturating_sub(3).max(2), (r + 4).min(16)] {
            if n != r {
                out.push(replace("--dpi-desync-repeats=", &n.to_string()));
            }
        }
    }
    if let Some(f) = get(recipe, "--dpi-desync-fooling=") {
        for alt in ["ts", "md5sig", "badseq"] {
            if alt != f {
                out.push(replace("--dpi-desync-fooling=", alt));
            }
        }
    }
    if let Some(p) = get(recipe, "--dpi-desync-split-pos=") {
        for alt in ["1", "2", "sniext+1", "midsld"] {
            if alt != p {
                out.push(replace("--dpi-desync-split-pos=", alt));
            }
        }
    }
    if let Some(o) = get(recipe, "--dpi-desync-split-seqovl=") {
        for alt in ["568", "681", "652"] {
            if alt != o {
                out.push(replace("--dpi-desync-split-seqovl=", alt));
            }
        }
    }
    for key in ["--dpi-desync-fake-tls=", "--dpi-desync-split-seqovl-pattern="] {
        if let Some(cur) = get(recipe, key) {
            for f in TLS_FAKES {
                if !cur.ends_with(f) {
                    out.push(replace(key, &format!("%BIN%{f}")));
                }
            }
        }
    }
    out
}

fn named(i: usize, recipe: &[String], base: &Strategy, template: Vec<String>) -> Strategy {
    Strategy::from_template(&format!("#{} · {}", i, describe(recipe)), Some(format!("Built from {}", base.name)), Origin::Builtin, template)
}

/// Stage 1 candidates: `base` with its own web settings first, then with those of every
/// strategy in `pool` (normally all built-in ones).
pub fn candidates(base: &Strategy, pool: &[Strategy]) -> Vec<Strategy> {
    let Some(own) = web_recipe(base) else { return Vec::new() };
    let mut recipes: Vec<Vec<String>> = vec![own];
    recipes.extend(pool.iter().filter_map(web_recipe));
    let mut seen = HashSet::new();
    recipes.retain(|r| seen.insert(r.clone()));
    recipes.truncate(MAX_CANDIDATES);
    recipes.iter().enumerate().map(|(i, r)| named(i + 1, r, base, with_recipe(base, r))).collect()
}

/// Stage 2 variations of the best candidates (taken in turn, so each finalist gets some),
/// skipping anything already tested. Numbering continues after `offset`.
pub fn refine(top: &[Strategy], tested: &[Vec<String>], offset: usize) -> Vec<Strategy> {
    let mut seen: HashSet<Vec<String>> = tested.iter().cloned().collect();
    seen.extend(top.iter().map(|s| s.template().to_vec()));
    let per: Vec<(usize, Vec<Vec<String>>)> =
        top.iter().enumerate().filter_map(|(i, s)| web_recipe(s).map(|r| (i, mutations(&r)))).collect();
    let mut out = Vec::new();
    let mut round = 0;
    while out.len() < REFINE_LIMIT && per.iter().any(|(_, m)| round < m.len()) {
        for (i, m) in &per {
            let Some(r) = m.get(round) else { continue };
            let template = with_recipe(&top[*i], r);
            if seen.insert(template.clone()) && out.len() < REFINE_LIMIT {
                out.push(named(offset + out.len() + 1, r, &top[*i], template));
            }
        }
        round += 1;
    }
    out
}

// ───────────────────────────── composing by hand ─────────────────────────────

/// Desync methods offered in the Studio, as winws spells them.
pub const METHODS: [&str; 8] = ["multisplit", "fake,multisplit", "fakedsplit", "fake,fakedsplit", "multidisorder", "fake,multidisorder", "hostfakesplit", "fake,hostfakesplit"];
pub const FOOLINGS: [&str; 4] = ["none", "ts", "md5sig", "badseq"];

/// Web-traffic settings chosen in the Studio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSpec {
    pub method: String,
    pub split_pos: String,
    /// 0 = no sequence overlap.
    pub seqovl: u32,
    /// `none` or a fooling method.
    pub fooling: String,
    /// Fake packets per connection (for methods with `fake`).
    pub repeats: u32,
    /// File in `bin/` used for the fake ClientHello and the overlap pattern.
    pub fake_file: String,
    /// Host shown in hostfakesplit's fake part.
    pub fake_host: String,
    /// QUIC fake repeats (0 = keep the base strategy's value).
    pub quic_repeats: u32,
    /// Discord voice fake repeats (0 = keep the base strategy's value).
    pub voice_repeats: u32,
}

impl Default for WebSpec {
    fn default() -> Self {
        Self {
            method: "multisplit".into(),
            split_pos: "1".into(),
            seqovl: 568,
            fooling: "none".into(),
            repeats: 6,
            fake_file: TLS_FAKES[1].into(),
            fake_host: "www.google.com".into(),
            quic_repeats: 0,
            voice_repeats: 0,
        }
    }
}

impl WebSpec {
    /// The winws arguments for the web profiles.
    pub fn recipe(&self) -> Vec<String> {
        let m = self.method.as_str();
        let fake = m.contains("fake");
        let mut r = vec![format!("--dpi-desync={m}")];
        if m.contains("hostfakesplit") {
            r.push(format!("--dpi-desync-hostfakesplit-mod=host={},altorder=1", self.fake_host.trim()));
        } else {
            r.push(format!("--dpi-desync-split-pos={}", self.split_pos.trim()));
        }
        if self.seqovl > 0 && m.contains("multisplit") {
            r.push(format!("--dpi-desync-split-seqovl={}", self.seqovl));
            r.push(format!("--dpi-desync-split-seqovl-pattern=%BIN%{}", self.fake_file));
        }
        if self.fooling != "none" {
            r.push(format!("--dpi-desync-fooling={}", self.fooling));
        }
        if fake {
            r.push(format!("--dpi-desync-repeats={}", self.repeats.clamp(1, 20)));
            r.push(format!("--dpi-desync-fake-tls=%BIN%{}", self.fake_file));
        }
        r
    }

    /// Problems that would make winws refuse the settings (empty = fine).
    pub fn problems(&self) -> Vec<&'static str> {
        let mut p = Vec::new();
        if !METHODS.contains(&self.method.as_str()) {
            p.push("Unknown method.");
        }
        let pos_ok = self.split_pos.split(',').all(|x| {
            let x = x.trim();
            !x.is_empty() && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-')
        });
        if !self.method.contains("hostfakesplit") && !pos_ok {
            p.push("Split position: use numbers or markers like 1, 2, sniext+1, midsld (comma separated).");
        }
        if self.seqovl > 2000 {
            p.push("Overlap must be at most 2000 bytes.");
        }
        if !FOOLINGS.contains(&self.fooling.as_str()) {
            p.push("Unknown fooling method.");
        }
        if !TLS_FAKES.contains(&self.fake_file.as_str()) {
            p.push("Unknown fake packet file.");
        }
        if self.method.contains("hostfakesplit") && !crate::userlists::is_domain(self.fake_host.trim()) {
            p.push("The fake host must be a domain name.");
        }
        p
    }

    /// Best-effort reading of a strategy's web settings (to start editing from it).
    pub fn from_strategy(s: &Strategy) -> Self {
        let mut spec = Self::default();
        let Some(r) = web_recipe(s) else { return spec };
        if let Some(m) = get(&r, "--dpi-desync=").filter(|m| METHODS.contains(m)) {
            spec.method = m.to_owned();
        }
        if let Some(p) = get(&r, "--dpi-desync-split-pos=") {
            spec.split_pos = p.to_owned();
        }
        spec.seqovl = get(&r, "--dpi-desync-split-seqovl=").and_then(|v| v.parse().ok()).unwrap_or(0);
        spec.fooling = get(&r, "--dpi-desync-fooling=").filter(|f| FOOLINGS.contains(f)).unwrap_or("none").to_owned();
        if let Some(n) = get(&r, "--dpi-desync-repeats=").and_then(|v| v.parse().ok()) {
            spec.repeats = n;
        }
        let file = get(&r, "--dpi-desync-fake-tls=").or_else(|| get(&r, "--dpi-desync-split-seqovl-pattern="));
        if let Some(f) = file.and_then(|f| TLS_FAKES.iter().find(|x| f.ends_with(*x))) {
            spec.fake_file = (*f).to_owned();
        }
        if let Some(h) = get(&r, "--dpi-desync-hostfakesplit-mod=host=") {
            spec.fake_host = h.split(',').next().unwrap_or("www.google.com").to_owned();
        }
        spec
    }

    /// `base` with these settings applied.
    pub fn compose(&self, base: &Strategy, name: &str) -> Strategy {
        let recipe = self.recipe();
        let set_repeats = |p: &[String], n: u32| -> Vec<String> {
            p.iter().map(|t| if t.starts_with("--dpi-desync-repeats=") { format!("--dpi-desync-repeats={n}") } else { t.clone() }).collect()
        };
        let profiles: Vec<Vec<String>> = split_profiles(base.template())
            .into_iter()
            .map(|p| {
                if is_web_profile(&p) {
                    let mut kept: Vec<String> = p.into_iter().filter(|t| !is_desync_arg(t)).collect();
                    kept.extend(recipe.iter().cloned());
                    kept
                } else if is_quic_profile(&p) && self.quic_repeats > 0 {
                    set_repeats(&p, self.quic_repeats.min(20))
                } else if is_voice_profile(&p) && self.voice_repeats > 0 {
                    set_repeats(&p, self.voice_repeats.min(20))
                } else {
                    p
                }
            })
            .collect();
        Strategy::from_template(name, Some("Studio".into()), Origin::Builtin, join_profiles(&profiles))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::builtin_strategies;

    #[test]
    fn builtin_strategies_have_web_recipes() {
        // ALT5 (not recommended upstream) has one catch-all profile instead of a web profile
        for s in builtin_strategies().iter().filter(|s| s.name != "general (ALT5)") {
            assert!(web_recipe(s).is_some(), "{}", s.name);
        }
    }

    #[test]
    fn candidates_only_change_the_web_profiles() {
        let all = builtin_strategies();
        let base = all.iter().find(|s| s.name == "general (ALT13)").unwrap();
        let cands = candidates(base, &all);
        assert!(cands.len() > 8 && cands.len() <= MAX_CANDIDATES, "{}", cands.len());
        assert_eq!(cands[0].template(), base.template(), "the first candidate is the base itself");
        let base_profiles = split_profiles(base.template());
        for c in &cands {
            let profiles = split_profiles(c.template());
            assert_eq!(profiles.len(), base_profiles.len(), "{}", c.name);
            for (a, b) in profiles.iter().zip(&base_profiles) {
                if !is_web_profile(b) {
                    assert_eq!(a, b, "non-web profile changed in {}", c.name);
                } else {
                    let keep = |p: &Vec<String>| p.iter().filter(|t| !is_desync_arg(t)).cloned().collect::<Vec<_>>();
                    assert_eq!(keep(a), keep(b));
                }
            }
        }
        let distinct: HashSet<_> = cands.iter().map(|c| c.template().to_vec()).collect();
        assert_eq!(distinct.len(), cands.len(), "candidates are distinct");
    }

    #[test]
    fn refinement_varies_each_finalist_and_skips_tested() {
        let all = builtin_strategies();
        let base = all.iter().find(|s| s.name == "general").unwrap();
        let stage1 = candidates(base, &all);
        let tested: Vec<Vec<String>> = stage1.iter().map(|s| s.template().to_vec()).collect();
        let top = &stage1[..3];
        let more = refine(top, &tested, stage1.len());
        assert!(!more.is_empty() && more.len() <= REFINE_LIMIT);
        for m in &more {
            assert!(!tested.contains(&m.template().to_vec()), "{} was already tested", m.name);
        }
        assert!(more[0].name.starts_with(&format!("#{} ", stage1.len() + 1)), "{}", more[0].name);
    }

    #[test]
    fn gentler_strategies_have_a_smaller_footprint() {
        let all = builtin_strategies();
        let by = |n: &str| all.iter().find(|s| s.name == n).unwrap();
        // ALT13: fake,hostfakesplit ×5 vs general: multisplit without fakes
        assert!(footprint(by("general")) < footprint(by("general (ALT13)")));
    }

    #[test]
    fn composed_strategy_applies_web_quic_and_voice_settings() {
        let all = builtin_strategies();
        let base = all.iter().find(|s| s.name == "general").unwrap();
        let spec = WebSpec {
            method: "fake,multisplit".into(),
            split_pos: "2".into(),
            seqovl: 681,
            fooling: "ts".into(),
            repeats: 8,
            quic_repeats: 9,
            voice_repeats: 4,
            ..WebSpec::default()
        };
        assert!(spec.problems().is_empty());
        let s = spec.compose(base, BUILT_NAME);
        let r = web_recipe(&s).unwrap();
        assert_eq!(describe(&r), "fake,multisplit · ts · pos 2 · seqovl 681 · ×8");
        let profiles = split_profiles(s.template());
        assert!(profiles.iter().filter(|p| is_quic_profile(p)).all(|p| p.contains(&"--dpi-desync-repeats=9".to_owned())));
        assert!(profiles.iter().filter(|p| is_voice_profile(p)).all(|p| p.contains(&"--dpi-desync-repeats=4".to_owned())));
        // and it reads back
        let back = WebSpec::from_strategy(&s);
        assert_eq!((back.method.as_str(), back.split_pos.as_str(), back.seqovl, back.repeats), ("fake,multisplit", "2", 681, 8));
        let bad = WebSpec { split_pos: "one two".into(), fooling: "x".into(), ..WebSpec::default() };
        assert_eq!(bad.problems().len(), 2);
    }

    #[test]
    fn saved_strategy_round_trips_through_a_batch_file() {
        let all = builtin_strategies();
        let c = &candidates(&all[0], &all)[3];
        let bat = c.to_bat("Auto-built");
        let back = Strategy::parse(BUILT_NAME, &bat, Origin::Builtin).unwrap();
        assert_eq!(back.template(), c.template());
        assert_eq!(back.note.as_deref(), Some("Auto-built"));
    }
}
