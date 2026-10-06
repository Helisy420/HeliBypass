//! Picks which Cloudflare-proxied domain to use for each DC and remembers the last one that worked.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::prelude::IndexedRandom;
use rand::seq::SliceRandom;

const DCS: [u32; 6] = [1, 2, 3, 4, 5, 203];

#[derive(Default)]
struct State {
    domains: Vec<String>,
    dc_to_domain: HashMap<u32, String>,
}

#[derive(Default)]
pub struct Balancer {
    state: Mutex<State>,
}

impl Balancer {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn update_domains_list(&self, list: &[String]) {
        let mut s = self.lock();
        let mut a = s.domains.clone();
        let mut b = list.to_vec();
        a.sort();
        b.sort();
        if a == b {
            return;
        }
        s.domains = list.to_vec();
        let mut rng = rand::rng();
        let domains = s.domains.clone();
        s.dc_to_domain =
            DCS.iter().filter_map(|dc| domains.choose(&mut rng).map(|d| (*dc, d.clone()))).collect();
    }

    /// Returns `true` when the active domain for `dc` actually changed.
    pub fn update_domain_for_dc(&self, dc: u32, domain: &str) -> bool {
        let mut s = self.lock();
        if s.dc_to_domain.get(&dc).is_some_and(|d| d == domain) {
            return false;
        }
        s.dc_to_domain.insert(dc, domain.to_owned());
        true
    }

    /// The current domain for `dc` first, then every other one in random order.
    pub fn domains_for_dc(&self, dc: u32) -> Vec<String> {
        let s = self.lock();
        let current = s.dc_to_domain.get(&dc).cloned();
        let mut rest: Vec<String> = s.domains.iter().filter(|d| Some(*d) != current.as_ref()).cloned().collect();
        rest.shuffle(&mut rand::rng());
        current.into_iter().chain(rest).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().domains.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_domain_comes_first_and_updates() {
        let b = Balancer::default();
        let list: Vec<String> = ["a.example", "b.example", "c.example"].iter().map(|s| s.to_string()).collect();
        b.update_domains_list(&list);
        let order = b.domains_for_dc(2);
        assert_eq!(order.len(), 3);
        let other = order[1].clone(); // differs from the current (first) domain
        assert!(b.update_domain_for_dc(2, &other));
        assert!(!b.update_domain_for_dc(2, &other));
        assert_eq!(b.domains_for_dc(2)[0], other);
        // same set in different order is not a change
        let before = b.domains_for_dc(1)[0].clone();
        b.update_domains_list(&["c.example".into(), "b.example".into(), "a.example".into()]);
        assert_eq!(b.domains_for_dc(1)[0], before);
    }
}
