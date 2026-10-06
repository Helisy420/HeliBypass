//! Protocol constants and the static Telegram data-center tables.

pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8;
pub const PREKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xEF; 4];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xEE; 4];
pub const PROTO_TAG_SECURE: [u8; 4] = [0xDD; 4];

pub const PROTO_ABRIDGED_INT: u32 = 0xEFEF_EFEF;
pub const PROTO_INTERMEDIATE_INT: u32 = 0xEEEE_EEEE;
pub const PROTO_PADDED_INTERMEDIATE_INT: u32 = 0xDDDD_DDDD;

/// First bytes that would make the obfuscated init look like another protocol.
pub const RESERVED_FIRST_BYTE: u8 = 0xEF;
pub const RESERVED_STARTS: [[u8; 4]; 6] = [
    *b"HEAD",
    *b"POST",
    *b"GET ",
    [0xEE; 4],
    [0xDD; 4],
    [0x16, 0x03, 0x01, 0x02],
];
pub const RESERVED_CONTINUE: [u8; 4] = [0; 4];

pub const WS_PATH: &str = "/apiws";
pub const WS_PATH_TEST: &str = "/apiws_test";

/// SNI used to reach Telegram's WebSocket gateways when the plain SNI is filtered.
pub const FRONTING_SNI: &str = "sprinthost.ru";

pub const DC_DEFAULT_IPS: &[(u32, &str)] = &[
    (1, "149.154.175.50"),
    (2, "149.154.167.51"),
    (3, "149.154.175.100"),
    (4, "149.154.167.91"),
    (5, "149.154.171.5"),
    (203, "91.105.192.100"),
];

pub const DC_TEST_IPS: &[(u32, &str)] = &[
    (1, "149.154.175.10"),
    (2, "149.154.167.40"),
    (3, "149.154.175.117"),
];

pub fn default_dc_ip(dc: u32, test: bool) -> Option<&'static str> {
    let table = if test { DC_TEST_IPS } else { DC_DEFAULT_IPS };
    table.iter().find(|(d, _)| *d == dc).map(|(_, ip)| *ip)
}

/// WebSocket gateway host names for a DC (media DCs have a dedicated `-1` host).
pub fn ws_domains(dc: u32, is_media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    if is_media {
        vec![format!("kws{dc}-1.web.telegram.org"), format!("kws{dc}.web.telegram.org")]
    } else {
        vec![format!("kws{dc}.web.telegram.org")]
    }
}

pub fn human_bytes(n: u64) -> String {
    let mut v = n as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if v.abs() < 1024.0 {
            return format!("{v:.1}{unit}");
        }
        v /= 1024.0;
    }
    format!("{v:.1}TB")
}
