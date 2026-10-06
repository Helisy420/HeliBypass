//! MTProto transport obfuscation ("obfuscated2") primitives.
//!
//! The proxy terminates the client's obfuscated stream, picks the target DC from the
//! handshake and re-encrypts everything towards Telegram with a fresh, self-generated
//! relay init. This module is a byte-exact port of the Python reference.

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

use crate::consts::*;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::fill(&mut out);
    out
}

pub fn new_ctr(key: &[u8], iv: &[u8]) -> Aes256Ctr {
    Aes256Ctr::new_from_slices(key, iv).expect("AES-256-CTR needs a 32 byte key and 16 byte iv")
}

/// Result of a successfully decoded client init packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub dc: u32,
    pub is_media: bool,
    pub proto_tag: [u8; 4],
    /// `prekey || iv` (48 bytes) of the client's "decrypt" direction.
    pub prekey_iv: [u8; PREKEY_LEN + IV_LEN],
}

impl Handshake {
    pub fn proto_int(&self) -> u32 {
        match self.proto_tag {
            PROTO_TAG_ABRIDGED => PROTO_ABRIDGED_INT,
            PROTO_TAG_INTERMEDIATE => PROTO_INTERMEDIATE_INT,
            _ => PROTO_PADDED_INTERMEDIATE_INT,
        }
    }
}

/// Validate the 64 byte client init against `secret`. `None` means wrong secret/protocol.
pub fn try_handshake(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8; 16]) -> Option<Handshake> {
    let prekey_iv: [u8; PREKEY_LEN + IV_LEN] =
        handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN].try_into().ok()?;
    let (prekey, iv) = prekey_iv.split_at(PREKEY_LEN);

    let mut hasher = Sha256::new();
    hasher.update(prekey);
    hasher.update(secret);
    let dec_key = hasher.finalize();

    let mut decrypted = *handshake;
    new_ctr(&dec_key, iv).apply_keystream(&mut decrypted);

    let tag: [u8; 4] = decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().ok()?;
    if tag != PROTO_TAG_ABRIDGED && tag != PROTO_TAG_INTERMEDIATE && tag != PROTO_TAG_SECURE {
        return None;
    }
    let dc_idx = i16::from_le_bytes([decrypted[DC_IDX_POS], decrypted[DC_IDX_POS + 1]]);
    Some(Handshake {
        dc: u32::from(dc_idx.unsigned_abs()),
        is_media: dc_idx < 0,
        proto_tag: tag,
        prekey_iv,
    })
}

/// Build the 64 byte init that is sent to Telegram (plain obfuscated2, no secret).
pub fn generate_relay_init(proto_tag: [u8; 4], dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    generate_relay_init_from(proto_tag, dc_idx, || random_bytes::<HANDSHAKE_LEN>(), || random_bytes::<2>())
}

/// Same as [`generate_relay_init`] with injectable randomness (used for deterministic tests).
pub fn generate_relay_init_from(
    proto_tag: [u8; 4],
    dc_idx: i16,
    mut next_init: impl FnMut() -> [u8; HANDSHAKE_LEN],
    mut next_pad: impl FnMut() -> [u8; 2],
) -> [u8; HANDSHAKE_LEN] {
    let rnd = loop {
        let candidate = next_init();
        if candidate[0] == RESERVED_FIRST_BYTE {
            continue;
        }
        if RESERVED_STARTS.iter().any(|s| candidate[..4] == s[..]) {
            continue;
        }
        if candidate[4..8] == RESERVED_CONTINUE {
            continue;
        }
        break candidate;
    };

    let enc_key = &rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let enc_iv = &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let mut encrypted_full = rnd;
    new_ctr(enc_key, enc_iv).apply_keystream(&mut encrypted_full);

    let pad = next_pad();
    let mut tail_plain = [0u8; 8];
    tail_plain[..4].copy_from_slice(&proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    tail_plain[6..8].copy_from_slice(&pad);

    let mut result = rnd;
    for i in 0..8 {
        // keystream byte = encrypted ^ plain at positions 56..64
        let keystream = encrypted_full[56 + i] ^ rnd[56 + i];
        result[56 + i] = tail_plain[i] ^ keystream;
    }
    result
}

/// The four AES-CTR states needed to bridge a client stream to Telegram.
pub struct CryptoCtx {
    /// decrypts data coming from the client
    pub clt_dec: Aes256Ctr,
    /// encrypts data going to the client
    pub clt_enc: Aes256Ctr,
    /// encrypts data going to Telegram
    pub tg_enc: Aes256Ctr,
    /// decrypts data coming from Telegram
    pub tg_dec: Aes256Ctr,
}

pub fn build_crypto_ctx(
    client_prekey_iv: &[u8; PREKEY_LEN + IV_LEN],
    secret: &[u8; 16],
    relay_init: &[u8; HANDSHAKE_LEN],
) -> CryptoCtx {
    // client side: key = SHA256(prekey || secret)
    let (dec_prekey, dec_iv) = client_prekey_iv.split_at(PREKEY_LEN);
    let clt_dec_key = sha256_two(dec_prekey, secret);

    let mut reversed = *client_prekey_iv;
    reversed.reverse();
    let (enc_prekey, enc_iv) = reversed.split_at(PREKEY_LEN);
    let clt_enc_key = sha256_two(enc_prekey, secret);

    let mut clt_dec = new_ctr(&clt_dec_key, dec_iv);
    let clt_enc = new_ctr(&clt_enc_key, enc_iv);
    // fast-forward past the 64 byte init the client already sent
    skip(&mut clt_dec, HANDSHAKE_LEN);

    // relay side: plain obfuscation, raw key
    let relay_enc_key = &relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let relay_enc_iv = &relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let mut relay_dec = [0u8; PREKEY_LEN + IV_LEN];
    relay_dec.copy_from_slice(&relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    relay_dec.reverse();
    let (relay_dec_key, relay_dec_iv) = relay_dec.split_at(KEY_LEN);

    let mut tg_enc = new_ctr(relay_enc_key, relay_enc_iv);
    let tg_dec = new_ctr(relay_dec_key, relay_dec_iv);
    skip(&mut tg_enc, HANDSHAKE_LEN);

    CryptoCtx { clt_dec, clt_enc, tg_enc, tg_dec }
}

fn sha256_two(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn skip(cipher: &mut Aes256Ctr, n: usize) {
    let mut zeros = vec![0u8; n];
    cipher.apply_keystream(&mut zeros);
}

/// Splits a stream of (relay-encrypted) MTProto transport packets so that each one can be
/// sent as its own WebSocket frame. Telegram's gateways expect one packet per frame.
pub struct MsgSplitter {
    dec: Aes256Ctr,
    proto: u32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

impl MsgSplitter {
    pub fn new(relay_init: &[u8; HANDSHAKE_LEN], proto: u32) -> Self {
        let mut dec = new_ctr(&relay_init[8..40], &relay_init[40..56]);
        skip(&mut dec, HANDSHAKE_LEN);
        Self { dec, proto, cipher_buf: Vec::new(), plain_buf: Vec::new(), disabled: false }
    }

    /// Feed relay-encrypted bytes; returns the complete packets now available.
    pub fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![chunk.to_vec()];
        }
        self.cipher_buf.extend_from_slice(chunk);
        let start = self.plain_buf.len();
        self.plain_buf.extend_from_slice(chunk);
        self.dec.apply_keystream(&mut self.plain_buf[start..]);

        let mut parts = Vec::new();
        let mut offset = 0;
        let buf_len = self.cipher_buf.len();
        while offset < buf_len {
            match self.next_packet_len(offset, buf_len - offset) {
                None => break,
                Some(0) => {
                    // unknown framing: give up on splitting and pass everything through
                    parts.push(self.cipher_buf[offset..].to_vec());
                    offset = buf_len;
                    self.disabled = true;
                    break;
                }
                Some(len) => {
                    parts.push(self.cipher_buf[offset..offset + len].to_vec());
                    offset += len;
                }
            }
        }
        if offset > 0 {
            self.cipher_buf.drain(..offset);
            self.plain_buf.drain(..offset);
        }
        parts
    }

    /// Whatever is left when the client closed mid-packet.
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return None;
        }
        self.plain_buf.clear();
        Some(std::mem::take(&mut self.cipher_buf))
    }

    fn next_packet_len(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail == 0 {
            return None;
        }
        match self.proto {
            PROTO_ABRIDGED_INT => self.abridged_len(offset, avail),
            PROTO_INTERMEDIATE_INT | PROTO_PADDED_INTERMEDIATE_INT => self.intermediate_len(offset, avail),
            _ => Some(0),
        }
    }

    fn abridged_len(&self, offset: usize, avail: usize) -> Option<usize> {
        let first = self.plain_buf[offset];
        let (header_len, payload_len) = if first == 0x7F || first == 0xFF {
            if avail < 4 {
                return None;
            }
            let b = &self.plain_buf[offset + 1..offset + 4];
            (4, (u32::from_le_bytes([b[0], b[1], b[2], 0]) as usize) * 4)
        } else {
            (1, ((first & 0x7F) as usize) * 4)
        };
        if payload_len == 0 {
            return Some(0);
        }
        let packet_len = header_len + payload_len;
        if avail < packet_len { None } else { Some(packet_len) }
    }

    fn intermediate_len(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail < 4 {
            return None;
        }
        let b = &self.plain_buf[offset..offset + 4];
        let payload_len = (u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x7FFF_FFFF) as usize;
        if payload_len == 0 {
            return Some(0);
        }
        let packet_len = 4 + payload_len;
        if avail < packet_len { None } else { Some(packet_len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_roundtrip() {
        // Build a client init exactly the way a Telegram client would for DC2/media.
        let secret: [u8; 16] = *b"0123456789abcdef";
        let prekey_iv: [u8; 48] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let mut init = [0u8; 64];
        init[8..56].copy_from_slice(&prekey_iv);
        // plain tail: tag + dc_idx(-2) + padding
        let mut plain = init;
        plain[56..60].copy_from_slice(&PROTO_TAG_INTERMEDIATE);
        plain[60..62].copy_from_slice(&(-2i16).to_le_bytes());

        let key = sha256_two(&prekey_iv[..32], &secret);
        let mut enc = plain;
        new_ctr(&key, &prekey_iv[32..]).apply_keystream(&mut enc);
        // only the tail is encrypted in a real init, the first 56 bytes stay as generated
        init[56..].copy_from_slice(&enc[56..]);

        let hs = try_handshake(&init, &secret).expect("valid handshake");
        assert_eq!(hs.dc, 2);
        assert!(hs.is_media);
        assert_eq!(hs.proto_tag, PROTO_TAG_INTERMEDIATE);
        assert_eq!(hs.proto_int(), PROTO_INTERMEDIATE_INT);

        let wrong: [u8; 16] = *b"fedcba9876543210";
        assert!(try_handshake(&init, &wrong).is_none());
    }

    #[test]
    fn relay_init_is_decodable_by_telegram() {
        // Telegram decodes the init with the plain key/iv found at bytes 8..56.
        let init = generate_relay_init(PROTO_TAG_ABRIDGED, 4);
        let mut dec = init;
        new_ctr(&init[8..40], &init[40..56]).apply_keystream(&mut dec);
        assert_eq!(&dec[56..60], &PROTO_TAG_ABRIDGED);
        assert_eq!(i16::from_le_bytes([dec[60], dec[61]]), 4);
        assert_ne!(init[0], RESERVED_FIRST_BYTE);
    }

    #[test]
    fn splitter_cuts_abridged_packets() {
        let init = generate_relay_init(PROTO_TAG_ABRIDGED, 2);
        // Packets as the client would send them *after* tg_enc, encrypted with the same stream.
        let mut enc = new_ctr(&init[8..40], &init[40..56]);
        skip(&mut enc, HANDSHAKE_LEN);

        let p1: Vec<u8> = [vec![2u8], vec![1u8; 8]].concat(); // 2 words = 8 bytes payload
        let p2: Vec<u8> = [vec![3u8], vec![2u8; 12]].concat();
        let mut stream = [p1.clone(), p2.clone()].concat();
        enc.apply_keystream(&mut stream);

        let mut splitter = MsgSplitter::new(&init, PROTO_ABRIDGED_INT);
        // deliver in awkward slices
        let mut parts = splitter.split(&stream[..4]);
        assert!(parts.is_empty());
        parts.extend(splitter.split(&stream[4..15]));
        parts.extend(splitter.split(&stream[15..]));
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), p1.len());
        assert_eq!(parts[1].len(), p2.len());
        assert_eq!([parts[0].clone(), parts[1].clone()].concat(), stream);
        assert!(splitter.flush().is_none());
    }
}
