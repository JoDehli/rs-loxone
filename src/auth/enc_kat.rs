//! Known-answer tests: AES-256-CBC with PKCS#7 padding on a fixed key, IV and plaintext.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::enc::EncCipher;
use super::keyexchange::{AES_KEY_LEN, IV_LEN, SessionKey};

#[test]
fn encrypted_payload_known_answer() {
    let key: [u8; AES_KEY_LEN] = std::array::from_fn(|i| i as u8);
    let iv: [u8; IV_LEN] = std::array::from_fn(|i| 0xa0 + i as u8);
    let session = SessionKey::from_parts_for_test(key, iv);
    let cipher = EncCipher::new(&session, "0123456789abcdef0123456789abcdef");

    // first
    let plain = "salt/0123456789abcdef0123456789abcdef/jdev/sps/io/AI1/on\0";
    let got = STANDARD.encode(cipher.encrypt_plain(plain.as_bytes()));
    assert_eq!(
        got,
        "LGcBGEHsWcR5nAHRfefiuJozBFD3+2nJN9v9zEH4TzWLPfqFdbdBeCdS64+pecsEJTu/hOoyySG6qX2wPs3CVQ==",
        "first"
    );
    // rotated
    let plain = "nextSalt/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210/jdev/sps/io/AI1/on\0";
    let got = STANDARD.encode(cipher.encrypt_plain(plain.as_bytes()));
    assert_eq!(
        got,
        "2Y7VCecj6GMVXip+49ierYYDxpFRkhez+SCRJGmzwKLpwnIV3gK1tEK5CNe4tx/wvptSNvc75R8ZDu98sbJbloz+wTp+Buwfe10G0OmpGuhHPo+PmBU+oQwwodGrnSQs",
        "rotated"
    );
    // block_aligned
    let plain = "0123456789abcdef";
    let got = STANDARD.encode(cipher.encrypt_plain(plain.as_bytes()));
    assert_eq!(
        got, "zhzzpOO4exObo8/xCs41tgbZay4YS/Irc9MbpL4U2Mk=",
        "block_aligned"
    );
}
