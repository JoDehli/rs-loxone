//! Known-answer vectors for the credential, token and secured-command hashes, on fixed inputs.

use rs_loxone::auth::{HashAlg, KeyAndSalt, Secret, hash};

fn ks(key: &str, salt: &str, alg: &str) -> KeyAndSalt {
    KeyAndSalt {
        key: Secret::new(key),
        salt: salt.to_owned(),
        hash_alg: HashAlg::parse(alg).unwrap(),
    }
}

#[test]
fn hashes_known_answers() {
    // credential SHA1
    assert_eq!(
        hash::credential_hash(
            "admin",
            "s3cret!",
            &ks(
                "00112233445566778899aabbccddeeff00112233",
                "a1b2c3d4",
                "SHA1"
            )
        )
        .unwrap(),
        "351f7ce72566320ebf366f8517456941fda607eb"
    );
    // token SHA1
    assert_eq!(
        hash::token_hash(
            "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig",
            &ks("00112233445566778899aabbccddeeff00112233", "", "SHA1")
        )
        .unwrap(),
        "04584dc0fd521973d4bf913e1b2d1e48a673f55e"
    );
    // visual SHA1
    assert_eq!(
        hash::visual_hash(
            "1234",
            &ks(
                "00112233445566778899aabbccddeeff00112233",
                "5f6e7d8c",
                "SHA1"
            )
        )
        .unwrap(),
        "bd4b4e560b0f04d1ad2cba805573089332b84bd7"
    );
    // credential SHA256
    assert_eq!(
        hash::credential_hash(
            "admin",
            "s3cret!",
            &ks(
                "00112233445566778899aabbccddeeff001122330011223344556677",
                "a1b2c3d4",
                "SHA256"
            )
        )
        .unwrap(),
        "562bda332d982392d80c198d7f4792f6b502b5d02fcb50399329978e825a5062"
    );
    // token SHA256
    assert_eq!(
        hash::token_hash(
            "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig",
            &ks(
                "00112233445566778899aabbccddeeff001122330011223344556677",
                "",
                "SHA256"
            )
        )
        .unwrap(),
        "f8c3d8aa2adf0585edaef1c3600a1d501dc6c821ab722c2cb5d12f76d5b2102b"
    );
    // visual SHA256
    assert_eq!(
        hash::visual_hash(
            "1234",
            &ks(
                "00112233445566778899aabbccddeeff001122330011223344556677",
                "5f6e7d8c",
                "SHA256"
            )
        )
        .unwrap(),
        "e9efff5e812cecf6840a81e106701e3d3de31db7a81879b17f2543a8b30851c3"
    );
}
