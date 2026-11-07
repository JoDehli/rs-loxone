//! Known-answer vectors for the UUID text form, from fixed random bytes (seed 1234).

use rs_loxone::protocol::Uuid;

#[test]
fn uuid_known_answers() {
    let vectors: &[(&str, &str)] = &[
        (
            "e13b032e112a32b579080f08b1f7ed4c",
            "2e033be1-2a11-b532-79080f08b1f7ed4c",
        ),
        (
            "2e5d3a07f97f21ee232d178a209af6b5",
            "073a5d2e-7ff9-ee21-232d178a209af6b5",
        ),
        (
            "887f66e8092402aa49f2c1551b27fe53",
            "e8667f88-2409-aa02-49f2c1551b27fe53",
        ),
        (
            "266e490db138489ce814d58d145a8b4f",
            "0d496e26-38b1-9c48-e814d58d145a8b4f",
        ),
        (
            "994fed15c5b2fdaeeff317f157e1e097",
            "15ed4f99-b2c5-aefd-eff317f157e1e097",
        ),
        (
            "8c3f5fd5df3d34f8c08262b03750894f",
            "d55f3f8c-3ddf-f834-c08262b03750894f",
        ),
        (
            "a5e42428ca6d189213702ca29ceb2183",
            "2824e4a5-6dca-9218-13702ca29ceb2183",
        ),
        (
            "25da6733cb63eb78b869d759689a1eb4",
            "3367da25-63cb-78eb-b869d759689a1eb4",
        ),
        (
            "4efff1aa474318544a23a657001f2c4b",
            "aaf1ff4e-4347-5418-4a23a657001f2c4b",
        ),
        (
            "6f14ddc8a66ac38f9bd8a34d2f858ed2",
            "c8dd146f-6aa6-8fc3-9bd8a34d2f858ed2",
        ),
    ];
    for (raw_hex, text) in vectors {
        let raw: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&raw_hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let uuid = Uuid::try_from(raw.as_slice()).unwrap();
        assert_eq!(uuid.to_string(), *text, "bytes {raw_hex}");
        let parsed: Uuid = text.parse().unwrap();
        assert_eq!(parsed, uuid, "text {text}");
    }
}
