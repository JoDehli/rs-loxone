//! Command strings for the auth flow. Each function returns the text to send;
//! encryption (`jdev/sys/enc/`) is applied by the caller through
//! [`super::enc::EncCipher`].

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use super::AuthError;

/// Token permission for the web interface.
pub const TOKEN_PERMISSION: u8 = 2;
/// Client UUID sent with `getjwt`/`gettoken`.
pub const TOKEN_UUID: &str = "edfc5f9a-df3f-4cad-9dddcdc42c732b82";
/// Client info sent with `getjwt`/`gettoken`.
pub const TOKEN_INFO: &str = "pyloxone_api";
/// First firmware that uses JSON web tokens (`[10, 2, 0]`).
pub const JWT_MIN_VERSION: [u32; 3] = [10, 2, 0];

/// RFC 3986 unreserved characters are kept; everything else is percent-encoded.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Parse a firmware version such as `"12.2.10.6"` into `[major, minor, patch]`.
pub fn parse_version(text: &str) -> Result<[u32; 3], AuthError> {
    crate::protocol::version::parse_version(text)
        .map_err(|_| AuthError::InvalidVersion(text.to_owned()))
}

/// True if the firmware uses JSON web tokens (`getjwt`/`refreshjwt`).
pub fn uses_jwt(version: [u32; 3]) -> bool {
    version >= JWT_MIN_VERSION
}

/// Percent-encode a username for a command path segment.
pub fn encode_user(user: &str) -> String {
    utf8_percent_encode(user, UNRESERVED).to_string()
}

/// `jdev/sys/getkey2/<user>`: fetch the user's key, salt and hash algorithm.
pub fn get_key2(user: &str) -> String {
    format!("jdev/sys/getkey2/{}", encode_user(user))
}

/// `jdev/sys/getkey`: fetch the key only (legacy flows).
pub fn get_key() -> &'static str {
    "jdev/sys/getkey"
}

/// `getjwt` (firmware >= 10.2) or `gettoken` (older), with a password hash.
pub fn request_token(version: [u32; 3], credential_hash: &str, user: &str) -> String {
    let verb = if uses_jwt(version) {
        "getjwt"
    } else {
        "gettoken"
    };
    format!(
        "jdev/sys/{verb}/{credential_hash}/{}/{TOKEN_PERMISSION}/{TOKEN_UUID}/{TOKEN_INFO}",
        encode_user(user)
    )
}

/// `authwithtoken/<tokenHash>/<user>`: log in with a stored token.
pub fn auth_with_token(token_hash: &str, user: &str) -> String {
    format!("authwithtoken/{token_hash}/{}", encode_user(user))
}

/// `refreshjwt` (firmware >= 10.2) or `refreshtoken` (older), with a token hash.
pub fn refresh_token(version: [u32; 3], token_hash: &str, user: &str) -> String {
    let verb = if uses_jwt(version) {
        "refreshjwt"
    } else {
        "refreshtoken"
    };
    format!("jdev/sys/{verb}/{token_hash}/{}", encode_user(user))
}

/// `checktoken/<token>/<user>`: check that a token is valid without renewing it.
///
/// Takes the plain token. Live testing on firmware 17.1.7 answered 200 for the
/// plain token and 401 for the hash, so the hash form is wrong here (the PDF allows
/// plain tokens from 11.2).
pub fn check_token(token: &str, user: &str) -> String {
    format!(
        "jdev/sys/checktoken/{}/{}",
        encode_user(token),
        encode_user(user)
    )
}

/// `killtoken/<token>/<user>`: revoke a token. Takes the plain token and the user name; both
/// segments are required (without the user name the Miniserver answers 400). No reply comes back.
pub fn kill_token(token: &str, user: &str) -> String {
    format!(
        "jdev/sys/killtoken/{}/{}",
        encode_user(token),
        encode_user(user)
    )
}

/// `jdev/sys/getvisusalt/<user>`: fetch the visualization-password key and salt.
pub fn get_visu_salt(user: &str) -> String {
    format!("jdev/sys/getvisusalt/{}", encode_user(user))
}

/// `jdev/sps/ios/<visualHash>/<uuid>/<value>`: a secured command.
pub fn secured_command(visual_hash: &str, uuid: &str, value: &str) -> String {
    format!("jdev/sps/ios/{visual_hash}/{uuid}/{value}")
}

/// `jdev/sps/checkuservisupwd/<hash>`: check a visualization code without running anything.
pub fn check_visu_password(visual_hash: &str) -> String {
    format!("jdev/sps/checkuservisupwd/{visual_hash}")
}

/// `jdev/sps/enablebinstatusupdate`: start receiving state updates.
pub fn enable_updates() -> &'static str {
    "jdev/sps/enablebinstatusupdate"
}

/// `keepalive`: sent every 30 s in plain text.
pub fn keepalive() -> &'static str {
    "keepalive"
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "abc123";

    #[test]
    fn version_gate_is_element_wise() {
        assert!(uses_jwt([10, 2, 0]));
        assert!(uses_jwt([11, 0, 0]));
        assert!(!uses_jwt([10, 1, 9]));
        assert!(!uses_jwt([9, 9, 9]));
        assert!(uses_jwt(parse_version("12.2.10.6").unwrap()));
    }

    #[test]
    fn parse_version_pads_and_rejects_garbage() {
        assert_eq!(parse_version("10.2").unwrap(), [10, 2, 0]);
        assert_eq!(parse_version("9.0.4").unwrap(), [9, 0, 4]);
        assert!(parse_version("ten.two").is_err());
    }

    #[test]
    fn get_key2_encodes_user() {
        assert_eq!(get_key2("admin"), "jdev/sys/getkey2/admin");
        assert_eq!(get_key2("a b/ü"), "jdev/sys/getkey2/a%20b%2F%C3%BC");
    }

    #[test]
    fn request_token_branches_on_version() {
        assert_eq!(
            request_token([10, 2, 0], HASH, "admin"),
            "jdev/sys/getjwt/abc123/admin/2/edfc5f9a-df3f-4cad-9dddcdc42c732b82/pyloxone_api"
        );
        assert_eq!(
            request_token([10, 1, 0], HASH, "admin"),
            "jdev/sys/gettoken/abc123/admin/2/edfc5f9a-df3f-4cad-9dddcdc42c732b82/pyloxone_api"
        );
    }

    #[test]
    fn refresh_branches_on_version() {
        assert_eq!(
            refresh_token([10, 2, 0], HASH, "admin"),
            "jdev/sys/refreshjwt/abc123/admin"
        );
        assert_eq!(
            refresh_token([10, 1, 0], HASH, "admin"),
            "jdev/sys/refreshtoken/abc123/admin"
        );
    }

    #[test]
    fn token_commands_have_expected_shapes() {
        assert_eq!(auth_with_token(HASH, "admin"), "authwithtoken/abc123/admin");
        assert_eq!(
            check_token("eyJ.a-b_c", "admin"),
            "jdev/sys/checktoken/eyJ.a-b_c/admin"
        );
        // Both segments are required: without the user name the Miniserver answers 400.
        assert_eq!(
            kill_token("eyJ.a-b_c", "admin"),
            "jdev/sys/killtoken/eyJ.a-b_c/admin"
        );
    }

    #[test]
    fn secured_and_misc_commands() {
        assert_eq!(get_visu_salt("admin"), "jdev/sys/getvisusalt/admin");
        assert_eq!(
            secured_command(HASH, "0f1e2d3c-4b5a-6978-ffff403fb0c34b9e", "1"),
            "jdev/sps/ios/abc123/0f1e2d3c-4b5a-6978-ffff403fb0c34b9e/1"
        );
        assert_eq!(enable_updates(), "jdev/sps/enablebinstatusupdate");
        assert_eq!(keepalive(), "keepalive");
        assert_eq!(get_key(), "jdev/sys/getkey");
    }
}
