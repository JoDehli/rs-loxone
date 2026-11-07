//! Secured commands: switching with a visualization password.
//!
//! 1. `jdev/sys/getvisusalt/<user>` (encrypted): visualization key, salt and hash algorithm.
//! 2. Hash the visualization code with them (`auth::hash::visual_hash`).
//! 3. `jdev/sps/ios/<hash>/<uuid>/<value>` (encrypted). Code 200 means the code was right.
//!
//! The visualization key is used for this call only. It never replaces the session key.
//!
//! [`Session::check_visu_code`] checks a code the same way, without sending a command.

use crate::auth::commands;
use crate::auth::hash::visual_hash;
use crate::auth::reply::parse_key2;
use crate::session::login::ensure_200;
use crate::session::{Session, SessionError};

impl Session {
    /// Send a secured command to a device, with its visualization code.
    ///
    /// Returns `Ok(())` if the Miniserver accepted the code and the command.
    /// A wrong code gives `SessionError::WrongVisuCode`.
    pub async fn send_secured(
        &self,
        device_uuid: &str,
        value: &str,
        code: &str,
    ) -> Result<(), SessionError> {
        let vis_reply = self
            .shared
            .request(&commands::get_visu_salt(&self.username), &["getvisusalt"])
            .await?;
        ensure_200(&vis_reply)?;
        let vis = parse_key2(&vis_reply)?;

        let hash = visual_hash(code, &vis)?;
        let reply = self
            .shared
            .request(
                &commands::secured_command(&hash, device_uuid, value),
                &["jdev/sps/ios"],
            )
            .await?;
        match reply.code {
            200 => Ok(()),
            500 => Err(SessionError::WrongVisuCode),
            _ => ensure_200(&reply),
        }
    }

    /// Check a visualization code without running anything on the Miniserver.
    /// Returns `Ok(true)` if the code is right, `Ok(false)` if it is wrong.
    pub async fn check_visu_code(&self, code: &str) -> Result<bool, SessionError> {
        let vis_reply = self
            .shared
            .request(&commands::get_visu_salt(&self.username), &["getvisusalt"])
            .await?;
        ensure_200(&vis_reply)?;
        let vis = parse_key2(&vis_reply)?;

        let hash = visual_hash(code, &vis)?;
        let reply = self
            .shared
            .request(&commands::check_visu_password(&hash), &["checkuservisupwd"])
            .await?;
        // The answer is code 200 either way; the value says "1" (right) or "0" (wrong).
        ensure_200(&reply)?;
        match reply.value.trim() {
            "1" => Ok(true),
            "0" => Ok(false),
            other => Err(SessionError::Protocol(
                crate::protocol::ProtocolError::Malformed(format!(
                    "unexpected visualization check value of {} bytes",
                    other.len()
                )),
            )),
        }
    }
}
