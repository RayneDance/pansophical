//! Always-on human-in-the-loop approval server.
//!
//! Runs on `127.0.0.1:ui.port` and serves approval pages
//! for `confirm = true` policy rules.

pub mod server;
pub mod token;
pub mod ui;
pub mod session;
