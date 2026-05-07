//! Human-in-the-loop confirmation system.
//!
//! When a tool call matches a `confirm = true` policy rule, the server
//! pauses execution and opens a browser approval page. The user can
//! approve or deny the action with a scoped TTL.

pub mod server;
pub mod session;
pub mod token;
pub mod ui;
