//! Child process lifecycle management and timeout enforcement.
//!
//! Spawns a monitoring task per child; kills after `tool_timeout_secs`.
//! Handles graceful shutdown: SIGTERM/SIGINT → drain → force-kill.
