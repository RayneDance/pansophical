//! OS-level child process sandboxing.
//!
//! Platform-specific implementations:
//! - Linux: landlock + seccomp
//! - Windows: AppContainer + Job Objects

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;
