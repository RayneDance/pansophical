//! Windows sandbox: AppContainer isolation, Job Objects with
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, environment stripping.
//!
//! AppContainer profiles are named `pansophical-<uuid>`.
//! Startup scavenging removes orphaned profiles from prior crashes.
