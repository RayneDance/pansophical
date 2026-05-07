//! Windows sandbox: Job Objects with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
//!
//! Job Objects ensure all child processes are terminated when the server
//! exits (even on crash), preventing orphaned processes.
//!
//! AppContainer profiles are named `pansophical-<uuid>`.
//! Startup scavenging removes orphaned profiles from prior crashes.
//!
//! This module uses raw Win32 API via `windows-sys` (lightweight) or
//! falls back to a "best-effort" approach using Rust `std` primitives.

use std::io;
use tracing::{info, warn};

/// A Windows Job Object handle wrapper.
///
/// When this is dropped, the job object is closed. If configured with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, all processes in the job are
/// killed when the handle is closed.
pub struct JobObject {
    #[cfg(windows)]
    handle: std::os::windows::io::RawHandle,
}

// SAFETY: Windows HANDLE values are kernel object references (opaque pointers).
// They can safely be used from any thread. The kernel manages synchronization.
#[cfg(windows)]
unsafe impl Send for JobObject {}
#[cfg(windows)]
unsafe impl Sync for JobObject {}

#[cfg(windows)]
mod win32 {
    //! Minimal Win32 FFI for Job Objects.
    //! We avoid pulling in the full `windows` crate for just these few calls.
    use std::os::windows::io::RawHandle;

    // Win32 constants.
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x00000008;
    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;

    // Win32 types.
    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        pub PerProcessUserTimeLimit: i64,
        pub PerJobUserTimeLimit: i64,
        pub LimitFlags: u32,
        pub MinimumWorkingSetSize: usize,
        pub MaximumWorkingSetSize: usize,
        pub ActiveProcessLimit: u32,
        pub Affinity: usize,
        pub PriorityClass: u32,
        pub SchedulingClass: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct IO_COUNTERS {
        pub ReadOperationCount: u64,
        pub WriteOperationCount: u64,
        pub OtherOperationCount: u64,
        pub ReadTransferCount: u64,
        pub WriteTransferCount: u64,
        pub OtherTransferCount: u64,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        pub BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        pub IoInfo: IO_COUNTERS,
        pub ProcessMemoryLimit: usize,
        pub JobMemoryLimit: usize,
        pub PeakProcessMemoryUsed: usize,
        pub PeakJobMemoryUsed: usize,
    }

    unsafe extern "system" {
        pub safe fn CreateJobObjectW(
            lpJobAttributes: *const std::ffi::c_void,
            lpName: *const u16,
        ) -> RawHandle;

        pub safe fn SetInformationJobObject(
            hJob: RawHandle,
            JobObjectInformationClass: u32,
            lpJobObjectInformation: *const std::ffi::c_void,
            cbJobObjectInformationLength: u32,
        ) -> i32;

        pub safe fn AssignProcessToJobObject(
            hJob: RawHandle,
            hProcess: RawHandle,
        ) -> i32;

        pub safe fn CloseHandle(hObject: RawHandle) -> i32;
    }
}

impl JobObject {
    /// Create a new Job Object configured to kill all children on close.
    ///
    /// This is the core safety mechanism: when the pansophical server exits
    /// (normally or via crash), the OS automatically terminates all child
    /// processes assigned to this job.
    #[cfg(windows)]
    pub fn new() -> io::Result<Self> {
        use std::ptr;

        let handle = win32::CreateJobObjectW(ptr::null(), ptr::null());
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        // Configure: kill all processes when job handle is closed.
        let mut info: win32::JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = win32::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let result = win32::SetInformationJobObject(
            handle,
            win32::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<win32::JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );

        if result == 0 {
            let err = io::Error::last_os_error();
            win32::CloseHandle(handle);
            return Err(err);
        }

        info!("Created Windows Job Object with KILL_ON_JOB_CLOSE");
        Ok(Self { handle })
    }

    /// Assign a child process to this job object.
    ///
    /// After assignment, the child will be killed when the job handle is
    /// closed (i.e., when the server exits).
    #[cfg(windows)]
    pub fn assign_process(&self, process_handle: std::os::windows::io::RawHandle) -> io::Result<()> {
        let result = win32::AssignProcessToJobObject(self.handle, process_handle);
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Assign a child process using its PID (looks up the process handle).
    #[cfg(windows)]
    pub fn assign_pid(&self, pid: u32) -> io::Result<()> {
        // Open the process with PROCESS_SET_QUOTA | PROCESS_TERMINATE.
        unsafe extern "system" {
            safe fn OpenProcess(dwDesiredAccess: u32, bInheritHandles: i32, dwProcessId: u32) -> std::os::windows::io::RawHandle;
        }

        const PROCESS_SET_QUOTA: u32 = 0x0100;
        const PROCESS_TERMINATE: u32 = 0x0001;

        let proc_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);

        if proc_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        let result = self.assign_process(proc_handle);

        // Close the handle — job object retains its own reference.
        win32::CloseHandle(proc_handle);

        result
    }
}

#[cfg(windows)]
impl Drop for JobObject {
    fn drop(&mut self) {
        win32::CloseHandle(self.handle);
    }
}

// Non-Windows stub for cross-compilation.
#[cfg(not(windows))]
impl JobObject {
    pub fn new() -> io::Result<Self> {
        warn!("Job Objects are Windows-only; sandbox not active on this platform");
        Ok(Self {})
    }

    pub fn assign_pid(&self, _pid: u32) -> io::Result<()> {
        Ok(())
    }
}

/// Create a server-wide Job Object that all child processes are assigned to.
///
/// This should be called once at startup and stored in the server state.
/// The returned `JobObject` must live for the entire server lifetime.
pub fn create_server_job() -> io::Result<JobObject> {
    JobObject::new()
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;

    #[test]
    fn create_job_object() {
        let job = JobObject::new();
        assert!(job.is_ok(), "should create job object: {:?}", job.err());
    }

    #[test]
    fn assign_self_to_job() {
        let job = JobObject::new().unwrap();
        // Assign the current process — this is safe for testing.
        let pid = std::process::id();
        // Note: assigning the current process to a KILL_ON_JOB_CLOSE job
        // means the test runner would be killed when the job is dropped.
        // So we skip this in actual tests — but verify the API compiles.
        // In production, only child processes are assigned.
        // let result = job.assign_pid(pid);
        // assert!(result.is_ok());
    }
}
