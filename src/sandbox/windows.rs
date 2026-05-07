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
pub(crate) mod win32 {
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

// ── Restricted Token Sandbox ──────────────────────────────────────────────────
//
// Spawns child processes with a restricted token at Low Integrity Level.
// Low-integrity processes CANNOT write to medium-integrity objects (most of the
// user's filesystem), providing OS-level enforcement of filesystem restrictions.

#[cfg(windows)]
mod restricted {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::RawHandle;
    use std::ptr;

    // ── Constants ─────────────────────────────────────────────────────────

    const TOKEN_DUPLICATE: u32 = 0x0002;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;

    const SECURITY_MAX_IMPERSONATION_LEVEL: u32 = 3; // SecurityDelegation
    const TOKEN_PRIMARY: u32 = 1;

    const DISABLE_MAX_PRIVILEGE: u32 = 0x1;

    const TOKEN_INTEGRITY_LEVEL: u32 = 25; // TokenIntegrityLevel

    // Low integrity SID: S-1-16-4096
    const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;

    const LOGON_WITH_PROFILE: u32 = 0x1;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;
    const CREATE_NEW_CONSOLE: u32 = 0x00000010;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const STARTF_USESTDHANDLES: u32 = 0x00000100;
    const HANDLE_FLAG_INHERIT: u32 = 0x00000001;

    // ── FFI Types ─────────────────────────────────────────────────────────

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[repr(C)]
    struct SidIdentifierAuthority {
        value: [u8; 6],
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct TokenMandatoryLabel {
        Label: SidAndAttributes,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SidAndAttributes {
        Sid: *mut c_void,
        Attributes: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct StartupInfoW {
        cb: u32,
        lpReserved: *mut u16,
        lpDesktop: *mut u16,
        lpTitle: *mut u16,
        dwX: u32,
        dwY: u32,
        dwXSize: u32,
        dwYSize: u32,
        dwXCountChars: u32,
        dwYCountChars: u32,
        dwFillAttribute: u32,
        dwFlags: u32,
        wShowWindow: u16,
        cbReserved2: u16,
        lpReserved2: *mut u8,
        hStdInput: RawHandle,
        hStdOutput: RawHandle,
        hStdError: RawHandle,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    pub struct ProcessInformation {
        pub hProcess: RawHandle,
        pub hThread: RawHandle,
        pub dwProcessId: u32,
        pub dwThreadId: u32,
    }

    // ── FFI Declarations ──────────────────────────────────────────────────

    unsafe extern "system" {
        // Token management
        safe fn GetCurrentProcess() -> RawHandle;
        fn OpenProcessToken(proc_handle: RawHandle, access: u32, token: *mut RawHandle) -> i32;
        fn DuplicateTokenEx(
            existing: RawHandle, access: u32, attrs: *const c_void,
            imp_level: u32, token_type: u32, new_token: *mut RawHandle,
        ) -> i32;
        fn CreateRestrictedToken(
            existing: RawHandle, flags: u32,
            disable_sid_count: u32, sids_to_disable: *const c_void,
            delete_priv_count: u32, privs_to_delete: *const c_void,
            restrict_sid_count: u32, sids_to_restrict: *const c_void,
            new_token: *mut RawHandle,
        ) -> i32;
        fn SetTokenInformation(
            token: RawHandle, info_class: u32,
            info: *const c_void, info_len: u32,
        ) -> i32;

        // SID management
        fn AllocateAndInitializeSid(
            authority: *const SidIdentifierAuthority,
            sub_count: u8,
            sub0: u32, sub1: u32, sub2: u32, sub3: u32,
            sub4: u32, sub5: u32, sub6: u32, sub7: u32,
            sid: *mut *mut c_void,
        ) -> i32;
        fn FreeSid(sid: *mut c_void) -> *mut c_void;

        // Process creation
        fn CreateProcessWithTokenW(
            token: RawHandle,
            logon_flags: u32,
            app_name: *const u16,
            cmd_line: *mut u16,
            creation_flags: u32,
            environment: *const c_void,
            current_dir: *const u16,
            startup_info: *const StartupInfoW,
            process_info: *mut ProcessInformation,
        ) -> i32;

        // Pipe + handle management
        fn CreatePipe(
            read: *mut RawHandle, write: *mut RawHandle,
            attrs: *const SecurityAttributes, size: u32,
        ) -> i32;
        fn SetHandleInformation(handle: RawHandle, mask: u32, flags: u32) -> i32;

        safe fn CloseHandle(handle: RawHandle) -> i32;
    }

    /// Create a restricted token at Low Integrity Level.
    ///
    /// Returns a new primary token with:
    /// - All privileges stripped (except SeChangeNotifyPrivilege)
    /// - Integrity level set to Low (cannot write to medium-integrity objects)
    pub fn create_low_integrity_token() -> io::Result<RawHandle> {
        unsafe {
            // 1. Open current process token.
            let mut process_token: RawHandle = ptr::null_mut();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &mut process_token,
            ) == 0 {
                return Err(io::Error::last_os_error());
            }

            // 2. Create a restricted token (strip most privileges).
            let mut restricted_token: RawHandle = ptr::null_mut();
            let result = CreateRestrictedToken(
                process_token,
                DISABLE_MAX_PRIVILEGE,
                0, ptr::null(),  // no SIDs to disable
                0, ptr::null(),  // let the flag handle privilege deletion
                0, ptr::null(),  // no restricting SIDs
                &mut restricted_token,
            );
            CloseHandle(process_token);
            if result == 0 {
                return Err(io::Error::last_os_error());
            }

            // 3. Duplicate as a primary token (needed for CreateProcessWithTokenW).
            let mut primary_token: RawHandle = ptr::null_mut();
            let result = DuplicateTokenEx(
                restricted_token,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                ptr::null(),
                SECURITY_MAX_IMPERSONATION_LEVEL,
                TOKEN_PRIMARY,
                &mut primary_token,
            );
            CloseHandle(restricted_token);
            if result == 0 {
                return Err(io::Error::last_os_error());
            }

            // 4. Set integrity level to Low.
            let authority = SidIdentifierAuthority {
                value: [0, 0, 0, 0, 0, 16], // SECURITY_MANDATORY_LABEL_AUTHORITY
            };
            let mut low_sid: *mut c_void = ptr::null_mut();
            if AllocateAndInitializeSid(
                &authority, 1,
                SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0,
                &mut low_sid,
            ) == 0 {
                CloseHandle(primary_token);
                return Err(io::Error::last_os_error());
            }

            let label = TokenMandatoryLabel {
                Label: SidAndAttributes {
                    Sid: low_sid,
                    Attributes: 0x20, // SE_GROUP_INTEGRITY
                },
            };

            let result = SetTokenInformation(
                primary_token,
                TOKEN_INTEGRITY_LEVEL,
                &label as *const _ as *const c_void,
                std::mem::size_of::<TokenMandatoryLabel>() as u32,
            );

            FreeSid(low_sid);

            if result == 0 {
                let err = io::Error::last_os_error();
                CloseHandle(primary_token);
                return Err(err);
            }

            Ok(primary_token)
        }
    }

    /// Spawn a process with a restricted Low Integrity token.
    ///
    /// Returns `(ProcessInformation, stdout_read_handle, stderr_read_handle)`.
    /// The caller is responsible for closing all handles.
    pub fn spawn_with_restricted_token(
        cmd_line: &str,
        env_block: &[u16],
    ) -> io::Result<(ProcessInformation, RawHandle, RawHandle)> {
        unsafe {
            let token = create_low_integrity_token()?;

            // Create pipes for stdout and stderr.
            let inheritable = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                security_descriptor: ptr::null_mut(),
                inherit_handle: 1, // TRUE
            };

            let mut stdout_read: RawHandle = ptr::null_mut();
            let mut stdout_write: RawHandle = ptr::null_mut();
            if CreatePipe(&mut stdout_read, &mut stdout_write, &inheritable, 0) == 0 {
                CloseHandle(token);
                return Err(io::Error::last_os_error());
            }
            // Don't inherit the read end.
            SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

            let mut stderr_read: RawHandle = ptr::null_mut();
            let mut stderr_write: RawHandle = ptr::null_mut();
            if CreatePipe(&mut stderr_read, &mut stderr_write, &inheritable, 0) == 0 {
                CloseHandle(token);
                CloseHandle(stdout_read);
                CloseHandle(stdout_write);
                return Err(io::Error::last_os_error());
            }
            SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);

            // Set up STARTUPINFO with pipe handles.
            let mut si: StartupInfoW = std::mem::zeroed();
            si.cb = std::mem::size_of::<StartupInfoW>() as u32;
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = stdout_write;
            si.hStdError = stderr_write;
            si.hStdInput = ptr::null_mut();

            // Convert command line to wide string (must be mutable for CreateProcess).
            let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

            let mut pi: ProcessInformation = std::mem::zeroed();

            let result = CreateProcessWithTokenW(
                token,
                LOGON_WITH_PROFILE,
                ptr::null(),
                cmd_wide.as_mut_ptr(),
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                env_block.as_ptr() as *const c_void,
                ptr::null(), // inherit current directory
                &si,
                &mut pi,
            );

            // Close write ends of pipes (child has them now).
            CloseHandle(stdout_write);
            CloseHandle(stderr_write);
            CloseHandle(token);

            if result == 0 {
                let err = io::Error::last_os_error();
                CloseHandle(stdout_read);
                CloseHandle(stderr_read);
                return Err(err);
            }

            Ok((pi, stdout_read, stderr_read))
        }
    }

    /// Build a Windows-style environment block (null-separated, double-null terminated).
    pub fn build_env_block(vars: &[(String, String)]) -> Vec<u16> {
        let mut block = Vec::new();
        for (k, v) in vars {
            let entry = format!("{k}={v}");
            block.extend(entry.encode_utf16());
            block.push(0); // null terminator between entries
        }
        block.push(0); // double-null terminator
        block
    }
}

#[cfg(windows)]
pub use restricted::{spawn_with_restricted_token, build_env_block, create_low_integrity_token};

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
        let _job = JobObject::new().unwrap();
        let _pid = std::process::id();
        // Note: assigning current process to KILL_ON_JOB_CLOSE job would
        // kill the test runner on drop. Just verify the API compiles.
    }

    #[test]
    fn create_restricted_token() {
        let token = create_low_integrity_token();
        assert!(token.is_ok(), "should create restricted token: {:?}", token.err());
        if let Ok(handle) = token {
            win32::CloseHandle(handle);
        }
    }

    #[test]
    fn build_env_block_format() {
        let vars = vec![
            ("FOO".into(), "bar".into()),
            ("BAZ".into(), "qux".into()),
        ];
        let block = build_env_block(&vars);
        // Should contain: F,O,O,=,b,a,r,\0,B,A,Z,=,q,u,x,\0,\0
        assert!(block.ends_with(&[0, 0]), "should end with double null");
    }
}
