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
use tracing::info;

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
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    const LOGON_WITH_PROFILE: u32 = 0x1;
    #[allow(dead_code)]
    const LOGON_NETCREDENTIALS_ONLY: u32 = 0x2;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;
    #[allow(dead_code)]
    const CREATE_NEW_CONSOLE: u32 = 0x00000010;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const STARTF_USESTDHANDLES: u32 = 0x00000100;
    const HANDLE_FLAG_INHERIT: u32 = 0x00000001;

    // ── FFI Types ─────────────────────────────────────────────────────────

    #[repr(C)]
    pub struct SecurityAttributes {
        pub length: u32,
        pub security_descriptor: *mut c_void,
        pub inherit_handle: i32,
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
    pub struct StartupInfoW {
        pub cb: u32,
        pub lpReserved: *mut u16,
        pub lpDesktop: *mut u16,
        pub lpTitle: *mut u16,
        pub dwX: u32,
        pub dwY: u32,
        pub dwXSize: u32,
        pub dwYSize: u32,
        pub dwXCountChars: u32,
        pub dwYCountChars: u32,
        pub dwFillAttribute: u32,
        pub dwFlags: u32,
        pub wShowWindow: u16,
        pub cbReserved2: u16,
        pub lpReserved2: *mut u8,
        pub hStdInput: RawHandle,
        pub hStdOutput: RawHandle,
        pub hStdError: RawHandle,
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
        fn CreateProcessAsUserW(
            token: RawHandle,
            app_name: *const u16,
            cmd_line: *mut u16,
            proc_attrs: *const c_void,
            thread_attrs: *const c_void,
            inherit_handles: i32,
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

            let result = CreateProcessAsUserW(
                token,
                ptr::null(),
                cmd_wide.as_mut_ptr(),
                ptr::null(), // proc attrs
                ptr::null(), // thread attrs
                1,           // inherit handles (TRUE - for pipes)
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

    /// Wrapper to free a SID using FreeSid
    pub fn free_sid(sid: *mut std::ffi::c_void) {
        unsafe {
            FreeSid(sid);
        }
    }
}

#[cfg(windows)]
pub use restricted::{spawn_with_restricted_token, build_env_block};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AppContainer sandbox — strongest Windows isolation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// AppContainer denies ALL filesystem access by default. Only paths with an
// explicit ACE for the container's SID are accessible. This works regardless
// of elevation level (admin, standard user, etc.).

#[cfg(windows)]
pub mod appcontainer {
    use std::ffi::c_void;
    use std::os::windows::io::RawHandle;
    use std::path::Path;
    use std::{io, ptr};

    use super::restricted::{
        ProcessInformation, SecurityAttributes, StartupInfoW,
    };

    // ── Constants ────────────────────────────────────────────────────────────

    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;
    const STARTF_USESTDHANDLES: u32 = 0x00000100;
    const HANDLE_FLAG_INHERIT: u32 = 0x00000001;

    // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = ProcThreadAttributeValue(9, FALSE, TRUE, FALSE)
    // = 9 | PROC_THREAD_ATTRIBUTE_INPUT(0x20000) = 0x20009
    const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x00020009;

    // HRESULT values
    const S_OK: i32 = 0;
    #[allow(dead_code)]
    const E_ALREADY_EXISTS: i32 = -2147023436_i32; // 0x800700B7

    // ── FFI Types ────────────────────────────────────────────────────────────

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SecurityCapabilities {
        AppContainerSid: *mut c_void,
        Capabilities: *mut c_void, // PSID_AND_ATTRIBUTES — we use none
        CapabilityCount: u32,
        Reserved: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct StartupInfoExW {
        StartupInfo: StartupInfoW,
        lpAttributeList: *mut c_void, // PPROC_THREAD_ATTRIBUTE_LIST
    }

    // ── FFI Declarations ─────────────────────────────────────────────────────

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn CreateAppContainerProfile(
            container_name: *const u16,
            display_name: *const u16,
            description: *const u16,
            capabilities: *const c_void,
            capability_count: u32,
            sid_ptr: *mut *mut c_void,
        ) -> i32; // HRESULT

        fn DeleteAppContainerProfile(container_name: *const u16) -> i32;
    }

    unsafe extern "system" {
        // SID → string conversion
        fn ConvertSidToStringSidW(
            sid: *const c_void,
            string_sid: *mut *mut u16,
        ) -> i32;
        fn LocalFree(mem: *mut c_void) -> *mut c_void;

        // Process creation
        fn CreateProcessW(
            app_name: *const u16,
            cmd_line: *mut u16,
            proc_attrs: *const c_void,
            thread_attrs: *const c_void,
            inherit_handles: i32,
            creation_flags: u32,
            environment: *const c_void,
            current_dir: *const u16,
            startup_info: *const StartupInfoExW,
            process_info: *mut ProcessInformation,
        ) -> i32;

        // Proc thread attribute list management
        fn InitializeProcThreadAttributeList(
            list: *mut c_void,
            count: u32,
            flags: u32,
            size: *mut usize,
        ) -> i32;
        fn UpdateProcThreadAttribute(
            list: *mut c_void,
            flags: u32,
            attribute: usize,
            value: *const c_void,
            size: usize,
            previous_value: *mut c_void,
            return_size: *mut usize,
        ) -> i32;
        fn DeleteProcThreadAttributeList(list: *mut c_void);

        // Pipe + handle management (re-declared from restricted module)
        fn CreatePipe(
            read: *mut RawHandle, write: *mut RawHandle,
            attrs: *const SecurityAttributes, size: u32,
        ) -> i32;
        fn SetHandleInformation(handle: RawHandle, mask: u32, flags: u32) -> i32;

        fn HeapAlloc(heap: RawHandle, flags: u32, bytes: usize) -> *mut c_void;
        fn HeapFree(heap: RawHandle, flags: u32, mem: *mut c_void) -> i32;
        fn GetProcessHeap() -> RawHandle;

        safe fn CloseHandle(handle: RawHandle) -> i32;
    }

    // ── AppContainer lifecycle ───────────────────────────────────────────────

    /// Managed AppContainer profile with RAII cleanup.
    pub struct AppContainer {
        name_wide: Vec<u16>,
        pub sid: *mut c_void,
        pub sid_string: String,
        granted_paths: Vec<String>,
    }

    // SAFETY: AppContainer is only used on the creating thread before spawn.
    // The SID pointer is a kernel-managed object safe to move between threads.
    unsafe impl Send for AppContainer {}

    impl AppContainer {
        /// Create a new AppContainer profile with a unique name.
        pub fn create() -> io::Result<Self> {
            let uuid = uuid::Uuid::new_v4();
            let name = format!("pansophical-{}", uuid);
            let display = format!("Pansophical Sandbox {}", uuid);
            let desc = "Pansophical MCP server sandboxed child";

            let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let display_wide: Vec<u16> = display.encode_utf16().chain(std::iter::once(0)).collect();
            let desc_wide: Vec<u16> = desc.encode_utf16().chain(std::iter::once(0)).collect();

            let mut sid: *mut c_void = ptr::null_mut();

            unsafe {
                // Delete any orphaned profile with the same name (shouldn't happen with UUID).
                let _ = DeleteAppContainerProfile(name_wide.as_ptr());

                let hr = CreateAppContainerProfile(
                    name_wide.as_ptr(),
                    display_wide.as_ptr(),
                    desc_wide.as_ptr(),
                    ptr::null(),
                    0,
                    &mut sid,
                );

                if hr != S_OK {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("CreateAppContainerProfile failed: HRESULT 0x{:08X}", hr as u32),
                    ));
                }
            }

            // Convert SID to string for icacls.
            let sid_string = sid_to_string(sid)?;

            tracing::info!(
                container = %name,
                sid = %sid_string,
                "Created AppContainer profile"
            );

            Ok(Self {
                name_wide,
                sid,
                sid_string,
                granted_paths: Vec::new(),
            })
        }

        /// Grant the AppContainer SID access to a path.
        ///
        /// `write` controls whether write access is granted (true) or read-only (false).
        pub fn grant_access(&mut self, path: &Path, write: bool) -> Result<(), String> {
            let path_str = path.display().to_string();
            let perms = if write { "(OI)(CI)(F)" } else { "(OI)(CI)(RX)" };

            let output = std::process::Command::new("icacls")
                .args([
                    &path_str,
                    "/grant",
                    &format!("*{}:{}", self.sid_string, perms),
                ])
                .output()
                .map_err(|e| format!("failed to run icacls: {e}"))?;

            if output.status.success() {
                tracing::debug!(path = %path_str, write, "Granted AppContainer access");
                self.granted_paths.push(path_str);
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(format!("icacls grant failed for '{}': {}", path_str, stderr.trim()))
            }
        }

        /// Revoke all previously granted ACEs.
        fn revoke_all(&self) {
            for path_str in &self.granted_paths {
                let _ = std::process::Command::new("icacls")
                    .args([
                        path_str.as_str(),
                        "/remove",
                        &format!("*{}", self.sid_string),
                    ])
                    .output();
            }
        }
    }

    impl Drop for AppContainer {
        fn drop(&mut self) {
            // Revoke filesystem ACEs.
            self.revoke_all();

            // Delete the container profile.
            unsafe {
                let _ = DeleteAppContainerProfile(self.name_wide.as_ptr());
                // FreeSid for AppContainer SIDs — allocated by CreateAppContainerProfile.
                // The docs say to use FreeSid.
                super::restricted::free_sid(self.sid);
            }

            tracing::debug!("Cleaned up AppContainer profile");
        }
    }

    /// Convert a SID pointer to a string (e.g., "S-1-15-2-...").
    fn sid_to_string(sid: *mut c_void) -> io::Result<String> {
        unsafe {
            let mut string_sid: *mut u16 = ptr::null_mut();
            if ConvertSidToStringSidW(sid, &mut string_sid) == 0 {
                return Err(io::Error::last_os_error());
            }

            // Read the wide string.
            let mut len = 0;
            while *string_sid.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(string_sid, len);
            let result = String::from_utf16_lossy(slice);

            LocalFree(string_sid as *mut c_void);
            Ok(result)
        }
    }

    /// Spawn a process inside an AppContainer.
    ///
    /// The AppContainer denies all access by default. Before calling this,
    /// use `container.grant_access()` to allow paths the child needs.
    ///
    /// Returns the process info and raw pipe handles for stdout/stderr.
    pub fn spawn_in_appcontainer(
        container: &AppContainer,
        cmd_line: &str,
        env_block: &[u16],
    ) -> io::Result<(ProcessInformation, RawHandle, RawHandle)> {
        unsafe {
            // ── Create pipes for stdout/stderr ──────────────────────────
            let sa = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                security_descriptor: ptr::null_mut(),
                inherit_handle: 1, // TRUE
            };

            let mut stdout_read: RawHandle = ptr::null_mut();
            let mut stdout_write: RawHandle = ptr::null_mut();
            if CreatePipe(&mut stdout_read, &mut stdout_write, &sa, 0) == 0 {
                return Err(io::Error::last_os_error());
            }
            SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

            let mut stderr_read: RawHandle = ptr::null_mut();
            let mut stderr_write: RawHandle = ptr::null_mut();
            if CreatePipe(&mut stderr_read, &mut stderr_write, &sa, 0) == 0 {
                CloseHandle(stdout_read);
                CloseHandle(stdout_write);
                return Err(io::Error::last_os_error());
            }
            SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);

            // ── Build SECURITY_CAPABILITIES ─────────────────────────────
            let sc = SecurityCapabilities {
                AppContainerSid: container.sid,
                Capabilities: ptr::null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };

            // ── Initialize proc thread attribute list ───────────────────
            let mut attr_size: usize = 0;
            // First call: get required size.
            let _ = InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_size);

            let heap = GetProcessHeap();
            let attr_list = HeapAlloc(heap, 0, attr_size);
            if attr_list.is_null() {
                CloseHandle(stdout_read); CloseHandle(stdout_write);
                CloseHandle(stderr_read); CloseHandle(stderr_write);
                return Err(io::Error::new(io::ErrorKind::OutOfMemory, "HeapAlloc failed"));
            }

            if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) == 0 {
                HeapFree(heap, 0, attr_list);
                CloseHandle(stdout_read); CloseHandle(stdout_write);
                CloseHandle(stderr_read); CloseHandle(stderr_write);
                return Err(io::Error::last_os_error());
            }

            if UpdateProcThreadAttribute(
                attr_list, 0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                &sc as *const _ as *const c_void,
                std::mem::size_of::<SecurityCapabilities>(),
                ptr::null_mut(), ptr::null_mut(),
            ) == 0 {
                DeleteProcThreadAttributeList(attr_list);
                HeapFree(heap, 0, attr_list);
                CloseHandle(stdout_read); CloseHandle(stdout_write);
                CloseHandle(stderr_read); CloseHandle(stderr_write);
                return Err(io::Error::last_os_error());
            }

            // ── Build STARTUPINFOEXW ────────────────────────────────────
            let mut si_ex: StartupInfoExW = std::mem::zeroed();
            si_ex.StartupInfo.cb = std::mem::size_of::<StartupInfoExW>() as u32;
            si_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si_ex.StartupInfo.hStdInput = ptr::null_mut();
            si_ex.StartupInfo.hStdOutput = stdout_write;
            si_ex.StartupInfo.hStdError = stderr_write;
            si_ex.lpAttributeList = attr_list;

            // ── Create the process ──────────────────────────────────────
            let mut cmd_wide: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();
            let mut pi: ProcessInformation = std::mem::zeroed();

            let result = CreateProcessW(
                ptr::null(),
                cmd_wide.as_mut_ptr(),
                ptr::null(), // proc attrs
                ptr::null(), // thread attrs
                1,           // inherit handles (for pipes)
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                env_block.as_ptr() as *const c_void,
                ptr::null(), // inherit cwd
                &si_ex,
                &mut pi,
            );

            // Clean up attribute list (no longer needed after CreateProcess).
            DeleteProcThreadAttributeList(attr_list);
            HeapFree(heap, 0, attr_list);

            // Close write ends of pipes.
            CloseHandle(stdout_write);
            CloseHandle(stderr_write);

            if result == 0 {
                let err = io::Error::last_os_error();
                CloseHandle(stdout_read);
                CloseHandle(stderr_read);
                return Err(err);
            }

            Ok((pi, stdout_read, stderr_read))
        }
    }
}

#[cfg(windows)]
pub use appcontainer::{AppContainer, spawn_in_appcontainer};

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
        let token = restricted::create_low_integrity_token();
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
