# Pansophical Sandbox — Future Work

## Phase 3: Linux Landlock

For Linux kernel 5.13+ (available on most modern distros):

1. **Create a Landlock ruleset** via `landlock_create_ruleset` syscall
   - Define handled access rights (read, write, execute, etc.)
2. **Add path-beneath rules** for each path in `SandboxProfile`
   - `write_paths` → `LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_*`
   - `read_paths` → `LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR`
   - `exec_paths` → `LANDLOCK_ACCESS_FS_EXECUTE`
3. **Enforce** via `landlock_restrict_self` in a `pre_exec` hook on the child process
4. **Fallback**: If Landlock is not available (old kernel), log a warning and
   run unsandboxed (same pattern as Windows restricted token fallback)

Reference implementation: `src/sandbox/linux.rs` (file exists, currently empty)

### Key differences from Windows

- Landlock is **path-based** — no need for integrity labels or token manipulation
- Rules are inherited by children automatically
- Works regardless of whether the server runs as root or unprivileged
- No cleanup needed — rules are per-process and die with the child


## Phase 4: Windows AppContainer (Strongest Isolation) - ✅ DONE

AppContainer provides the strongest possible sandbox on Windows, even on
elevated/admin sessions. It blocks ALL filesystem access except paths with
an explicit ACE for the container's SID.

### Steps Implemented
1. `CreateAppContainerProfile` — create a named container (e.g., `pansophical-<key>-<tool>`)
2. Get the container SID via `DeriveAppContainerSidFromAppContainerName`
3. For each allowed path, add an ACE granting the container SID access:
   - Write paths → `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
   - Read paths → `FILE_GENERIC_READ`
4. Use `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute`
   with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`
5. Call `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`
6. After process exits: remove ACEs, delete container profile

### Why this matters

On elevated (admin) sessions, the current Low Integrity approach does NOT
reliably block writes to paths without explicit integrity labels. AppContainer
solves this by denying ALL access by default and requiring explicit grants.


## Phase 5: Read-path Enforcement

Currently, read paths are collected in the `SandboxProfile` but not enforced
at the OS level. The child process can read any file the user can read.

- **Linux**: Add Landlock read rules (straightforward)
- **Windows Low IL**: Read access is generally not restricted by integrity level.
  AppContainer would enforce read restrictions.
- **Windows AppContainer**: Read paths would get read-only ACEs for the container SID.


## Phase 6: Network Isolation

Restrict child processes from making network connections:

- **Linux**: Landlock v4 (kernel 6.7+) adds `LANDLOCK_ACCESS_NET_*` rules
- **Windows AppContainer**: Network access requires explicit capability grants
- **Fallback**: Use Job Object `JOB_OBJECT_NET_RATE_CONTROL_FLAGS` (limited)


## Priority Order

1. **Linux Landlock** — high value, moderate complexity
2. **Read-path enforcement** — fills a gap, varies by platform
3. **Network isolation** — defense-in-depth, platform-dependent
