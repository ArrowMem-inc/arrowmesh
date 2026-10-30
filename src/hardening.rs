//! Keep the unwrapped key out of core dumps (F4). Called first thing in `arrowmesh run`.
//!
//! Two calls, the same pair ssh-agent and gpg-agent make: a core file size limit of 0, and the
//! process marked not dumpable (which also makes its /proc entries root owned, so another process
//! of the same user cannot read its environment or memory through /proc). Declared by hand
//! against the libc std already links, so no new crate and no lock file change.

#[cfg(target_os = "linux")]
mod sys {
    #[repr(C)]
    pub struct Rlimit {
        pub cur: u64,
        pub max: u64,
    }
    unsafe extern "C" {
        pub fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32;
        pub fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    }
    pub const RLIMIT_CORE: i32 = 4;
    pub const PR_SET_DUMPABLE: i32 = 4;
}

/// Err means the process could not be hardened; `run` refuses to start rather than run exposed.
#[cfg(target_os = "linux")]
pub fn no_core_dumps() -> Result<(), String> {
    let zero = sys::Rlimit { cur: 0, max: 0 };
    // SAFETY: plain syscalls with a valid pointer to a live struct and integer arguments.
    unsafe {
        if sys::setrlimit(sys::RLIMIT_CORE, &zero) != 0 {
            return Err("could not set the core file limit to 0".into());
        }
        if sys::prctl(sys::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err("could not mark the process not dumpable".into());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn no_core_dumps() -> Result<(), String> {
    Ok(())
}
