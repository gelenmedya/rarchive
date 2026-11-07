//! What this processor offers, detected once at run time.

#[cfg(target_arch = "x86_64")]
pub(crate) fn bmi2() -> bool {
    use std::sync::OnceLock;
    static HAS: OnceLock<bool> = OnceLock::new();
    *HAS.get_or_init(|| {
        if let Some(v) = std::env::var_os("RARCHIVE_NO_BMI2") {
            if v != "0" {
                return false;
            }
        }
        std::is_x86_feature_detected!("bmi1")
            && std::is_x86_feature_detected!("bmi2")
            && std::is_x86_feature_detected!("lzcnt")
            && std::is_x86_feature_detected!("popcnt")
    })
}

/// Worker threads to use when the caller doesn't say: every hardware thread.
pub fn threads() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

/// How the worker threads rarchive starts compete for the processor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Priority {
    /// Like any other thread.
    Normal,
    /// Lowest normal-class priority, without wake-up boosts: full speed on an idle machine,
    /// but whatever the user is doing in the foreground (a game, a render, the UI) runs
    /// first. The default.
    #[default]
    Low,
}

/// Applies `p` to the calling thread (worker threads call this when they start).
pub(crate) fn apply_priority(p: Priority) {
    #[cfg(windows)]
    if p == Priority::Low {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentThread() -> isize;
            fn SetThreadPriority(thread: isize, priority: i32) -> i32;
            fn SetThreadPriorityBoost(thread: isize, disable: i32) -> i32;
        }
        const THREAD_PRIORITY_LOWEST: i32 = -2;
        // SAFETY: plain Win32 calls on the current thread's pseudo-handle
        unsafe {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
            // Windows briefly raises a thread that wakes from a wait; for ours that would
            // lift them level with the user's programs, which is exactly what we avoid.
            SetThreadPriorityBoost(GetCurrentThread(), 1);
        }
    }
    #[cfg(not(windows))]
    let _ = p;
}

/// Memory extraction may hold when the caller doesn't say: an eighth of the memory free
/// right now, between 256 MB and 2 GB (a busy or small machine gets the floor).
pub fn memory_budget() -> u64 {
    const MIN: u64 = 256 << 20;
    const MAX: u64 = 2 << 30;
    available_memory().map_or(MIN, |a| (a / 8).clamp(MIN, MAX))
}

/// Physical memory currently available, when the platform tells.
pub fn available_memory() -> Option<u64> {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct MemoryStatusEx {
            length: u32,
            memory_load: u32,
            total_phys: u64,
            avail_phys: u64,
            total_page_file: u64,
            avail_page_file: u64,
            total_virtual: u64,
            avail_virtual: u64,
            avail_extended_virtual: u64,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
        }
        let mut m = MemoryStatusEx {
            length: std::mem::size_of::<MemoryStatusEx>() as u32,
            memory_load: 0,
            total_phys: 0,
            avail_phys: 0,
            total_page_file: 0,
            avail_page_file: 0,
            total_virtual: 0,
            avail_virtual: 0,
            avail_extended_virtual: 0,
        };
        // SAFETY: plain Win32 call filling a correctly sized struct
        if unsafe { GlobalMemoryStatusEx(&mut m) } != 0 {
            return Some(m.avail_phys);
        }
    }
    None
}
