#[cfg(unix)]
pub fn harden_process() {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let _ = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
}

#[cfg(not(unix))]
pub fn harden_process() {}
