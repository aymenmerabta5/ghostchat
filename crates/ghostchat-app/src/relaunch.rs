//! Starting a fresh ghostchat after a Bluetooth reset, the same as quitting,
//! switching Bluetooth off and on, and starting it again by hand. The new
//! process waits for this one to release the single-instance lock.

use std::path::Path;
use std::time::Duration;

const ENV: &str = "GHOSTCHAT_RELAUNCHED";
/// How long a relaunched ghostchat waits for the old one to exit.
pub const WAIT: Duration = Duration::from_secs(15);

/// Start ghostchat again with the same arguments; the caller then exits.
pub fn spawn() -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    spawn_exe(&exe)
}

/// Start `exe` with the same arguments; the caller then exits. After an
/// update this is the path that now holds the new binary.
pub fn spawn_exe(exe: &Path) -> std::io::Result<()> {
    let args = std::env::args_os().skip(1).filter(|a| a != "--background");
    std::process::Command::new(exe).args(args).env(ENV, "1").spawn().map(|_| ())
}

/// This process was started by [`spawn`].
pub fn is_relaunch() -> bool {
    std::env::var_os(ENV).is_some()
}
