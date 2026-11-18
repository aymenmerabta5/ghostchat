//! Windows GUI binaries start without a console.
//!
//! `ghostchat.exe` is linked as a GUI-subsystem program so launching it from
//! Explorer never leaves a terminal window behind, and so a window app never
//! owns a console it does not need. That also means the command-line modes
//! (`--diag`, `--scan`, `--relay`, `--geohash`, `--qr-lab`, `--geo-lab`,
//! `--ble-links`, `--help`) begin with no standard handles at all.
//!
//! This module gives those modes back the console of the shell that started
//! them: attach to the parent console, then point the missing standard handles
//! at `CONOUT$` / `CONIN$`. Redirected streams are left exactly as the shell
//! set them, so `ghostchat --diag > report.txt`, `2> errors.txt` and pipelines
//! keep their files and pipes. The window mode detaches again before the event
//! loop starts.

#[cfg(not(windows))]
pub struct Console;

/// Attach to the parent console when output would otherwise be lost.
///
/// Returns `None` on non-Windows targets, when both output streams already
/// point somewhere real (a terminal, a pipe or a file), and when the parent has
/// no console to attach to (an Explorer launch).
#[cfg(not(windows))]
pub fn attach_to_parent_console() -> Option<Console> {
    None
}

#[cfg(not(windows))]
impl Console {
    /// Nothing to release on other platforms.
    pub fn detach(self) {}
}

#[cfg(windows)]
pub use windows_console::attach_to_parent_console;

#[cfg(windows)]
mod windows_console {
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_UNKNOWN};
    use windows::Win32::System::Console::{
        AttachConsole, FreeConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_HANDLE,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    /// The console handles we opened, kept alive while the process prints.
    pub(crate) struct Console {
        _held: Vec<File>,
    }

    /// Attach to the console that started this process, if any.
    pub fn attach_to_parent_console() -> Option<Console> {
        // A shell that redirected our output already handed us working
        // handles. Do not replace them with the console.
        let stdout = connected(STD_OUTPUT_HANDLE);
        let stderr = connected(STD_ERROR_HANDLE);
        if stdout && stderr {
            return None;
        }
        let stdin = connected(STD_INPUT_HANDLE);

        // SAFETY: AttachConsole only affects this process. The parent either
        // has a console (a shell) or does not (Explorer, a service, CI).
        if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) }.is_err() {
            return None;
        }

        match setup(stdout, stderr, stdin) {
            Some(console) => Some(console),
            None => {
                // SAFETY: we attached above; drop the attachment we cannot use.
                unsafe {
                    let _ = FreeConsole();
                }
                None
            }
        }
    }

    impl Console {
        /// Leave the parent console before the window takes over.
        pub fn detach(self) {
            drop(self);
        }
    }

    impl Drop for Console {
        fn drop(&mut self) {
            // SAFETY: FreeConsole only detaches this process.
            unsafe {
                let _ = FreeConsole();
            }
        }
    }

    /// Open the console devices for every stream the shell did not redirect.
    fn setup(stdout: bool, stderr: bool, stdin: bool) -> Option<Console> {
        let mut held = Vec::new();
        if !stdout {
            held.push(redirect(STD_OUTPUT_HANDLE, "CONOUT$").ok()?);
        }
        if !stderr {
            held.push(redirect(STD_ERROR_HANDLE, "CONOUT$").ok()?);
        }
        if !stdin {
            // Input is optional: a console that refuses CONIN$ must not cost
            // us the output streams we just wired up.
            if let Ok(file) = redirect(STD_INPUT_HANDLE, "CONIN$") {
                held.push(file);
            }
        }
        Some(Console { _held: held })
    }

    /// Whether `which` already points at a file, pipe or terminal.
    fn connected(which: STD_HANDLE) -> bool {
        // SAFETY: GetStdHandle is a plain query with no side effects.
        let Ok(handle) = (unsafe { GetStdHandle(which) }) else {
            return false;
        };
        // SAFETY: the handle came from GetStdHandle and GetFileType only reads it.
        unsafe { GetFileType(handle) != FILE_TYPE_UNKNOWN }
    }

    /// Open a console device and make it the standard handle `which`.
    fn redirect(which: STD_HANDLE, device: &str) -> std::io::Result<File> {
        let file = File::options().read(true).write(true).open(device)?;
        let handle = HANDLE(file.as_raw_handle());
        // SAFETY: `file` owns a live handle for as long as the File lives; the
        // caller stores it in `Console`, which is not dropped until detach.
        unsafe { SetStdHandle(which, handle)? };
        Ok(file)
    }
}
