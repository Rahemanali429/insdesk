//! Privilege-elevation / UAC bridge.
//!
//! ## The problem
//!
//! When Windows shows a UAC consent prompt it does so on an isolated **secure
//! desktop** (the `Winlogon` desktop). Code running in the ordinary interactive
//! desktop — which is where a normal capture/inject agent lives — cannot see or
//! click that prompt. So by default a remote operator watching the user's screen
//! sees it go dark and is locked out exactly when administrative work needs
//! doing.
//!
//! ## The design
//!
//! To make the UAC prompt *accessible and controllable from the remote side*,
//! InsDesk uses a privileged helper:
//!
//! 1. The agent installs a small **Windows service** running as `LocalSystem`
//!    in session 0 (see `docs` and `insdesk-host`'s `--install-service`).
//! 2. That service has the rights to attach to the secure desktop
//!    (`OpenInputDesktop` / `SetThreadDesktop("Winlogon")`), capture it, and
//!    inject input into it.
//! 3. When the bridge detects the secure desktop is active it raises
//!    [`SecureDesktopEvent::Activated`]; the host then streams the *secure*
//!    desktop's pixels and routes the operator's clicks/keys to it, so the UAC
//!    dialog can be read and answered remotely. When it closes,
//!    [`SecureDesktopEvent::Deactivated`] switches capture back.
//!
//! The human at the host keeps a hard kill-switch: secure-desktop control is
//! only honored while they have granted it (see
//! `insdesk_proto::ElevationMsg::SetSecureDesktopControl`).
//!
//! The trait and the portable [`NullElevationBridge`] are always compiled; the
//! real Windows implementation is behind `cfg(windows)` + the `uac-windows`
//! feature so the engine builds everywhere.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElevationError {
    #[error("elevation backend error: {0}")]
    Backend(String),
    #[error("elevation is not supported on this platform/build")]
    Unsupported,
}

/// The privilege level the agent is currently running at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// A normal, non-administrative user token.
    Standard,
    /// An elevated / administrative token (or `root`/`LocalSystem`).
    Elevated,
}

/// A change in secure-desktop state, produced by [`ElevationBridge::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureDesktopEvent {
    /// A UAC / secure-desktop prompt just appeared.
    Activated,
    /// The secure desktop was dismissed; capture returns to the normal desktop.
    Deactivated,
}

/// Abstraction over platform elevation + secure-desktop handling.
pub trait ElevationBridge: Send {
    /// Current privilege level of the running agent.
    fn privilege_level(&self) -> PrivilegeLevel;

    /// Whether a secure desktop (UAC prompt) is active right now.
    fn is_secure_desktop_active(&self) -> bool;

    /// Poll for a transition since the last call. Returns `None` if nothing
    /// changed. Cheap enough to call on the capture cadence.
    fn poll(&mut self) -> Option<SecureDesktopEvent>;

    /// Attempt to elevate the agent (e.g. relaunch via the service, or trigger
    /// a UAC consent). `reason` is surfaced to the local user.
    fn request_elevation(&mut self, reason: &str) -> Result<(), ElevationError>;
}

/// Portable fallback: reports standard privileges and never sees a secure
/// desktop. Used on non-Windows hosts and whenever the Windows bridge is not
/// compiled in. It keeps the whole protocol path exercisable everywhere.
pub struct NullElevationBridge {
    level: PrivilegeLevel,
}

impl NullElevationBridge {
    pub fn new() -> Self {
        NullElevationBridge { level: detect_portable_privilege() }
    }
}

impl Default for NullElevationBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ElevationBridge for NullElevationBridge {
    fn privilege_level(&self) -> PrivilegeLevel {
        self.level
    }
    fn is_secure_desktop_active(&self) -> bool {
        false
    }
    fn poll(&mut self) -> Option<SecureDesktopEvent> {
        None
    }
    fn request_elevation(&mut self, _reason: &str) -> Result<(), ElevationError> {
        Err(ElevationError::Unsupported)
    }
}

/// Best-effort privilege detection that needs no platform crates: on Unix,
/// `root` (uid 0) counts as elevated; elsewhere assume standard.
fn detect_portable_privilege() -> PrivilegeLevel {
    #[cfg(unix)]
    {
        // Safe FFI: getuid has no preconditions and never fails.
        let uid = unsafe { libc_getuid() };
        if uid == 0 {
            return PrivilegeLevel::Elevated;
        }
    }
    PrivilegeLevel::Standard
}

#[cfg(unix)]
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

/// The real Windows secure-desktop bridge. Compiled only on Windows with the
/// `uac-windows` feature; the body uses the `windows` crate. It is documented
/// here and kept behind cfg so the rest of the project builds on any host.
#[cfg(all(windows, feature = "uac-windows"))]
mod windows_backend {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::StationsAndDesktops::{CloseDesktop, OpenInputDesktop, DESKTOP_READOBJECTS};

    pub struct WindowsElevationBridge {
        last_secure: bool,
    }

    impl WindowsElevationBridge {
        pub fn new() -> Result<Self, ElevationError> {
            Ok(WindowsElevationBridge { last_secure: false })
        }

        /// The current input desktop's name tells us whether we're on the
        /// secure desktop. The UAC prompt runs on the `Winlogon` desktop; when
        /// `OpenInputDesktop` returns a desktop other than the usual `Default`,
        /// a secure prompt is up.
        fn secure_desktop_now() -> bool {
            unsafe {
                match OpenInputDesktop(Default::default(), false, DESKTOP_READOBJECTS) {
                    Ok(hdesk) => {
                        // A full implementation reads the desktop name via
                        // GetUserObjectInformationW and compares to "Winlogon".
                        // Here we conservatively treat a failure to open the
                        // input desktop from the interactive session as "secure
                        // desktop active", which is the signal the service uses
                        // to switch capture to the Winlogon desktop.
                        let _ = CloseDesktop(hdesk);
                        false
                    }
                    Err(_) => true,
                }
            }
        }

        fn token_is_elevated() -> bool {
            unsafe {
                let mut token = HANDLE::default();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                    return false;
                }
                let mut elevation = TOKEN_ELEVATION::default();
                let mut ret_len = 0u32;
                let ok = GetTokenInformation(
                    token,
                    TokenElevation,
                    Some(&mut elevation as *mut _ as *mut _),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut ret_len,
                )
                .is_ok();
                let _ = CloseHandle(token);
                ok && elevation.TokenIsElevated != 0
            }
        }
    }

    impl ElevationBridge for WindowsElevationBridge {
        fn privilege_level(&self) -> PrivilegeLevel {
            if Self::token_is_elevated() {
                PrivilegeLevel::Elevated
            } else {
                PrivilegeLevel::Standard
            }
        }

        fn is_secure_desktop_active(&self) -> bool {
            Self::secure_desktop_now()
        }

        fn poll(&mut self) -> Option<SecureDesktopEvent> {
            let now = Self::secure_desktop_now();
            if now != self.last_secure {
                self.last_secure = now;
                return Some(if now {
                    SecureDesktopEvent::Activated
                } else {
                    SecureDesktopEvent::Deactivated
                });
            }
            None
        }

        fn request_elevation(&mut self, _reason: &str) -> Result<(), ElevationError> {
            // A full implementation relaunches the agent via the installed
            // service (already SYSTEM) or with a `runas`/ShellExecute "runas"
            // verb to raise a consent prompt. Left to the service installer.
            Err(ElevationError::Unsupported)
        }
    }
}

/// Construct the best elevation bridge available for this build/platform.
pub fn default_bridge() -> Box<dyn ElevationBridge> {
    #[cfg(all(windows, feature = "uac-windows"))]
    {
        if let Ok(b) = windows_backend::WindowsElevationBridge::new() {
            return Box::new(b);
        }
    }
    Box::new(NullElevationBridge::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bridge_is_quiet() {
        let mut b = NullElevationBridge::new();
        assert!(!b.is_secure_desktop_active());
        assert!(b.poll().is_none());
        assert!(b.request_elevation("test").is_err());
        // privilege_level is one of the two variants; just exercise it.
        let _ = b.privilege_level();
    }
}
