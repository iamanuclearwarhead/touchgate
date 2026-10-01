use std::sync::mpsc;
use std::time::Duration;

use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::Win32::UI::Input::KeyboardAndMouse::{KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP, VK_MENU, keybd_event};
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, GetDesktopWindow, GetForegroundWindow, SetForegroundWindow};
use windows::core::{HSTRING, factory, w};
use windows_future::IAsyncOperation;

use crate::{AuthResult, DeviceInfo, Prompt, Verifier};

pub struct Hello;

fn availability() -> Result<UserConsentVerifierAvailability, String> {
    UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|op| op.join())
        .map_err(|e| format!("windows hello: {}", e.message()))
}

fn availability_text(a: UserConsentVerifierAvailability) -> &'static str {
    match a {
        UserConsentVerifierAvailability::DeviceNotPresent => "no windows hello device",
        UserConsentVerifierAvailability::NotConfiguredForUser => "windows hello is not set up for this user",
        UserConsentVerifierAvailability::DisabledByPolicy => "windows hello is disabled by policy",
        UserConsentVerifierAvailability::DeviceBusy => "windows hello device is busy",
        _ => "windows hello is not available",
    }
}

fn owner_window() -> HWND {
    unsafe {
        let fg = GetForegroundWindow();
        if !fg.is_invalid() {
            return fg;
        }
        let console = GetConsoleWindow();
        if !console.is_invalid() {
            return console;
        }
        GetDesktopWindow()
    }
}

fn bring_dialog_forward() {
    std::thread::spawn(|| {
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(150));
            unsafe {
                if let Ok(h) = FindWindowW(w!("Credential Dialog Xaml Host"), None) {
                    if !h.is_invalid() {
                        keybd_event(VK_MENU.0 as u8, 0, KEYBD_EVENT_FLAGS(0), 0);
                        let _ = SetForegroundWindow(h);
                        keybd_event(VK_MENU.0 as u8, 0, KEYEVENTF_KEYUP, 0);
                        return;
                    }
                }
            }
        }
    });
}

impl Verifier for Hello {
    fn backend(&self) -> &'static str {
        "windows-hello"
    }

    fn probe(&self) -> Result<DeviceInfo, String> {
        match availability()? {
            UserConsentVerifierAvailability::Available => Ok(DeviceInfo {
                name: "Windows Hello".into(),
                enrolled: vec!["configured".into()],
            }),
            UserConsentVerifierAvailability::NotConfiguredForUser => Ok(DeviceInfo {
                name: "Windows Hello".into(),
                enrolled: Vec::new(),
            }),
            a => Err(availability_text(a).into()),
        }
    }

    fn verify(&self, prompt: &Prompt) -> AuthResult {
        match availability() {
            Ok(UserConsentVerifierAvailability::Available) => {}
            Ok(a) => return AuthResult::Rejected(availability_text(a).into()),
            Err(e) => return AuthResult::Rejected(e),
        }
        let message = HSTRING::from(format!("{}\n\n{}", prompt.headline(), prompt.action));
        let op: IAsyncOperation<UserConsentVerificationResult> = match factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
            .and_then(|interop| unsafe { interop.RequestVerificationForWindowAsync(owner_window(), &message) })
        {
            Ok(op) => op,
            Err(e) => return AuthResult::Rejected(format!("windows hello: {}", e.message())),
        };
        bring_dialog_forward();
        let (tx, rx) = mpsc::channel();
        let waiting = op.clone();
        std::thread::spawn(move || {
            let _ = tx.send(waiting.join());
        });
        match rx.recv_timeout(prompt.timeout) {
            Ok(Ok(UserConsentVerificationResult::Verified)) => AuthResult::Verified,
            Ok(Ok(UserConsentVerificationResult::Canceled)) => AuthResult::Rejected("cancelled".into()),
            Ok(Ok(UserConsentVerificationResult::RetriesExhausted)) => AuthResult::Rejected("too many failed tries".into()),
            Ok(Ok(UserConsentVerificationResult::DeviceBusy)) => AuthResult::Rejected("windows hello device is busy".into()),
            Ok(Ok(_)) => AuthResult::Rejected("windows hello did not verify".into()),
            Ok(Err(e)) => AuthResult::Rejected(format!("windows hello: {}", e.message())),
            Err(_) => {
                let _ = op.Cancel();
                AuthResult::Rejected("timed out waiting for windows hello".into())
            }
        }
    }
}
