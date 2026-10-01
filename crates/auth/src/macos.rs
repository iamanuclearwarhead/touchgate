use std::sync::mpsc;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};

use crate::{AuthResult, DeviceInfo, Prompt, Verifier};

const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

pub struct TouchId;

fn error_text(code: isize) -> String {
    match code {
        -1 => "authentication failed".into(),
        -2 => "cancelled".into(),
        -3 => "fallback was chosen, touchgate only takes a fingerprint".into(),
        -4 => "cancelled by the system".into(),
        -5 => "no login password is set".into(),
        -6 => "no touch id sensor available".into(),
        -7 => "no fingerprints enrolled".into(),
        -8 => "touch id is locked out, unlock with your password first".into(),
        -9 => "cancelled by touchgate".into(),
        -10 => "invalid context".into(),
        -11 => "no paired companion device".into(),
        -1000 => "not interactive".into(),
        c => format!("touch id error {c}"),
    }
}

impl Verifier for TouchId {
    fn backend(&self) -> &'static str {
        "touch-id"
    }

    fn probe(&self) -> Result<DeviceInfo, String> {
        let ctx = unsafe { LAContext::new() };
        let can = unsafe { ctx.canEvaluatePolicy_error(POLICY) };
        let name = match unsafe { ctx.biometryType() } {
            LABiometryType::TouchID => "Touch ID",
            LABiometryType::FaceID => "Face ID",
            LABiometryType::OpticID => "Optic ID",
            _ => "biometrics",
        }
        .to_string();
        match can {
            Ok(()) => Ok(DeviceInfo {
                name,
                enrolled: vec!["enrolled".into()],
            }),
            Err(e) if e.code() == -7 => Ok(DeviceInfo { name, enrolled: Vec::new() }),
            Err(e) => Err(error_text(e.code())),
        }
    }

    fn verify(&self, prompt: &Prompt) -> AuthResult {
        let ctx = unsafe { LAContext::new() };
        if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(POLICY) } {
            return AuthResult::Rejected(error_text(e.code()));
        }
        unsafe { ctx.setLocalizedFallbackTitle(Some(&NSString::from_str(""))) };
        let mut text = format!("allow {}: {}", prompt.agent, prompt.action);
        if text.chars().count() > 150 {
            text = text.chars().take(147).collect::<String>() + "...";
        }
        let reason = NSString::from_str(&text);
        let (tx, rx) = mpsc::channel::<Result<(), isize>>();
        let block = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            let r = if ok.as_bool() {
                Ok(())
            } else {
                Err(unsafe { err.as_ref() }.map(|e| e.code()).unwrap_or(-1))
            };
            let _ = tx.send(r);
        });
        unsafe { ctx.evaluatePolicy_localizedReason_reply(POLICY, &reason, &block) };
        match rx.recv_timeout(prompt.timeout) {
            Ok(Ok(())) => AuthResult::Verified,
            Ok(Err(code)) => AuthResult::Rejected(error_text(code)),
            Err(_) => {
                unsafe { ctx.invalidate() };
                AuthResult::Rejected("timed out waiting for touch id".into())
            }
        }
    }
}
