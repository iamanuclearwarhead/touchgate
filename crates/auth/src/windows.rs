use crate::{AuthResult, DeviceInfo, Prompt, Verifier};

pub struct Hello;

impl Verifier for Hello {
    fn backend(&self) -> &'static str {
        "windows-hello"
    }
    fn probe(&self) -> Result<DeviceInfo, String> {
        Err("windows hello backend not built yet".into())
    }
    fn verify(&self, _: &Prompt) -> AuthResult {
        AuthResult::Rejected("windows hello backend not built yet".into())
    }
}
