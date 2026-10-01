use crate::{AuthResult, DeviceInfo, Prompt, Verifier};

pub struct TouchId;

impl Verifier for TouchId {
    fn backend(&self) -> &'static str {
        "touch-id"
    }
    fn probe(&self) -> Result<DeviceInfo, String> {
        Err("touch id backend not built yet".into())
    }
    fn verify(&self, _: &Prompt) -> AuthResult {
        AuthResult::Rejected("touch id backend not built yet".into())
    }
}
