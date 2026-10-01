use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone)]
pub struct Prompt {
    pub agent: String,
    pub action: String,
    pub reason: String,
    pub timeout: Duration,
}

impl Prompt {
    pub fn headline(&self) -> String {
        format!("{} wants to run something risky", self.agent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Verified,
    Rejected(String),
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub enrolled: Vec<String>,
}

pub trait Verifier {
    fn backend(&self) -> &'static str;
    fn probe(&self) -> Result<DeviceInfo, String>;
    fn verify(&self, prompt: &Prompt) -> AuthResult;
}

pub fn platform() -> Box<dyn Verifier> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::Fprintd)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::TouchId)
    }
    #[cfg(windows)]
    {
        Box::new(windows::Hello)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Box::new(Unsupported)
    }
}

pub struct Unsupported;

impl Verifier for Unsupported {
    fn backend(&self) -> &'static str {
        "none"
    }
    fn probe(&self) -> Result<DeviceInfo, String> {
        Err("no biometric backend for this platform".into())
    }
    fn verify(&self, _: &Prompt) -> AuthResult {
        AuthResult::Rejected("no biometric backend for this platform".into())
    }
}

pub struct Fixed(pub AuthResult);

impl Verifier for Fixed {
    fn backend(&self) -> &'static str {
        "fixed"
    }
    fn probe(&self) -> Result<DeviceInfo, String> {
        Ok(DeviceInfo {
            name: "fixed".into(),
            enrolled: vec!["any".into()],
        })
    }
    fn verify(&self, _: &Prompt) -> AuthResult {
        self.0.clone()
    }
}
