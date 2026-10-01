use std::env;
use std::path::{Path, PathBuf};

use touchgate_agents::Agent;

#[derive(Debug, Clone)]
pub struct Locations {
    pub bin: PathBuf,
    pub policy: PathBuf,
    pub state: PathBuf,
    pub claude: PathBuf,
    pub codex: PathBuf,
    pub gemini: PathBuf,
}

impl Locations {
    pub fn system() -> Self {
        #[cfg(target_os = "macos")]
        {
            let lib = PathBuf::from("/Library/Application Support");
            Self {
                bin: PathBuf::from("/usr/local/bin/touchgate"),
                policy: lib.join("touchgate/policy.toml"),
                state: lib.join("touchgate/installed.json"),
                claude: lib.join("ClaudeCode/managed-settings.json"),
                codex: PathBuf::from("/etc/codex/requirements.toml"),
                gemini: lib.join("GeminiCli/settings.json"),
            }
        }
        #[cfg(windows)]
        {
            let pd = PathBuf::from(env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()));
            let pf = PathBuf::from(env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()));
            Self {
                bin: pf.join("touchgate\\touchgate.exe"),
                policy: pd.join("touchgate\\policy.toml"),
                state: pd.join("touchgate\\installed.json"),
                claude: pf.join("ClaudeCode\\managed-settings.json"),
                codex: pd.join("OpenAI\\Codex\\requirements.toml"),
                gemini: pd.join("gemini-cli\\settings.json"),
            }
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            let bin = if Path::new("/usr/bin/touchgate").exists() {
                PathBuf::from("/usr/bin/touchgate")
            } else {
                PathBuf::from("/usr/local/bin/touchgate")
            };
            Self {
                bin,
                policy: PathBuf::from("/etc/touchgate/policy.toml"),
                state: PathBuf::from("/etc/touchgate/installed.json"),
                claude: PathBuf::from("/etc/claude-code/managed-settings.json"),
                codex: PathBuf::from("/etc/codex/requirements.toml"),
                gemini: PathBuf::from("/etc/gemini-cli/settings.json"),
            }
        }
    }

    #[cfg(test)]
    pub fn under(root: &Path) -> Self {
        let s = Self::system();
        let re = |p: &Path| {
            let rel: PathBuf = p.components().filter(|c| matches!(c, std::path::Component::Normal(_))).collect();
            root.join(rel)
        };
        Self {
            bin: re(&s.bin),
            policy: re(&s.policy),
            state: re(&s.state),
            claude: re(&s.claude),
            codex: re(&s.codex),
            gemini: re(&s.gemini),
        }
    }

    pub fn agent_config(&self, agent: Agent) -> &Path {
        match agent {
            Agent::Claude => &self.claude,
            Agent::Codex => &self.codex,
            Agent::Gemini => &self.gemini,
        }
    }
}

pub fn home() -> PathBuf {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn user_policy() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(a) = env::var_os("APPDATA") {
            return PathBuf::from(a).join("touchgate\\policy.toml");
        }
    }
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".config"));
    base.join("touchgate/policy.toml")
}

pub fn audit_log() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(a) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(a).join("touchgate\\audit.jsonl");
        }
    }
    #[cfg(target_os = "macos")]
    {
        return home().join("Library/Logs/touchgate/audit.jsonl");
    }
    #[allow(unreachable_code)]
    {
        let base = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home().join(".local/state"));
        base.join("touchgate/audit.jsonl")
    }
}

pub fn hook_command(bin: &Path, agent: Agent) -> String {
    let b = bin.to_string_lossy();
    if b.contains(' ') {
        format!("\"{b}\" hook --agent {agent}")
    } else {
        format!("{b} hook --agent {agent}")
    }
}
