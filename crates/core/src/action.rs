use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolKind {
    Shell,
    Read,
    Write,
    Fetch,
    Mcp,
    Other,
}

impl ToolKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "shell" | "bash" => Some(Self::Shell),
            "read" => Some(Self::Read),
            "write" | "edit" => Some(Self::Write),
            "fetch" | "web" => Some(Self::Fetch),
            "mcp" => Some(Self::Mcp),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

impl fmt::Display for ToolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Shell => "shell",
            Self::Read => "read",
            Self::Write => "write",
            Self::Fetch => "fetch",
            Self::Mcp => "mcp",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Action {
    pub agent: String,
    pub tool_name: String,
    pub kind: ToolKind,
    pub command: Option<String>,
    pub paths: Vec<String>,
    pub url: Option<String>,
    pub cwd: Option<String>,
}

impl Action {
    pub fn new(agent: impl Into<String>, tool_name: impl Into<String>, kind: ToolKind) -> Self {
        Self {
            agent: agent.into(),
            tool_name: tool_name.into(),
            kind,
            command: None,
            paths: Vec::new(),
            url: None,
            cwd: None,
        }
    }

    pub fn summary(&self, max: usize) -> String {
        let body = match self.kind {
            ToolKind::Shell => self.command.clone().unwrap_or_default(),
            ToolKind::Read => format!("read {}", self.paths.join(", ")),
            ToolKind::Write => format!("write {}", self.paths.join(", ")),
            ToolKind::Fetch => format!("fetch {}", self.url.clone().unwrap_or_default()),
            ToolKind::Mcp | ToolKind::Other => self.tool_name.clone(),
        };
        let line: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
        if line.chars().count() <= max {
            line
        } else {
            let cut: String = line.chars().take(max.saturating_sub(3)).collect();
            format!("{cut}...")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Touch,
    Deny,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Touch => "touch",
            Self::Deny => "deny",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub rule: Option<String>,
    pub reason: String,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            verdict: Verdict::Allow,
            rule: None,
            reason: "no rule matched".into(),
        }
    }
}
