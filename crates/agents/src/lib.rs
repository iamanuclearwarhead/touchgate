use std::fmt;
use std::str::FromStr;

use serde_json::{Value, json};
use touchgate_core::{Action, ToolKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
    Gemini,
}

impl Agent {
    pub const ALL: [Agent; 3] = [Agent::Claude, Agent::Codex, Agent::Gemini];

    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
            Agent::Gemini => "gemini",
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code",
            Agent::Codex => "Codex",
            Agent::Gemini => "Gemini CLI",
        }
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Agent {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Ok(Agent::Claude),
            "codex" => Ok(Agent::Codex),
            "gemini" | "gemini-cli" => Ok(Agent::Gemini),
            _ => Err(format!("unknown agent `{s}`, expected claude, codex or gemini")),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("hook input is not valid json")]
    Json(#[from] serde_json::Error),
    #[error("hook input has no tool_name")]
    NoTool,
}

pub fn parse(agent: Agent, input: &str) -> Result<Action, ParseError> {
    let v: Value = serde_json::from_str(input)?;
    let tool = v.get("tool_name").and_then(Value::as_str).ok_or(ParseError::NoTool)?;
    let ti = v.get("tool_input").cloned().unwrap_or(Value::Null);
    let cwd = v.get("cwd").and_then(Value::as_str).map(str::to_string);
    let mut a = match agent {
        Agent::Claude => claude(tool, &ti),
        Agent::Codex => codex(tool, &ti),
        Agent::Gemini => gemini(tool, &ti, v.get("mcp_context")),
    };
    a.agent = agent.name().to_string();
    if a.cwd.is_none() {
        a.cwd = cwd;
    }
    Ok(a)
}

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).filter(|x| !x.is_empty()).map(str::to_string)
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::String(x)) => vec![x.clone()],
        Some(Value::Array(xs)) => xs.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

fn with_paths(mut a: Action, paths: Vec<String>) -> Action {
    a.paths = paths;
    a
}

fn shell_action(tool: &str, command: Option<String>, cwd: Option<String>) -> Action {
    let mut a = Action::new("", tool, ToolKind::Shell);
    a.command = command;
    a.cwd = cwd;
    a
}

fn claude(tool: &str, ti: &Value) -> Action {
    match tool {
        "Bash" | "BashOutput" | "PowerShell" => shell_action(tool, s(ti, "command"), None),
        "Read" => with_paths(Action::new("", tool, ToolKind::Read), s(ti, "file_path").into_iter().collect()),
        "Grep" | "Glob" | "LS" => with_paths(Action::new("", tool, ToolKind::Read), s(ti, "path").into_iter().collect()),
        "Write" | "Edit" | "MultiEdit" => {
            with_paths(Action::new("", tool, ToolKind::Write), s(ti, "file_path").into_iter().collect())
        }
        "NotebookEdit" => with_paths(
            Action::new("", tool, ToolKind::Write),
            s(ti, "notebook_path").into_iter().collect(),
        ),
        "WebFetch" => {
            let mut a = Action::new("", tool, ToolKind::Fetch);
            a.url = s(ti, "url");
            a
        }
        t if t.starts_with("mcp__") => Action::new("", t, ToolKind::Mcp),
        t => Action::new("", t, ToolKind::Other),
    }
}

fn codex(tool: &str, ti: &Value) -> Action {
    match tool {
        "Bash" | "shell" | "exec_command" | "local_shell" | "unified_exec" => {
            let command = match ti.get("command").or_else(|| ti.get("cmd")) {
                Some(Value::String(c)) => Some(c.clone()),
                Some(Value::Array(parts)) => Some(join_argv(parts)),
                _ => None,
            };
            shell_action(tool, command, s(ti, "workdir"))
        }
        "apply_patch" | "Edit" | "Write" => {
            let body = s(ti, "patch").or_else(|| s(ti, "input")).or_else(|| s(ti, "command")).unwrap_or_default();
            let mut paths = patch_paths(&body);
            paths.extend(s(ti, "file_path"));
            with_paths(Action::new("", tool, ToolKind::Write), paths)
        }
        t if t.starts_with("mcp__") => Action::new("", t, ToolKind::Mcp),
        t => Action::new("", t, ToolKind::Other),
    }
}

fn gemini(tool: &str, ti: &Value, mcp: Option<&Value>) -> Action {
    if let Some(m) = mcp {
        let server = s(m, "server_name").unwrap_or_else(|| "unknown".into());
        let name = s(m, "tool_name").unwrap_or_else(|| tool.to_string());
        return Action::new("", format!("mcp__{server}__{name}"), ToolKind::Mcp);
    }
    match tool {
        "run_shell_command" => shell_action(tool, s(ti, "command"), s(ti, "dir_path")),
        "read_file" => with_paths(Action::new("", tool, ToolKind::Read), s(ti, "file_path").or_else(|| s(ti, "absolute_path")).into_iter().collect()),
        "read_many_files" => {
            let mut p = strings(ti, "include");
            p.extend(strings(ti, "paths"));
            with_paths(Action::new("", tool, ToolKind::Read), p)
        }
        "list_directory" | "glob" | "grep_search" | "search_file_content" => {
            with_paths(Action::new("", tool, ToolKind::Read), s(ti, "dir_path").or_else(|| s(ti, "path")).into_iter().collect())
        }
        "write_file" | "replace" => with_paths(Action::new("", tool, ToolKind::Write), s(ti, "file_path").into_iter().collect()),
        "web_fetch" => {
            let mut a = Action::new("", tool, ToolKind::Fetch);
            a.url = s(ti, "url").or_else(|| s(ti, "prompt").and_then(|p| first_url(&p)));
            a
        }
        t => Action::new("", t, ToolKind::Other),
    }
}

fn first_url(text: &str) -> Option<String> {
    text.split_whitespace()
        .find(|w| w.starts_with("http://") || w.starts_with("https://"))
        .map(|w| w.trim_end_matches(['.', ',', ')', '"', '\'']).to_string())
}

fn join_argv(parts: &[Value]) -> String {
    let argv: Vec<&str> = parts.iter().filter_map(Value::as_str).collect();
    if argv.len() >= 3 && matches!(argv[0].rsplit('/').next(), Some("bash" | "sh" | "zsh")) && argv[1].ends_with('c') && argv[1].starts_with('-') {
        return argv[2..].join(" ");
    }
    argv.iter().map(|p| quote(p)).collect::<Vec<_>>().join(" ")
}

fn quote(p: &str) -> String {
    if !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+%~".contains(c)) {
        p.to_string()
    } else {
        format!("'{}'", p.replace('\'', "'\\''"))
    }
}

pub fn patch_paths(patch: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in patch.lines() {
        for prefix in ["*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "] {
            if let Some(p) = line.strip_prefix(prefix) {
                out.push(p.trim().to_string());
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Approved(String),
    Denied(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub fn respond(agent: Agent, outcome: &Outcome) -> Response {
    let ok = |stdout: String| Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    };
    match (agent, outcome) {
        (_, Outcome::Pass) => ok(String::new()),
        (Agent::Claude, Outcome::Approved(reason)) => ok(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": reason,
            }
        })
        .to_string()),
        (Agent::Codex | Agent::Gemini, Outcome::Approved(_)) => ok(String::new()),
        (Agent::Claude | Agent::Codex, Outcome::Denied(reason)) => ok(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
        .to_string()),
        (Agent::Gemini, Outcome::Denied(reason)) => ok(json!({ "decision": "deny", "reason": reason }).to_string()),
    }
}

pub fn fail_closed(reason: &str) -> Response {
    Response {
        stdout: String::new(),
        stderr: format!("touchgate: {reason}"),
        exit_code: 2,
    }
}
