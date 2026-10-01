use serde_json::Value;
use touchgate_agents::{Agent, Outcome, parse, respond};
use touchgate_core::ToolKind;

#[test]
fn claude_payloads() {
    let bash = r#"{"session_id":"s","transcript_path":"/t","cwd":"/home/u/p","permission_mode":"bypassPermissions","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf dist","description":"clean"},"tool_use_id":"x"}"#;
    let a = parse(Agent::Claude, bash).unwrap();
    assert_eq!(a.kind, ToolKind::Shell);
    assert_eq!(a.command.as_deref(), Some("rm -rf dist"));
    assert_eq!(a.cwd.as_deref(), Some("/home/u/p"));
    assert_eq!(a.agent, "claude");

    let edit = r#"{"cwd":"/p","tool_name":"Edit","tool_input":{"file_path":"/p/.env","old_string":"a","new_string":"b"}}"#;
    let a = parse(Agent::Claude, edit).unwrap();
    assert_eq!(a.kind, ToolKind::Write);
    assert_eq!(a.paths, vec!["/p/.env"]);

    let mcp = r#"{"cwd":"/p","tool_name":"mcp__github__delete_repo","tool_input":{"repo":"x"}}"#;
    assert_eq!(parse(Agent::Claude, mcp).unwrap().kind, ToolKind::Mcp);

    let fetch = r#"{"cwd":"/p","tool_name":"WebFetch","tool_input":{"url":"https://x.dev","prompt":"p"}}"#;
    assert_eq!(parse(Agent::Claude, fetch).unwrap().url.as_deref(), Some("https://x.dev"));
}

#[test]
fn codex_payloads() {
    let bash = r#"{"session_id":"s","cwd":"/p","hook_event_name":"PreToolUse","model":"m","turn_id":"t","tool_name":"Bash","tool_use_id":"u","tool_input":{"command":["bash","-lc","git push --force"],"workdir":"/p/sub"},"permission_mode":"default"}"#;
    let a = parse(Agent::Codex, bash).unwrap();
    assert_eq!(a.command.as_deref(), Some("git push --force"));
    assert_eq!(a.cwd.as_deref(), Some("/p/sub"));

    let argv = r#"{"cwd":"/p","tool_name":"Bash","tool_input":{"command":["rm","-rf","my dir"]}}"#;
    assert_eq!(parse(Agent::Codex, argv).unwrap().command.as_deref(), Some("rm -rf 'my dir'"));

    let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n-x\n+y\n*** Add File: .env\n+K=V\n*** End Patch";
    let payload = serde_json::json!({"cwd":"/p","tool_name":"apply_patch","tool_input":{"input":patch}}).to_string();
    let a = parse(Agent::Codex, &payload).unwrap();
    assert_eq!(a.kind, ToolKind::Write);
    assert_eq!(a.paths, vec!["src/a.rs", ".env"]);
}

#[test]
fn gemini_payloads() {
    let shell = r#"{"session_id":"s","transcript_path":"/t","cwd":"/p","hook_event_name":"BeforeTool","timestamp":"now","tool_name":"run_shell_command","tool_input":{"command":"sudo rm -rf /","description":"x","dir_path":"/p"}}"#;
    let a = parse(Agent::Gemini, shell).unwrap();
    assert_eq!(a.kind, ToolKind::Shell);
    assert_eq!(a.command.as_deref(), Some("sudo rm -rf /"));

    let read = r#"{"cwd":"/p","tool_name":"read_file","tool_input":{"file_path":"/home/u/.ssh/id_rsa"}}"#;
    assert_eq!(parse(Agent::Gemini, read).unwrap().paths, vec!["/home/u/.ssh/id_rsa"]);

    let mcp = r#"{"cwd":"/p","tool_name":"delete_issue","tool_input":{},"mcp_context":{"server_name":"github","tool_name":"delete_issue","command":"gh-mcp"}}"#;
    let a = parse(Agent::Gemini, mcp).unwrap();
    assert_eq!(a.kind, ToolKind::Mcp);
    assert_eq!(a.tool_name, "mcp__github__delete_issue");

    let fetch = r#"{"cwd":"/p","tool_name":"web_fetch","tool_input":{"prompt":"summarize http://169.254.169.254/latest please"}}"#;
    assert_eq!(parse(Agent::Gemini, fetch).unwrap().url.as_deref(), Some("http://169.254.169.254/latest"));
}

#[test]
fn bad_input_is_an_error() {
    assert!(parse(Agent::Claude, "not json").is_err());
    assert!(parse(Agent::Claude, "{}").is_err());
}

#[test]
fn responses() {
    let deny = Outcome::Denied("no".into());
    let allow = Outcome::Approved("touched".into());

    let r = respond(Agent::Claude, &deny);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(r.exit_code, 0);

    let v: Value = serde_json::from_str(&respond(Agent::Claude, &allow).stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");

    let v: Value = serde_json::from_str(&respond(Agent::Codex, &deny).stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");

    let v: Value = serde_json::from_str(&respond(Agent::Gemini, &deny).stdout).unwrap();
    assert_eq!(v["decision"], "deny");
    assert_eq!(v["reason"], "no");

    for a in Agent::ALL {
        assert_eq!(respond(a, &Outcome::Pass).stdout, "");
    }
}
