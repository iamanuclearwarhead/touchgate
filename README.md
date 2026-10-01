# touchgate

fingerprint approval for risky ai agent actions

your agent wants to `rm -rf ~/Projects`, force push, read `~/.ssh` or run `curl | sh`. touchgate pauses it and asks for your fingerprint first. touch the sensor and it goes through, do nothing and it gets denied. everything else runs like normal so you dont end up turning it off

works with claude code, codex and gemini cli. uses fprintd on linux, touch id on macos and windows hello on windows

## why

agents run with your permissions. `--dangerously-skip-permissions` and auto modes are great until the one command you didnt read. normal permission prompts get clicked through, and a hook in your own settings can be edited by the same agent it is supposed to stop

touchgate puts its hook and its rules in your agents' **managed** config, the admin level files that user and project settings cant override, and those files are owned by root. so the agent cant just edit its way past it. and the approval is your finger, not a y/n the agent could type

## install

### arch

```sh
yay -S touchgate-git
sudo touchgate install
touchgate doctor
```

### from source

```sh
cargo install --git https://github.com/iamanuclearwarhead/touchgate
sudo touchgate install
touchgate doctor
```

on windows run `touchgate install` from an admin terminal

> you need a fingerprint reader with at least one finger enrolled. on linux thats fprintd (`fprintd-enroll`), on macos touch id, on windows a hello fingerprint, face or pin

## usage

```
touchgate install             gate every supported agent (sudo)
touchgate install --lock      also block hooks added outside managed config
touchgate doctor              check the reader, the install and known bypasses
touchgate test rm -rf build   what would happen with this command
touchgate test --read .env    or with a file, --write, --fetch, --mcp
touchgate test --verify ...   same but actually ask for the fingerprint
touchgate log                 recent touches and denials
touchgate uninstall           take the hooks back out (sudo)
```

## what needs a touch

out of the box:

- deleting stuff, `rm -r`, `rm -f`, `find -delete`, `shred`
- `sudo`, `doas`, `pkexec` and friends
- git history rewrites, force push, `reset --hard`, `clean -f`, `branch -D`
- disks, `dd of=`, `mkfs`, `fdisk`, mounts
- publishing, `npm publish`, `cargo publish`, `docker push`, `gh release`
- live infra, `kubectl delete`, `terraform apply`, cloud clis
- databases, `DROP TABLE`, `FLUSHALL`, `db:drop`
- secrets, `~/.ssh`, `~/.aws`, `.env`, keys, browser profiles, password stores
- startup files, `~/.bashrc`, autostart, systemd units, git hooks
- the agent's own settings files
- sending files out, `curl -F @file`, `nc`, `scp` to a remote
- mcp tools that delete, send, merge, publish or pay
- anything it cant read: `curl | sh`, `eval "$x"`, base64 into bash, `python -c` that shells out

commands are parsed properly, so `ls && rm -rf x`, `$(rm -rf x)`, `bash -c '...'`, `sudo env nohup rm -rf x`, `xargs rm` and `find -exec rm` all get caught

writes to touchgate's own config and the managed agent configs are always denied

## rules

`/etc/touchgate/policy.toml` (macos `/Library/Application Support/touchgate/`, windows `%ProgramData%\touchgate\`) is yours. its rules run before the built in ones, first match wins

```toml
timeout = 45

[[rule]]
name = "build-dirs"
tool = ["shell"]
command = ['^rm -rf (target|dist|node_modules)$']
action = "allow"

[[rule]]
name = "prod"
tool = ["shell"]
command = ['--context[= ]prod']
action = "deny"
```

- `tool`: `shell`, `read`, `write`, `fetch`, `mcp`, `other`
- matchers: `command` (regex on each command), `path` (globs, `~` works), `url` (regex), `tool_name` (globs), `flag` (`obfuscated`, `dynamic-command`, `shell-from-stdin`, `inline-code-exec`, `unparsed`)
- `action`: `allow`, `touch` or `deny`
- `builtin = false` drops the built in rules, `default = "touch"` makes unmatched things need a touch too

`~/.config/touchgate/policy.toml` works the same but can only make things stricter, `allow` rules there are ignored

## how it works

`touchgate install` adds a pre tool hook to

- claude code `/etc/claude-code/managed-settings.json`
- codex `/etc/codex/requirements.toml`
- gemini cli `/etc/gemini-cli/settings.json`

(or the macos and windows equivalents) and copies itself to `/usr/local/bin`. every tool call goes through `touchgate hook`, which parses it, checks the rules and either lets it pass, asks for a finger, or denies it with a reason the agent can read. if anything goes wrong, bad input, broken rules, a crash, it denies

existing files are merged, not replaced, and a `.touchgate-backup` copy is kept

## what it does not do

this is a speed bump with a fingerprint, not a sandbox

- it only sees what goes through the agent's tool calls. a script the agent writes and then runs with an innocent looking command is not inspected
- passwordless sudo lets anything undo it, `touchgate doctor` warns you
- gemini cli reads `GEMINI_CLI_SYSTEM_SETTINGS_PATH` from your env, if thats set the managed hook is skipped. doctor checks for it
- regexes miss things. if you find a bypass, open an issue

for real isolation run agents in a container or vm, and use touchgate on top

## status

- linux with fprintd: tested on a real reader
- macos touch id and windows hello: build, not tested on hardware yet
- claude code, codex, gemini cli: hook formats from each agent's docs and source, live tests are next

if you try it anywhere, tell me how it went

## notes

- the hook gives you 45 seconds to touch, change it with `timeout` (max 80, agents kill hooks that take too long)
- fprintd can only be used by one thing at a time, if your lock screen or another prompt has the reader, touchgate denies
- the decision log lives in `~/.local/state/touchgate/audit.jsonl`

## license

mit or apache-2.0, see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE)
