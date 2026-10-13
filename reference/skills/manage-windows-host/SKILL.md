---
name: manage-windows-host
description: Work on the owner's Windows host from this Mac through the configured windows-host SSH bridge, including remote repository work, Windows diagnostics and authorized host changes or file exchange. Use for Mac-to-Windows tasks; not for unrelated Windows advice or local Mac changes.
---

# Work on Windows from the Mac

The configured target is SSH alias `windows-host`. Use the existing alias, not a
remembered address or account. The Mac control source is `~/AIDev/control`;
the Windows machine has its own contracts. This skill supplies bridge context,
not permission to change either machine beyond the user's request.

## Choose the owner and connection

- For a remote repository, inspect its current `AGENTS.md` and Git state on
  Windows before edits. Example paths are
  `C:/AIDev/Workspaces/repos/example-project` and
  `C:/AIDev/Workspaces/repos/admin-project`; discover the actual authorized
  paths rather than using these placeholders. Windows host changes use the local administration
  contract, not the Mac's typed broker or old migration phase instructions.
- Prefer an already available native remote workspace for substantial repo
  work. SSH is suitable for bounded diagnostics and operations. Creating a
  separate Codex task still requires the user's request for a new task.
- When connectivity is uncertain, run the existing bounded client doctor:

  ```sh
  /usr/bin/python3 -B "$HOME/AIDev/control/bin/windows-host-ssh-client" doctor
  ```

  Its PASS proves strict key-only SSH smoke, not Windows application health.
  Read `~/AIDev/control/docs/windows-host-ssh-client.md` for a bridge failure.
  Do not weaken host-key checking, accept a new host key, use password fallback,
  read/copy private keys or change SSH/Tailscale settings to make a task pass.

## Shell and paths

The configured SSH shell is POSIX/Git Bash, **not PowerShell or cmd.exe**.
Use bounded noninteractive SSH, for example:

```sh
/usr/bin/ssh -o BatchMode=yes -o ConnectTimeout=10 windows-host 'printf "BRIDGE_OK\n"'
```

Git Bash paths such as `/c/AIDev/Workspaces/repos/admin-project` differ from native
Windows paths. Confirm the path in the shell consuming it. Avoid nesting
`cmd.exe /c` through Git Bash: argument/path conversion and encoding have
already caused failures in this bridge.

For Windows APIs, invoke `powershell.exe -NoLogo -NoProfile -NonInteractive`
explicitly. For scripts with quotes or dollar signs, encode the known script
locally as UTF-16LE then Base64 and pass it as `-EncodedCommand`; this avoids
both local and remote POSIX expansion. Encoding is quoting, not secrecy: never
embed credentials. Do not add `ExecutionPolicy Bypass`. Set terminating-error
behavior and a nonzero failure exit when the task requires reliable status;
for machine-readable probes use `-OutputFormat Text` and suppress PowerShell
progress with `$ProgressPreference = 'SilentlyContinue'` in the known script
(Windows PowerShell 5.1 can otherwise emit CLIXML progress). Capture only the
requested bounded result. Do not infer success from empty
output. Long-running work needs its actual native process/completion handle,
not an unobserved background launch or a duplicate after a disconnect.

## File exchange and connector issues

`C:\CodexBridgeDrop` is the existing exchange folder. SFTP over `windows-host` is
the agent transfer path; `/Volumes/CodexBridgeDrop` is a Finder convenience
mount and may be absent. Confirm remote SFTP paths before a transfer and bind
source/destination explicitly. Do not overwrite an existing unrelated file.
Read `~/AIDev/control/docs/codex-bridge-drop-smb.md` only for share/mount issues;
do not open firewall ports or extract Keychain credentials.

SSH availability and Codex Remote Control registration are separate. For a
connector problem, read
`~/AIDev/control/docs/codex-windows-host-ssh-remote-control-isolation.md` and the
relevant holder/stdio docs there. Preserve the existing SSH-session isolation,
DefaultShell and foreground app-server ownership; do not start a second holder
or change server configuration as an incidental repository fix.

Report what was actually checked or changed on which host. Keep credentials,
private keys, account names, overlay addresses and host-key fingerprints out
of ordinary Git and saved evidence. A Windows reboot, service restart or
destructive operation must be within the actual task and remote contract;
this skill does not preauthorize those operations.
