{ pkgs, ... }:

let
  automountScript = pkgs.writeTextFile {
    name = "codex-bridge-drop-automount";
    destination = "/bin/codex-bridge-drop-automount";
    executable = true;
    text = builtins.readFile ./codex-bridge-drop-automount.sh;
  };
in
{
  launchd.user.agents."codex-bridge-smb-tunnel" = {
    managedBy = "manifests/codex-bridge-drop-smb.json";
    serviceConfig = {
      Label = "com.aidev.codex-bridge.smb-tunnel";
      ProgramArguments = [
        "/usr/bin/ssh"
        "-N"
        "-T"
        "-o"
        "BatchMode=yes"
        "-o"
        "ExitOnForwardFailure=yes"
        "-o"
        "ServerAliveInterval=30"
        "-o"
        "ServerAliveCountMax=3"
        "-L"
        "127.0.0.1:14445:127.0.0.1:445"
        "windows-host"
      ];
      RunAtLoad = true;
      KeepAlive = true;
      ThrottleInterval = 15;
      ProcessType = "Background";
      StandardOutPath = "/dev/null";
      StandardErrorPath = "/dev/null";
    };
  };

  launchd.user.agents."codex-bridge-smb-automount" = {
    managedBy = "manifests/codex-bridge-drop-smb.json";
    serviceConfig = {
      Label = "com.aidev.codex-bridge.smb-automount";
      ProgramArguments = [
        "${automountScript}/bin/codex-bridge-drop-automount"
      ];
      RunAtLoad = true;
      StartInterval = 60;
      ProcessType = "Background";
      StandardOutPath = "/dev/null";
      StandardErrorPath = "/dev/null";
    };
  };
}
