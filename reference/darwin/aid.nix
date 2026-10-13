{ pkgs, lib, bootstrapIdentity, ... }:

let
  # One managed launcher, two stable names. The payload is accepted canonical
  # control source, just like the existing source-routed diagnostics.
  # Use the macOS shell for this macOS-specific trampoline. Native probes
  # showed that the Nix Bash launch chain adds com.apple.provenance to fresh
  # fixture directories; the unchanged private-fixture gate rejects that.
  # Do not strip attributes or weaken the fixture admission policy.
  aidLauncher = pkgs.writeTextFile {
    name = "aid";
    destination = "/bin/aid";
    executable = true;
    text = ''
      #!/bin/sh
      exec /usr/bin/python3 ${lib.escapeShellArg "${bootstrapIdentity.homeDirectory}/AIDev/control/bin/aid"} "$@"
    '';
  };
in
{
  home-manager.users.${bootstrapIdentity.userName} = {
    home.packages = [ aidLauncher ];
    # Home Manager refuses an unmanaged collision; never force/overwrite it.
    home.file."AIDev/bin/aid".source = "${aidLauncher}/bin/aid";
  };
}
