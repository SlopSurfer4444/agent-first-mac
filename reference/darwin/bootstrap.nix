{ self, pkgs, bootstrapIdentity, ... }:

{
  assertions = [
    {
      assertion =
        builtins.match "^[A-Za-z_][A-Za-z0-9._-]*$" bootstrapIdentity.userName
        != null;
      message = "Set AID_BOOTSTRAP_USER to the existing local account name and evaluate with --impure.";
    }
    {
      assertion =
        builtins.match "^/Users/[A-Za-z_][A-Za-z0-9._-]*$"
          bootstrapIdentity.homeDirectory
        != null;
      message = "Set AID_BOOTSTRAP_HOME to the existing canonical /Users path and evaluate with --impure.";
    }
  ];

  nixpkgs.hostPlatform = "aarch64-darwin";

  nix = {
    enable = true;
    package = pkgs.lixPackageSets.lix_2_95.lix;
    settings.experimental-features = [ "nix-command" "flakes" ];
  };

  system = {
    configurationRevision = self.rev or self.dirtyRev or null;
    primaryUser = bootstrapIdentity.userName;
    stateVersion = 7;
  };

  users.users.${bootstrapIdentity.userName}.home =
    bootstrapIdentity.homeDirectory;

  environment.systemPackages = [ ];
}
