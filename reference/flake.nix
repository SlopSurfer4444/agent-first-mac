{
  description = "Agent-First Mac Phase 2 package-control bootstrap";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/76fe02659c00bef75e12fbfdd45ca665115e9302";

    nix-darwin = {
      url = "github:nix-darwin/nix-darwin/c3e90c89649b07d1a96e4b9dd6cd0d6e44b91a74";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    home-manager = {
      url = "github:nix-community/home-manager/3cd22efe6471dc7365c822bd9ad73a21e55f38fb";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ self, nix-darwin, home-manager, ... }:
    let
      bootstrapIdentity = {
        userName = builtins.getEnv "AID_BOOTSTRAP_USER";
        homeDirectory = builtins.getEnv "AID_BOOTSTRAP_HOME";
      };

      mkBootstrap = enableHomebrew:
        nix-darwin.lib.darwinSystem {
          specialArgs = {
            inherit self bootstrapIdentity enableHomebrew;
          };
          modules = [
            ./darwin/bootstrap.nix
            ./darwin/productivity.nix
            ./darwin/amnezia-vpn.nix
            ./darwin/tailscale.nix
            ./darwin/windows-app.nix
            ./darwin/rustdesk-controller.nix
            ./darwin/gametomac.nix
            ./darwin/codex-bridge-drop.nix
            home-manager.darwinModules.home-manager
            ./darwin/home-manager.nix
            ./darwin/github-cli.nix
            ./darwin/aid.nix
            ./darwin/homebrew.nix
          ];
        };
    in
    {
      darwinConfigurations.bootstrap = mkBootstrap false;
      darwinConfigurations.bootstrap-with-homebrew = mkBootstrap true;
    };
}
