{ pkgs, bootstrapIdentity, ... }:

{
  # Package only. Authentication and credential-helper consent stay outside
  # declarative source; no tokens, browser state or login side effects in Nix.
  home-manager.users.${bootstrapIdentity.userName}.home.packages = [ pkgs.gh ];
}
