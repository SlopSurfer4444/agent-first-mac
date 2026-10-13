{ bootstrapIdentity, ... }:

{
  home-manager = {
    useGlobalPkgs = true;
    useUserPackages = true;

    users.${bootstrapIdentity.userName} = {
      home = {
        username = bootstrapIdentity.userName;
        homeDirectory = bootstrapIdentity.homeDirectory;
        stateVersion = "26.05";
        packages = [ ];
      };

      programs.home-manager.enable = true;
    };
  };
}
