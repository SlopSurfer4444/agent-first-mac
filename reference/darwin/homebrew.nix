{ bootstrapIdentity, enableHomebrew, ... }:

{
  homebrew = {
    enable = enableHomebrew;
    user = bootstrapIdentity.userName;
    prefix = "/opt/homebrew";

    enableBashIntegration = false;
    enableFishIntegration = false;
    enableZshIntegration = false;

    global.autoUpdate = false;
    onActivation = {
      autoUpdate = false;
      upgrade = false;
      cleanup = "check";
    };

    taps = [ ];
    brews = [ ];
    casks = [ ];
    masApps = { };
  };
}
