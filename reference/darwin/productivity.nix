{ lib, pkgs, bootstrapIdentity, ... }:

let
  # False defines the rollback prestate; true activates the reviewed target.
  # The manifest carries the same commit-bound state.
  productivityProfileEnabled = true;

  # False records Tahoe's current default (Automatic). The reviewed target
  # changes only this flag and its matching manifest value.
  fullColorWidgetsEnabled = true;

  # Example policy: Low Power Mode on battery; AC remains unchanged at zero.
  # Battery charge limits are a separate setting.
  batteryLowPowerEnabled = true;

  screenshotsDirectory =
    "${bootstrapIdentity.homeDirectory}/Pictures/Screenshots";

  # The stock Darwin LocalSend derivation adds a wrapper and runs fixup over
  # the vendor bundle. That invalidates the notarized bundle's resource seal.
  # Preserve the exact fixed-output DMG payload and deliberately omit the CLI
  # wrapper so the installed application retains the vendor signature.
  localsendPreserved = pkgs.localsend.overrideAttrs (_old: {
    nativeBuildInputs = [ pkgs.undmg ];
    dontFixup = true;

    installPhase = ''
      runHook preInstall

      mkdir -p "$out/Applications"
      /usr/bin/ditto "LocalSend.app" "$out/Applications/LocalSend.app"

      runHook postInstall
    '';
  });

  productivityApplications = [
    pkgs.iina
    pkgs.keka
    localsendPreserved
    pkgs.raycast
    pkgs.shottr
  ];
in
{
  nixpkgs.config.allowUnfreePredicate = package:
    builtins.elem (lib.getName package) [ "keka" "raycast" "shottr" ];

  environment.systemPackages =
    lib.optionals productivityProfileEnabled productivityApplications;

  networking.applicationFirewall = {
    enable = true;
    blockAllIncoming = false;
    allowSigned = true;
    allowSignedApp = true;
    enableStealthMode = productivityProfileEnabled;
  };

  system.defaults = {
    SoftwareUpdate.AutomaticallyInstallMacOSUpdates = true;

    NSGlobalDomain = {
      # Owner override: preserve each app's native icon colors.
      AppleIconAppearanceTheme = "RegularAutomatic";
      AppleInterfaceStyleSwitchesAutomatically = productivityProfileEnabled;
      AppleShowAllExtensions = productivityProfileEnabled;
      InitialKeyRepeat = if productivityProfileEnabled then 15 else 25;
      KeyRepeat = if productivityProfileEnabled then 2 else 6;
      "com.apple.trackpad.scaling" =
        if productivityProfileEnabled then 2.0 else 0.875;
    };

    CustomUserPreferences."com.apple.widgets".widgetAppearance =
      if fullColorWidgetsEnabled then 1 else 0;

    dock = {
      # With autohide off, Dock stays visible normally and macOS still hides it
      # in full-screen application spaces.
      autohide = false;
      minimize-to-application = productivityProfileEnabled;
      mru-spaces = !productivityProfileEnabled;
      show-recents = !productivityProfileEnabled;
      # Restore the pre-change lower-right corner affordance.
      wvous-br-corner = 14;
    };

    finder = {
      AppleShowAllExtensions = productivityProfileEnabled;
      ShowPathbar = productivityProfileEnabled;
      ShowStatusBar = productivityProfileEnabled;
    };

    trackpad = {
      Clicking = true;
      TrackpadRightClick = true;
      TrackpadThreeFingerDrag = productivityProfileEnabled;
    };

    WindowManager = {
      GloballyEnabled = false;
      # Restore the original click-on-wallpaper desktop reveal behavior.
      EnableStandardClickToShowDesktop = true;
      EnableTilingByEdgeDrag = true;
      EnableTopTilingByEdgeDrag = true;
      EnableTilingOptionAccelerator = true;
      EnableTiledWindowMargins = false;
    };

    screencapture.location =
      if productivityProfileEnabled
      then screenshotsDirectory
      else "${bootstrapIdentity.homeDirectory}/Desktop";
  };

  system.activationScripts.power.text = lib.mkAfter ''
    echo "configuring the owner-authorized productivity baseline..." >&2

    ${lib.optionalString productivityProfileEnabled ''
      /usr/bin/install -d -m 0700 \
        -o "${bootstrapIdentity.userName}" -g staff \
        "${screenshotsDirectory}"
    ''}

    /usr/bin/pmset -b lowpowermode \
      ${if batteryLowPowerEnabled then "1" else "0"}
    /usr/bin/pmset -c lowpowermode 0
  '';
}
