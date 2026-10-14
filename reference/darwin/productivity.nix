{ lib, pkgs, bootstrapIdentity, ... }:

let
  # False defines the rollback prestate; true activates the reviewed target.
  # The manifest carries the same commit-bound state.
  productivityProfileEnabled = true;

  # False records Tahoe's current default (Automatic). The reviewed target
  # changes only this flag and its matching manifest value.
  fullColorWidgetsEnabled = true;

  # Owner override (2026-09-09): preserve Low Power Mode on battery while AC
  # remains unchanged at zero. Tahoe's 90 percent charge limit is independent.
  batteryLowPowerEnabled = true;

  # Released owner preferences are retained as historical/adopted values, not
  # replayed by every unrelated activation. Explicit reviewed keys alone write.
  managedPreferences = [ ];
  owns = key: builtins.elem key managedPreferences;
  preferenceDeclarations = {
    iconAppearance = { path = [ "NSGlobalDomain" "AppleIconAppearanceTheme" ]; value = "RegularAutomatic"; };
    automaticAppearance = { path = [ "NSGlobalDomain" "AppleInterfaceStyleSwitchesAutomatically" ]; value = true; };
    showFileExtensions = { path = [ "NSGlobalDomain" "AppleShowAllExtensions" ]; value = true; };
    initialKeyRepeat = { path = [ "NSGlobalDomain" "InitialKeyRepeat" ]; value = 15; };
    keyRepeat = { path = [ "NSGlobalDomain" "KeyRepeat" ]; value = 2; };
    trackpadScaling = { path = [ "NSGlobalDomain" "com.apple.trackpad.scaling" ]; value = 2.0; };
    widgetAppearance = { path = [ "CustomUserPreferences" "com.apple.widgets" "widgetAppearance" ]; value = 1; };
    dockAutohide = { path = [ "dock" "autohide" ]; value = false; };
    minimizeIntoApplicationIcon = { path = [ "dock" "minimize-to-application" ]; value = true; };
    reorderSpacesByRecentUse = { path = [ "dock" "mru-spaces" ]; value = false; };
    dockRecents = { path = [ "dock" "show-recents" ]; value = false; };
    bottomRightHotCornerRaw = { path = [ "dock" "wvous-br-corner" ]; value = 14; };
    finderPathBar = { path = [ "finder" "ShowPathbar" ]; value = true; };
    finderStatusBar = { path = [ "finder" "ShowStatusBar" ]; value = true; };
    tapToClick = { path = [ "trackpad" "Clicking" ]; value = true; };
    trackpadRightClick = { path = [ "trackpad" "TrackpadRightClick" ]; value = true; };
    threeFingerDrag = { path = [ "trackpad" "TrackpadThreeFingerDrag" ]; value = true; };
    stageManager = { path = [ "WindowManager" "GloballyEnabled" ]; value = false; };
    clickWallpaperToShowDesktop = { path = [ "WindowManager" "EnableStandardClickToShowDesktop" ]; value = true; };
    nativeWindowTiling = { path = [ "WindowManager" "EnableTilingByEdgeDrag" ]; value = true; };
    tiledWindowMargins = { path = [ "WindowManager" "EnableTiledWindowMargins" ]; value = false; };
    screenshotLocationClass = { path = [ "screencapture" "location" ]; value = screenshotsDirectory; };
  };
  selectedDefaults = lib.foldl' lib.recursiveUpdate { }
    (map (key: let item = preferenceDeclarations.${key};
              in lib.setAttrByPath item.path item.value)
         (builtins.filter (key: builtins.hasAttr key preferenceDeclarations) managedPreferences));

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

  system.defaults = selectedDefaults // {
    SoftwareUpdate.AutomaticallyInstallMacOSUpdates = true;
  };

  system.activationScripts.power.text = lib.mkAfter ''
    ${lib.optionalString (owns "screenshotLocationClass") ''
      /usr/bin/install -d -m 0700 \
        -o "${bootstrapIdentity.userName}" -g staff \
        "${screenshotsDirectory}"
    ''}

    ${lib.optionalString (owns "batteryLowPowerMode") ''
      /usr/bin/pmset -b lowpowermode \
        ${if batteryLowPowerEnabled then "1" else "0"}
    ''}
    ${lib.optionalString (owns "acLowPowerMode") ''
      /usr/bin/pmset -c lowpowermode 0
    ''}
  '';
}
