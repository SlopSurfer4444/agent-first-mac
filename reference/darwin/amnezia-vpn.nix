{ lib, pkgs, bootstrapIdentity, ... }:

let
  # False alone selects the historical legacy-app rollback state. The new
  # absent flag must also be true for a real managed-payload retirement.
  amneziaDesktopEnabled = false;
  # A third state: neither the desktop nor the historical legacy rollback app.
  amneziaDesktopAbsent = true;

  # The owner wants only the desktop build in /Applications and wants it
  # pinned in the Dock. Flipping both values is the recoverable rollback for
  # this cleanup: the exact legacy app returns from Trash and the Dock tile is
  # removed without touching VPN profiles, keys, or application data.
  legacyAppRetained = false;
  desktopDockPinned = true;

  amneziaPkg = pkgs.fetchurl {
    url = "https://github.com/amnezia-vpn/amnezia-client/releases/download/4.8.21.0/AmneziaVPN_4.8.21.0_macos.pkg";
    hash = "sha256-2jOSNu7xcolWGXyL+e2WoqIQRycBBubAqgYsnhQuOsc=";
  };
in
{
  system.activationScripts.extraActivation.text = lib.mkAfter ''
    echo "reconciling the owner-authorized AmneziaVPN desktop lifecycle..." >&2

    canonical=/Applications/AmneziaVPN.app
    legacy=/Applications/AmneziaVPN-iOS-4.8.19.app
    legacy_trash='${bootstrapIdentity.homeDirectory}/.Trash/AmneziaVPN-iOS-4.8.19.app'
    daemon=/Library/LaunchDaemons/AmneziaVPN.plist
    marker_dir=/var/db/agent-first-mac/amnezia-vpn
    marker=$marker_dir/managed-version
    retired=/var/db/agent-first-mac/amnezia-vpn-retired
    support='/Library/Application Support/AmneziaVPN'
    expected_marker='4.8.21|da339236eef1728956197c8bf9ed96a2a21047270106e6c0aa062c9e142e3ac7'
    staging=
    legacy_moved=0
    desktop_installed=0
    daemon_installed=0
    marker_installed=0
    legacy_trashed=0
    legacy_restored=0
    dock_added=0
    dock_removed=0
    dock_changed=0
    retired_created=0
    desktop_retired=0
    daemon_retired=0
    marker_retired=0
    support_pf_removed=0
    support_parent_removed=0
    service_was_loaded=0
    reactivation_dock_added=0
    reactivation_service_loaded=0
    reactivation_marker_restored=0
    reactivation_daemon_restored=0
    reactivation_desktop_restored=0
    reactivation_pf_created=0
    reactivation_parent_created=0
    owner_name='${bootstrapIdentity.userName}'
    owner_home='${bootstrapIdentity.homeDirectory}'
    owner_uid=$(/usr/bin/id -u -- "$owner_name")

    fail() {
      echo "AmneziaVPN lifecycle failure: $1" >&2
      return 1
    }

    plist_raw() {
      /usr/bin/plutil -extract "$2" raw -o - "$1/Contents/Info.plist" 2>/dev/null
    }

    team_id() {
      /usr/bin/codesign -d --verbose=4 "$1" 2>&1 \
        | /usr/bin/sed -n 's/^TeamIdentifier=//p' \
        | /usr/bin/sed -n '1p'
    }

    verify_legacy() {
      test -d "$1" \
        && test -d "$1/Wrapper/AmneziaVPN.app" \
        && test "$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$1/Wrapper/AmneziaVPN.app/Info.plist" 2>/dev/null)" = org.amnezia.AmneziaVPN \
        && test "$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$1/Wrapper/AmneziaVPN.app/Info.plist" 2>/dev/null)" = 4.8.19 \
        && test "$(team_id "$1/Wrapper/AmneziaVPN.app")" = X7UJ388FXK \
        && test "$(/usr/bin/shasum -a 256 "$1/Wrapper/AmneziaVPN.app/AmneziaVPN" | /usr/bin/awk '{print $1}')" = dcbeea0fdde339fe8c600c5b1b046449f958cabb98c559e63318a03bedba3437 \
        && test "$(/usr/bin/shasum -a 256 "$1/Wrapper/AmneziaVPN.app/Info.plist" | /usr/bin/awk '{print $1}')" = 4e943fece767bd84d1271d4ffe6985a38e59adcdb6562b92802e8b920a326af4
    }

    verify_desktop() {
      test -d "$1" \
        && test "$(plist_raw "$1" CFBundleIdentifier)" = com.yourcompany.AmneziaVPN \
        && test "$(plist_raw "$1" CFBundleShortVersionString)" = 4.8.21 \
        && test "$(team_id "$1")" = X7UJ388FXK \
        && /usr/bin/file "$1/Contents/MacOS/AmneziaVPN" | /usr/bin/grep -q 'x86_64' \
        && /usr/bin/codesign --verify --deep --strict "$1" >/dev/null 2>&1 \
        && /usr/sbin/spctl --assess --type execute "$1" >/dev/null 2>&1 \
        && test "$(/usr/bin/shasum -a 256 "$1/Contents/MacOS/AmneziaVPN-service" | /usr/bin/awk '{print $1}')" = 96858f0916e57f0e6bbae68cbc2b70e7eb5f3ad84a4f120c89a6defbda34cdbb \
        && test "$(/usr/bin/shasum -a 256 "$1/Contents/Resources/AmneziaVPN.plist" | /usr/bin/awk '{print $1}')" = e85a4836b4eee622d0bbce572cc356272758b77e7b707ce90041cc4c5bd17b8a
    }

    verify_daemon() {
      test ! -L "$1" && test -f "$1" \
        && test "$(/usr/bin/plutil -extract Label raw -o - "$1" 2>/dev/null)" = AmneziaVPN-service \
        && test "$(/usr/bin/plutil -extract ProgramArguments.0 raw -o - "$1" 2>/dev/null)" = /Applications/AmneziaVPN.app/Contents/MacOS/AmneziaVPN-service \
        && test "$(/usr/bin/plutil -extract Sockets.Listeners.SockFamily raw -o - "$1" 2>/dev/null)" = IPv4 \
        && test "$(/usr/bin/plutil -extract Sockets.Listeners.SockServiceName raw -o - "$1" 2>/dev/null)" = 5959 \
        && test "$(/usr/bin/plutil -extract Sockets.Listeners.SockType raw -o - "$1" 2>/dev/null)" = stream \
        && test "$(/usr/bin/plutil -extract Sockets.Listeners.SockNodeName raw -o - "$1" 2>/dev/null)" = 127.0.0.1 \
        && test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$1" 2>/dev/null)" = root:wheel:644 \
        && test "$(/usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}')" = 97f8b6cb06b1ed315ad6c4cf9a1c7c657ce8f420e400fe31c8c2a25493d76b85
    }

    verify_marker() {
      test ! -L "$1" && test -f "$1" \
        && test "$(/bin/cat "$1")" = "$expected_marker" \
        && test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$1" 2>/dev/null)" = root:wheel:644
    }

    verify_retired() {
      test ! -L "$retired" && test -d "$retired" \
        && test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$retired" 2>/dev/null)" = root:wheel:755 \
        && test "$(/usr/bin/find "$retired" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 3 \
        && test ! -L "$retired/AmneziaVPN.app" \
        && verify_desktop "$retired/AmneziaVPN.app" \
        && verify_daemon "$retired/AmneziaVPN.plist" \
        && verify_marker "$retired/managed-version"
    }

    verify_absent() {
      test ! -L /Applications && test ! -L /Library/LaunchDaemons \
        && test ! -L '/Library/Application Support' \
        && test ! -L /var/db/agent-first-mac \
        && test ! -L "$marker_dir" \
        && test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' /var/db/agent-first-mac 2>/dev/null)" = root:wheel:755 \
        && test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$marker_dir" 2>/dev/null)" = root:wheel:755 \
        && test ! -e "$canonical" && test ! -L "$canonical" \
        && test ! -e "$legacy" && test ! -L "$legacy" \
        && test ! -e "$daemon" && test ! -L "$daemon" \
        && test ! -e "$marker" && test ! -L "$marker" \
        && test ! -e "$support" && test ! -L "$support" \
        && ! /bin/launchctl print system/AmneziaVPN-service >/dev/null 2>&1 \
        && no_service_process_or_listener \
        && ! dock_has_desktop \
        && verify_retired
    }

    no_service_process_or_listener() {
      if /usr/bin/pgrep -f '^/Applications/AmneziaVPN.app/Contents/MacOS/AmneziaVPN-service([[:space:]]|$)' >/dev/null 2>&1; then
        process_status=0
      else
        process_status=$?
      fi
      if test "$process_status" != 1; then
        return 1
      fi
      listeners=$(/usr/sbin/netstat -anv -p tcp 2>/dev/null) || return 1
      if /usr/bin/printf '%s\n' "$listeners" \
          | /usr/bin/grep -E '[.:]5959[[:space:]].*LISTEN' >/dev/null; then
        return 1
      else
        test "$?" = 1
      fi
    }

    no_gui_process() {
      if /usr/bin/pgrep -x AmneziaVPN >/dev/null 2>&1; then
        return 1
      else
        test "$?" = 1
      fi
    }

    run_dockutil() {
      /bin/launchctl asuser "$owner_uid" \
        /usr/bin/sudo --user="$owner_name" --set-home \
        ${pkgs.dockutil}/bin/dockutil "$@"
    }

    dock_has_desktop() {
      run_dockutil --find "$canonical" "$owner_home" >/dev/null 2>&1
    }

    restart_owner_dock() {
      /usr/bin/killall -qu "$owner_name" Dock >/dev/null 2>&1 || true
    }

    verify_extras() {
      legacy_ok=0
      dock_ok=0
      ${lib.optionalString legacyAppRetained ''
        if verify_legacy "$legacy"; then legacy_ok=1; fi
      ''}
      ${lib.optionalString (!legacyAppRetained) ''
        if ! test -e "$legacy"; then legacy_ok=1; fi
      ''}
      ${lib.optionalString desktopDockPinned ''
        if dock_has_desktop; then dock_ok=1; fi
      ''}
      ${lib.optionalString (!desktopDockPinned) ''
        if ! dock_has_desktop; then dock_ok=1; fi
      ''}
      test "$legacy_ok" = 1 && test "$dock_ok" = 1
    }

    reconcile_extras() {
      case "$legacy_trash" in
        "$owner_home"/.Trash/AmneziaVPN-iOS-4.8.19.app) ;;
        *) fail unsafe_legacy_trash_path; return 1 ;;
      esac

      ${lib.optionalString legacyAppRetained ''
        if ! verify_legacy "$legacy"; then
          if test -e "$legacy" || ! verify_legacy "$legacy_trash"; then
            fail legacy_restore_source
            return 1
          fi
          /bin/mv -- "$legacy_trash" "$legacy"
          /usr/sbin/chown -R root:wheel "$legacy"
          legacy_restored=1
        fi
      ''}

      ${lib.optionalString (!legacyAppRetained) ''
        if test -e "$legacy"; then
          if ! verify_legacy "$legacy" || test -e "$legacy_trash"; then
            fail legacy_cleanup_identity_or_collision
            return 1
          fi
          /bin/mv -- "$legacy" "$legacy_trash"
          /usr/sbin/chown -R "$owner_name":staff "$legacy_trash"
          legacy_trashed=1
        fi
      ''}

      ${lib.optionalString desktopDockPinned ''
        if ! dock_has_desktop; then
          run_dockutil --add "$canonical" --after Happ --no-restart "$owner_home"
          dock_added=1
          dock_changed=1
        fi
      ''}

      ${lib.optionalString (!desktopDockPinned) ''
        if dock_has_desktop; then
          run_dockutil --remove "$canonical" --no-restart "$owner_home"
          dock_removed=1
          dock_changed=1
        fi
      ''}

      if test "$dock_changed" = 1; then
        restart_owner_dock
      fi
      verify_extras
    }

    rollback_extras() {
      if test "$dock_added" = 1; then
        run_dockutil --remove "$canonical" --no-restart "$owner_home" >/dev/null 2>&1 || true
      fi
      if test "$dock_removed" = 1; then
        run_dockutil --add "$canonical" --after Happ --no-restart "$owner_home" >/dev/null 2>&1 || true
      fi
      if test "$legacy_trashed" = 1 \
          && verify_legacy "$legacy_trash" \
          && ! test -e "$legacy"; then
        /bin/mv -- "$legacy_trash" "$legacy" || true
        /usr/sbin/chown -R root:wheel "$legacy" >/dev/null 2>&1 || true
      fi
      if test "$legacy_restored" = 1 \
          && verify_legacy "$legacy" \
          && ! test -e "$legacy_trash"; then
        /bin/mv -- "$legacy" "$legacy_trash" || true
        /usr/sbin/chown -R "$owner_name":staff "$legacy_trash" >/dev/null 2>&1 || true
      fi
      if test "$dock_changed" = 1; then
        restart_owner_dock
      fi
    }

    cleanup_staging() {
      if test -n "$staging"; then
        case "$staging" in
          /private/var/tmp/amnezia-desktop.*)
            /bin/rm -rf -- "$staging"
            ;;
          *)
            echo "refusing unsafe AmneziaVPN staging cleanup: $staging" >&2
            return 1
            ;;
        esac
      fi
    }

    restore_failed_install() {
      status=$?
      trap - EXIT
      rollback_extras
      /bin/launchctl bootout system/AmneziaVPN-service >/dev/null 2>&1 || true
      if test "$daemon_installed" = 1; then
        /bin/rm -f -- "$daemon"
      fi
      if test "$marker_installed" = 1; then
        /bin/rm -f -- "$marker"
      fi
      if test "$desktop_installed" = 1; then
        /bin/rm -rf -- "$canonical"
      fi
      if test "$legacy_moved" = 1 && verify_legacy "$legacy" && ! test -e "$canonical"; then
        /bin/mv -- "$legacy" "$canonical"
      fi
      cleanup_staging || true
      exit "$status"
    }

    restore_failed_extras() {
      status=$?
      trap - EXIT
      rollback_extras
      exit "$status"
    }

    restore_failed_removal() {
      status=$?
      trap - EXIT
      if test "$support_parent_removed" = 1; then
        /usr/bin/install -d -o root -g admin -m 0755 "$support" || status=1
      fi
      if test "$support_pf_removed" = 1; then
        /usr/bin/install -d -o root -g admin -m 0755 "$support/pf" || status=1
      fi
      if test "$marker_retired" = 1 && verify_marker "$retired/managed-version" \
          && ! test -e "$marker" && ! test -L "$marker"; then
        /bin/mv -- "$retired/managed-version" "$marker" || status=1
      fi
      if test "$daemon_retired" = 1 && verify_daemon "$retired/AmneziaVPN.plist" \
          && ! test -e "$daemon" && ! test -L "$daemon"; then
        /bin/mv -- "$retired/AmneziaVPN.plist" "$daemon" || status=1
      fi
      if test "$desktop_retired" = 1 && verify_desktop "$retired/AmneziaVPN.app" \
          && ! test -e "$canonical" && ! test -L "$canonical"; then
        /bin/mv -- "$retired/AmneziaVPN.app" "$canonical" || status=1
      fi
      if test "$retired_created" = 1; then
        /bin/rmdir -- "$retired" || status=1
      fi
      if test "$service_was_loaded" = 1 && verify_daemon "$daemon"; then
        /bin/launchctl bootstrap system "$daemon" || status=1
        /bin/launchctl enable system/AmneziaVPN-service || status=1
        /bin/launchctl kickstart -k system/AmneziaVPN-service || status=1
      fi
      if test "$dock_removed" = 1 && verify_desktop "$canonical"; then
        run_dockutil --add "$canonical" --after Happ --no-restart "$owner_home" || status=1
        restart_owner_dock
      fi
      if test "$status" != 0; then
        echo 'AmneziaVPN removal did not commit; verify exact rollback before retry' >&2
      fi
      exit "$status"
    }

    restore_failed_reactivation() {
      status=$?
      trap - EXIT
      if test "$reactivation_dock_added" = 1; then
        run_dockutil --remove "$canonical" --no-restart "$owner_home" >/dev/null 2>&1 || true
        restart_owner_dock
      fi
      if test "$reactivation_service_loaded" = 1; then
        /bin/launchctl bootout system/AmneziaVPN-service >/dev/null 2>&1 || true
      fi
      if test "$reactivation_marker_restored" = 1 && verify_marker "$marker"; then
        /bin/mv -- "$marker" "$retired/managed-version" || status=1
      fi
      if test "$reactivation_daemon_restored" = 1 && verify_daemon "$daemon"; then
        /bin/mv -- "$daemon" "$retired/AmneziaVPN.plist" || status=1
      fi
      if test "$reactivation_desktop_restored" = 1 && verify_desktop "$canonical"; then
        /bin/mv -- "$canonical" "$retired/AmneziaVPN.app" || status=1
      fi
      if test "$reactivation_pf_created" = 1; then
        /bin/rmdir -- "$support/pf" || status=1
      fi
      if test "$reactivation_parent_created" = 1; then
        /bin/rmdir -- "$support" || status=1
      fi
      echo 'AmneziaVPN reactivation failed; verify exact retired state before retry' >&2
      exit "$status"
    }

    reactivate_retired() {
      if ! verify_absent; then
        fail retired_state_drift
        return 1
      fi
      # Restoration must work even if Rosetta disappeared after installation.
      # It re-establishes the preceding payload, not a new runnable guarantee.
      reactivation_dock_added=0
      reactivation_service_loaded=0
      reactivation_marker_restored=0
      reactivation_daemon_restored=0
      reactivation_desktop_restored=0
      reactivation_pf_created=0
      reactivation_parent_created=0
      trap restore_failed_reactivation EXIT
      /usr/bin/install -d -o root -g admin -m 0755 "$support" || return 1
      reactivation_parent_created=1
      /usr/bin/install -d -o root -g admin -m 0755 "$support/pf" || return 1
      reactivation_pf_created=1
      /bin/mv -- "$retired/AmneziaVPN.app" "$canonical" || return 1
      reactivation_desktop_restored=1
      /bin/mv -- "$retired/AmneziaVPN.plist" "$daemon" || return 1
      reactivation_daemon_restored=1
      /bin/mv -- "$retired/managed-version" "$marker" || return 1
      reactivation_marker_restored=1
      /bin/launchctl bootstrap system "$daemon" || return 1
      reactivation_service_loaded=1
      /bin/launchctl enable system/AmneziaVPN-service || return 1
      if test -f /Library/Apple/usr/share/rosetta/rosetta; then
        /bin/launchctl kickstart -k system/AmneziaVPN-service || return 1
      fi
      run_dockutil --add "$canonical" --after Happ --no-restart "$owner_home" || return 1
      reactivation_dock_added=1
      restart_owner_dock
      if ! verify_desktop "$canonical" || ! verify_daemon "$daemon" \
          || ! verify_marker "$marker" || ! dock_has_desktop \
          || ! /bin/launchctl print system/AmneziaVPN-service >/dev/null 2>&1; then
        fail reactivation_poststate
        return 1
      fi
      /bin/rmdir -- "$retired" || return 1
      trap - EXIT
      return 0
    }

    amnezia_desktop_main() {
    ${lib.optionalString amneziaDesktopEnabled ''
      pkg='${amneziaPkg}'

      # A later unrelated nix-darwin activation must recognize the already
      # exact managed target before applying install-only environmental gates.
      # Otherwise a transient fallback-VPN state or an open GUI can block both
      # an idempotent switch and the broker's return to the previous generation.
      if test -f "$marker" \
          && test "$(/bin/cat "$marker")" = "$expected_marker" \
          && verify_desktop "$canonical" \
          && verify_daemon "$daemon"; then
        if ! verify_extras; then
          trap restore_failed_extras EXIT
          reconcile_extras
        fi
        if /bin/launchctl print system/AmneziaVPN-service >/dev/null 2>&1; then
          echo "AmneziaVPN desktop target is already exact" >&2
          trap - EXIT
          return 0
        fi
        /bin/launchctl bootstrap system "$daemon"
        /bin/launchctl enable system/AmneziaVPN-service
        /bin/launchctl kickstart -k system/AmneziaVPN-service
        /bin/launchctl print system/AmneziaVPN-service >/dev/null
        trap - EXIT
        return 0
      fi

      if verify_absent; then
        reactivate_retired
        return $?
      fi

      if ! test -f /Library/Apple/usr/share/rosetta/rosetta; then
        fail rosetta_missing
        return 1
      fi
      if ! /usr/sbin/scutil --nc list 2>/dev/null \
          | /usr/bin/grep -q 'Connected.*su\.ffg\.happ'; then
        fail fallback_vpn_not_connected
        return 1
      fi
      if /usr/bin/pgrep -x AmneziaVPN >/dev/null 2>&1; then
        fail amnezia_process_running
        return 1
      fi

      if ! verify_legacy "$canonical" \
          || test -e "$legacy" \
          || test -e "$daemon" \
          || test -e "$marker" \
          || /bin/launchctl print system/AmneziaVPN-service >/dev/null 2>&1; then
        fail unexpected_prestate
        return 1
      fi

      actual_pkg_hash=$(/usr/bin/shasum -a 256 "$pkg" | /usr/bin/awk '{print $1}')
      if test "$actual_pkg_hash" != da339236eef1728956197c8bf9ed96a2a21047270106e6c0aa062c9e142e3ac7; then
        fail package_hash
        return 1
      fi
      if ! /usr/sbin/pkgutil --check-signature "$pkg" 2>&1 \
          | /usr/bin/grep -q 'Developer ID Installer: Privacy Technologies OU (X7UJ388FXK)'; then
        fail package_signature
        return 1
      fi
      if ! /usr/sbin/spctl --assess --type install "$pkg" >/dev/null 2>&1; then
        fail package_notarization
        return 1
      fi

      staging=$(/usr/bin/mktemp -d /private/var/tmp/amnezia-desktop.XXXXXX)
      case "$staging" in
        /private/var/tmp/amnezia-desktop.*) ;;
        *) fail unsafe_staging; return 1 ;;
      esac
      trap restore_failed_install EXIT

      /usr/sbin/pkgutil --expand-full "$pkg" "$staging/expanded"
      extracted=$staging/expanded/AmneziaVPN_install.pkg/Payload/Applications/AmneziaVPN.app
      if ! verify_desktop "$extracted"; then
        fail extracted_application_identity
        return 1
      fi

      /bin/mv -- "$canonical" "$legacy"
      legacy_moved=1
      /usr/bin/ditto "$extracted" "$canonical"
      desktop_installed=1
      /usr/sbin/chown -R root:wheel "$canonical"
      /bin/chmod -R go-w "$canonical"
      if ! verify_desktop "$canonical"; then
        fail installed_application_identity
        return 1
      fi

      /usr/bin/ditto "$canonical/Contents/Resources/AmneziaVPN.plist" "$staging/AmneziaVPN.plist"
      /usr/bin/plutil -insert Sockets.Listeners.SockNodeName -string 127.0.0.1 "$staging/AmneziaVPN.plist"
      /usr/bin/plutil -lint "$staging/AmneziaVPN.plist" >/dev/null
      /usr/bin/install -o root -g wheel -m 0644 "$staging/AmneziaVPN.plist" "$daemon"
      daemon_installed=1
      if ! verify_daemon "$daemon"; then
        fail launch_daemon_identity
        return 1
      fi

      /bin/launchctl bootstrap system "$daemon"
      /bin/launchctl enable system/AmneziaVPN-service
      /bin/launchctl kickstart -k system/AmneziaVPN-service
      /bin/launchctl print system/AmneziaVPN-service >/dev/null

      /usr/bin/install -d -o root -g wheel -m 0755 "$marker_dir"
      /usr/bin/printf '%s\n' "$expected_marker" > "$marker"
      /usr/sbin/chown root:wheel "$marker"
      /bin/chmod 0644 "$marker"
      marker_installed=1

      reconcile_extras

      cleanup_staging
      staging=
      trap - EXIT
    ''}

    ${lib.optionalString amneziaDesktopAbsent ''
      # The retired directory contains only the signed app and exact managed
      # metadata; no profile, key, support file, or log is copied there.
      if verify_absent; then
        echo 'AmneziaVPN managed payload is already absent' >&2
        return 0
      fi
      if test -e "$retired" || test -L "$retired" \
          || test -L /Applications || test -L /Library/LaunchDaemons \
          || test -L '/Library/Application Support' \
          || test -L /var/db/agent-first-mac \
          || test -L "$canonical" || test -L "$legacy" \
          || test -L "$daemon" || test -L "$marker" \
          || test -L "$marker_dir" || test -L "$support" \
          || test -L "$support/pf" \
          || test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' /var/db/agent-first-mac 2>/dev/null)" != root:wheel:755 \
          || test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$marker_dir" 2>/dev/null)" != root:wheel:755 \
          || test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$support" 2>/dev/null)" != root:admin:755 \
          || test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$support/pf" 2>/dev/null)" != root:admin:755 \
          || test "$(/usr/bin/find "$support" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" != 1 \
          || test "$(/usr/bin/find "$support/pf" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l | /usr/bin/tr -d ' ')" != 0 \
          || ! verify_desktop "$canonical" \
          || ! verify_daemon "$daemon" \
          || ! verify_marker "$marker" \
          || test -e "$legacy" || test -L "$legacy" \
          || ! no_gui_process; then
        fail unexpected_removal_prestate
        return 1
      fi

      retired_created=0
      desktop_retired=0
      daemon_retired=0
      marker_retired=0
      support_pf_removed=0
      support_parent_removed=0
      service_was_loaded=0
      dock_removed=0
      if /bin/launchctl print system/AmneziaVPN-service >/dev/null 2>&1; then
        service_was_loaded=1
      fi
      trap restore_failed_removal EXIT
      /usr/bin/install -d -o root -g wheel -m 0755 "$retired" || return 1
      retired_created=1
      if dock_has_desktop; then
        run_dockutil --remove "$canonical" --no-restart "$owner_home" || return 1
        dock_removed=1
        restart_owner_dock
      fi
      if test "$service_was_loaded" = 1; then
        /bin/launchctl bootout system/AmneziaVPN-service || return 1
      fi
      if ! no_service_process_or_listener; then
        fail service_not_quiescent
        return 1
      fi
      /bin/mv -- "$canonical" "$retired/AmneziaVPN.app" || return 1
      desktop_retired=1
      /bin/mv -- "$daemon" "$retired/AmneziaVPN.plist" || return 1
      daemon_retired=1
      /bin/mv -- "$marker" "$retired/managed-version" || return 1
      marker_retired=1
      # These two observed system-owned directories are empty. rmdir is the
      # only permitted operation: an unexpected profile/file fails closed.
      /bin/rmdir -- "$support/pf" || return 1
      support_pf_removed=1
      /bin/rmdir -- "$support" || return 1
      support_parent_removed=1
      if ! verify_absent; then
        fail removal_poststate
        return 1
      fi
      trap - EXIT
      return 0
    ''}

    ${lib.optionalString (!amneziaDesktopEnabled && !amneziaDesktopAbsent) ''
      if verify_legacy "$canonical" \
          && ! test -e "$legacy" \
          && ! test -e "$daemon" \
          && ! test -e "$marker" \
          && ! /bin/launchctl print system/AmneziaVPN-service >/dev/null 2>&1; then
        echo "AmneziaVPN desktop rollback prestate is already exact" >&2
        return 0
      fi

      if /usr/bin/pgrep -x AmneziaVPN >/dev/null 2>&1; then
        fail amnezia_process_running
        return 1
      fi
      if ! verify_desktop "$canonical" \
          || ! verify_legacy "$legacy" \
          || ! verify_daemon "$daemon" \
          || ! test -f "$marker" \
          || test "$(/bin/cat "$marker")" != "$expected_marker"; then
        fail unexpected_managed_state
        return 1
      fi

      rollback_desktop=/Applications/AmneziaVPN-desktop-rollback-4.8.21.app
      if test -e "$rollback_desktop"; then
        fail rollback_collision
        return 1
      fi
      /bin/launchctl bootout system/AmneziaVPN-service >/dev/null 2>&1 || true
      /bin/mv -- "$canonical" "$rollback_desktop"
      /bin/mv -- "$legacy" "$canonical"
      if ! verify_legacy "$canonical"; then
        /bin/mv -- "$canonical" "$legacy" 2>/dev/null || true
        /bin/mv -- "$rollback_desktop" "$canonical" 2>/dev/null || true
        /bin/launchctl bootstrap system "$daemon" >/dev/null 2>&1 || true
        fail rollback_restore_legacy
        return 1
      fi
      /bin/rm -f -- "$daemon" "$marker"
      /bin/rm -rf -- "$rollback_desktop"
      /usr/bin/rmdir "$marker_dir" >/dev/null 2>&1 || true
    ''}
    }

    amnezia_desktop_main
  '';
}
