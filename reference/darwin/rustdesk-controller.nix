{ lib, pkgs, ... }:

let
  rustDeskControllerEnabled = true;

  rustDeskDmg = pkgs.fetchurl {
    name = "rustdesk-1.4.6-aarch64.dmg";
    url = "https://github.com/rustdesk/rustdesk/releases/download/1.4.6/rustdesk-1.4.6-aarch64.dmg";
    hash = "sha256-DNSY4/mch4v6PFSZYIm5Zx/dFa7l0awWBESEH5XqAbw=";
  };

  managedMarker = pkgs.writeText "rustdesk-controller-managed-source" ''
    1.4.6|0cd498e3f99c878bfa3c54996089b9671fdd15aee5d1ac160444841f95ea01bc
  '';
in
{
  system.activationScripts.extraActivation.text = lib.mkAfter ''
    # aid-admin-resume-rustdesk-marker-guards-v1
    echo "reconciling the owner-authorized RustDesk controller lifecycle..." >&2

    app=/Applications/RustDesk.app
    marker_dir=/var/db/agent-first-mac/rustdesk-controller
    marker=$marker_dir/managed-source
    expected_marker='1.4.6|0cd498e3f99c878bfa3c54996089b9671fdd15aee5d1ac160444841f95ea01bc'
    dmg='${rustDeskDmg}'
    marker_source='${managedMarker}'

    fail() {
      echo "RustDesk controller lifecycle failure: $1" >&2
      # Abort even when called from an if/|| context; do not rely on set -e.
      exit 1
    }

    plist_raw() {
      /usr/bin/plutil -extract "$2" raw -o - "$1/Contents/Info.plist" 2>/dev/null
    }

    team_id() {
      /usr/bin/codesign -d --verbose=4 "$1" 2>&1 \
        | /usr/bin/sed -n 's/^TeamIdentifier=//p' \
        | /usr/bin/sed -n '1p'
    }

    verify_app() {
      test -d "$1" && ! test -L "$1" || return 1
      test "$(plist_raw "$1" CFBundleIdentifier)" = com.carriez.rustdesk \
        || return 1
      test "$(plist_raw "$1" CFBundleShortVersionString)" = 1.4.6 \
        || return 1
      test "$(team_id "$1")" = HZF9JMC8YN || return 1
      /usr/bin/codesign --verify --deep --strict "$1" >/dev/null 2>&1 \
        || return 1
      /usr/sbin/spctl --assess --type execute "$1" >/dev/null 2>&1 \
        || return 1
      test -x "$1/Contents/MacOS/RustDesk"
    }

    no_marker_acl() {
      # POSIX mode bits alone do not exclude ACL-granted non-root writers.
      acl_listing=$(/bin/ls -lde "$1" 2>/dev/null) || return 1
      test -n "$acl_listing" || return 1
      case "$acl_listing" in
        ??????????+*|*"
"*) return 1 ;;
      esac
    }

    safe_marker_directory() {
      test -d "$1" && ! test -L "$1" || return 1
      case "$(/usr/bin/stat -f '%u:%Lp' "$1" 2>/dev/null)" in
        0:7[0145][0145]) ;;
        *) return 1 ;;
      esac
      no_marker_acl "$1"
    }

    marker_prestate() {
      test -f "$marker_source" && ! test -L "$marker_source" || return 1
      safe_marker_directory /var/db/agent-first-mac || return 1
      if test -e "$marker_dir" || test -L "$marker_dir"; then
        safe_marker_directory "$marker_dir" || return 1
      fi
      if test -e "$marker" || test -L "$marker"; then
        test -f "$marker" && ! test -L "$marker" \
          && test "$(/usr/bin/stat -f '%u:%Lp:%l' "$marker" 2>/dev/null)" = 0:644:1 \
          && no_marker_acl "$marker" \
          && /usr/bin/cmp -s "$marker_source" "$marker" || return 1
      fi
    }

    install_marker() {
      marker_prestate || return 1
      if test -e "$marker"; then return 0; fi
      if ! test -d "$marker_dir"; then
        /usr/bin/install -d -o root -g wheel -m 0755 "$marker_dir" || return 1
      fi
      # The broker serializes root operations; this parent excludes non-root
      # writers. A competing root is outside this minimal marker contract.
      marker_prestate || return 1
      ! test -e "$marker" && ! test -L "$marker" || return 1
      /usr/bin/install -o root -g wheel -m 0644 "$marker_source" "$marker" || return 1
      marker_prestate
    }

    verify_managed() {
      verify_app "$app" \
        && test -f "$marker" \
        && test "$(/bin/cat "$marker")" = "$expected_marker"
    }

    marker_prestate || fail conflicting_or_unsafe_managed_marker
    if ${if rustDeskControllerEnabled then "true" else "false"}; then
      if ! verify_managed; then
        if test -e "$app" || test -L "$app"; then
          verify_app "$app" || fail competing_or_untrusted_application
        else
          test "$(/usr/bin/shasum -a 256 "$dmg" | /usr/bin/awk '{print $1}')" \
            = 0cd498e3f99c878bfa3c54996089b9671fdd15aee5d1ac160444841f95ea01bc \
            || fail source_checksum
          staging=$(/usr/bin/mktemp -d /private/var/tmp/rustdesk-controller.XXXXXX) \
            || fail staging
          case "$staging" in
            /private/var/tmp/rustdesk-controller.*) ;;
            *) fail staging_path ;;
          esac
          mount=$staging/mount
          /bin/mkdir "$mount" || fail mount_directory
          cleanup() {
            /usr/bin/hdiutil detach "$mount" >/dev/null 2>&1 || true
            /bin/rm -rf -- "$staging"
          }
          trap cleanup EXIT
          /usr/bin/hdiutil attach -readonly -nobrowse -noverify \
            -mountpoint "$mount" "$dmg" >/dev/null || fail mount_source
          verify_app "$mount/RustDesk.app" || fail source_application
          /usr/bin/ditto "$mount/RustDesk.app" "$app" || fail copy_application
          verify_app "$app" || fail installed_application
          cleanup
          trap - EXIT
        fi

        install_marker || fail managed_marker
        verify_managed || fail final_verification
      fi
    else
      if test -f "$marker" \
        && test "$(/bin/cat "$marker")" = "$expected_marker" \
        && verify_app "$app"; then
        /bin/rm -rf -- "$app" || fail remove_application
        /bin/rm -f -- "$marker" || fail remove_marker
        /bin/rmdir "$marker_dir" 2>/dev/null || true
      elif test -e "$app" || test -e "$marker"; then
        fail unmanaged_or_drifted_removal_state
      fi
    fi
  '';
}
