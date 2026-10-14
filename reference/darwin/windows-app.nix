{ lib, pkgs, ... }:

let
  windowsAppEnabled = true;

  windowsAppPkg = pkgs.fetchurl {
    name = "WindowsApp-11.3.8.pkg";
    url = "https://go.microsoft.com/fwlink/?linkid=868963";
    hash = "sha256-RwUuCrqNWyrZpUaDSfcr7jF7acBzAKQMyt77lgULElE=";
  };

  managedMarker = pkgs.writeText "windows-app-managed-source" ''
    11.3.8|47052e0aba8d5b2ad9a5468349f72bee317b69c07300a40ccadefb96050b1251
  '';
in
{
  system.activationScripts.extraActivation.text = lib.mkAfter ''
    # aid-admin-resume-windows-marker-guards-v1
    echo "reconciling the owner-authorized Windows App lifecycle..." >&2

    app='/Applications/Windows App.app'
    receipt=com.microsoft.rdc.macos
    marker_dir=/var/db/agent-first-mac/windows-app
    marker=$marker_dir/managed-source
    expected_marker='11.3.8|47052e0aba8d5b2ad9a5468349f72bee317b69c07300a40ccadefb96050b1251'
    pkg='${windowsAppPkg}'
    marker_source='${managedMarker}'

    fail() {
      echo "Windows App lifecycle failure: $1" >&2
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

    version_at_least() {
      actual=$1
      floor=$2
      case "$actual" in
        ""|.*|*.|*..*|*[!0-9.]*) return 1 ;;
      esac
      /usr/bin/awk -v actual="$actual" -v floor="$floor" 'BEGIN {
        an = split(actual, a, "."); fn = split(floor, f, ".");
        n = an > fn ? an : fn;
        for (i = 1; i <= n; i++) {
          av = i <= an ? a[i] + 0 : 0;
          fv = i <= fn ? f[i] + 0 : 0;
          if (av > fv) exit 0;
          if (av < fv) exit 1;
        }
        exit 0;
      }'
    }

    verify_app() {
      test -d "$app" && ! test -L "$app" || return 1
      test "$(plist_raw "$app" CFBundleIdentifier)" = com.microsoft.rdc.macos \
        || return 1
      app_version=$(plist_raw "$app" CFBundleShortVersionString) || return 1
      version_at_least "$app_version" 11.3.8 || return 1
      test "$(team_id "$app")" = UBF8T346G9 || return 1
      /usr/bin/codesign --verify --deep --strict "$app" >/dev/null 2>&1 \
        || return 1
      /usr/sbin/spctl --assess --type execute "$app" >/dev/null 2>&1 \
        || return 1
      test -x "$app/Contents/MacOS/Windows App"
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
      # Exact existing ownership is a real no-op, not a marker rewrite.
      if test -e "$marker"; then return 0; fi
      if ! test -d "$marker_dir"; then
        /usr/bin/install -d -o root -g wheel -m 0755 "$marker_dir" || return 1
      fi
      # The broker holds the one root-operation owner. Parent admission excludes
      # unprivileged writers; this is not protection against a competing root.
      marker_prestate || return 1
      ! test -e "$marker" && ! test -L "$marker" || return 1
      /usr/bin/install -o root -g wheel -m 0644 "$marker_source" "$marker" || return 1
      marker_prestate
    }

    install_receipts_absent() {
      # A successful complete inventory distinguishes absence from probe error.
      # Never print inventory, and never replay vendor scripts over a partial
      # receipt merely because the application directory is currently absent.
      receipt_inventory=$(/usr/sbin/pkgutil --pkgs) || return 1
      case "
$receipt_inventory
" in
        *"
$receipt
"*|*"
com.microsoft.rdc.installer.scripts
"*) return 1 ;;
      esac
      return 0
    }

    verify_managed() {
      verify_app \
        && test -f "$marker" \
        && test "$(/bin/cat "$marker")" = "$expected_marker"
    }

    marker_prestate || fail conflicting_or_unsafe_managed_marker
    if ${if windowsAppEnabled then "true" else "false"}; then
      if ! verify_managed; then
        if test -e "$app" || test -L "$app"; then
          verify_app || fail competing_or_untrusted_application
        else
          install_receipts_absent || fail partial_or_unobserved_package_receipts
          test "$(/usr/bin/shasum -a 256 "$pkg" | /usr/bin/awk '{print $1}')" \
            = 47052e0aba8d5b2ad9a5468349f72bee317b69c07300a40ccadefb96050b1251 \
            || fail package_checksum
          signature=$(/usr/sbin/pkgutil --check-signature "$pkg" 2>&1) \
            || fail package_signature
          echo "$signature" \
            | /usr/bin/grep -Fq 'Developer ID Installer: Microsoft Corporation (UBF8T346G9)' \
            || fail package_identity
          echo "$signature" | /usr/bin/grep -Fq 'Notarization: trusted' \
            || fail package_notarization
          /usr/sbin/installer -pkg "$pkg" -target / >/dev/null \
            || fail vendor_installer
          verify_app || fail installed_application
        fi

        install_marker || fail managed_marker
        verify_managed || fail final_verification
      fi
    else
      if test -f "$marker" \
        && test "$(/bin/cat "$marker")" = "$expected_marker" \
        && verify_app; then
        /bin/rm -rf -- "$app" || fail remove_application
        /usr/sbin/pkgutil --forget "$receipt" >/dev/null 2>&1 || true
        /usr/sbin/pkgutil --forget com.microsoft.rdc.installer.scripts >/dev/null 2>&1 || true
        /bin/rm -f -- "$marker" || fail remove_marker
        /bin/rmdir "$marker_dir" 2>/dev/null || true
      elif test -e "$app" || test -e "$marker"; then
        fail unmanaged_or_drifted_removal_state
      fi
    fi
  '';
}
