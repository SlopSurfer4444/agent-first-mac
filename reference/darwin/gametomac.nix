{ lib, pkgs, ... }:

let
  # The system-revision graph admits the module, while the payload checker
  # independently verifies agreement with the reviewed manifest.
  manifest = {
    enabled = false;
    source = {
      url = "https://updates.gametomac.com/GameToMac-0.1.47-alpha-build87.dmg";
      sha256 = "26beb41fcf7de9a73625aa90ccae1ba1e9eb70b028933809e2bc6a4a2c3c4f59";
    };
    application = {
      path = "/Applications/GameToMac.app";
      bundleIdentifier = "com.marcibrahim.gamelibrary";
      teamIdentifier = "4F5RV48Y8T";
      executable = "GameLibrary";
      versionKey = "CFBundleVersion";
      minimumVersion = 87;
    };
  };
  identity = manifest.application;
  source = manifest.source;
  dmg = pkgs.fetchurl {
    name = "GameToMac-0.1.47-alpha-build87.dmg";
    url = source.url;
    sha256 = source.sha256;
  };
  managedMarker = pkgs.writeText "gametomac-managed-source"
    "${toString identity.minimumVersion}|${source.sha256}\n";
in
assert builtins.isBool manifest.enabled;
assert identity.path == "/Applications/GameToMac.app";
assert identity.bundleIdentifier == "com.marcibrahim.gamelibrary";
assert identity.teamIdentifier == "4F5RV48Y8T";
assert identity.executable == "GameLibrary";
assert identity.versionKey == "CFBundleVersion";
assert identity.minimumVersion == 87;
assert builtins.match "https://updates[.]gametomac[.]com/[A-Za-z0-9.-]+[.]dmg" source.url != null;
assert builtins.match "[0-9a-f]{64}" source.sha256 != null;
{
  # This subshell isolates helpers/traps from other activation modules. Every
  # failure exits it, and the outer exit propagates failure to the typed broker.
  system.activationScripts.extraActivation.text = lib.mkAfter ''
    (
      echo "reconciling the owner-authorized GameToMac application lifecycle..." >&2
      app='${identity.path}'
      marker_parent=/var/db/agent-first-mac
      marker_dir=$marker_parent/gametomac
      marker=$marker_dir/managed-source
      marker_source='${managedMarker}'
      staging=
      mounted=false
      installed_id=
      created_marker_id=
      created_dir=false
      committed=false
      removing=false

      fail() {
        echo "GameToMac lifecycle failure: $1" >&2
        exit 1
      }

      path_id() { /usr/bin/stat -f '%d:%i' "$1"; }
      safe_directory() {
        test -d "$1" && ! test -L "$1" || return 1
        case "$(/usr/bin/stat -f '%u:%g:%Lp' "$1")" in
          0:0:755|0:0:700) return 0 ;;
          *) return 1 ;;
        esac
      }
      absent() { ! test -e "$1" && ! test -L "$1"; }
      plist_raw() {
        /usr/bin/plutil -extract "$2" raw -o - "$1/Contents/Info.plist" 2>/dev/null
      }
      verify_app() {
        test -d "$1" && ! test -L "$1" || return 1
        test "$(plist_raw "$1" CFBundleIdentifier)" = '${identity.bundleIdentifier}' || return 1
        test "$(plist_raw "$1" CFBundleExecutable)" = '${identity.executable}' || return 1
        build=$(plist_raw "$1" '${identity.versionKey}') || return 1
        case "$build" in ""|*[!0-9]*|0[0-9]*) return 1 ;; esac
        test "''${#build}" -le 9 && test "$build" -ge ${toString identity.minimumVersion} || return 1
        test -f "$1/Contents/MacOS/${identity.executable}" \
          && ! test -L "$1/Contents/MacOS/${identity.executable}" \
          && test -x "$1/Contents/MacOS/${identity.executable}" || return 1
        /usr/bin/lipo -verify_arch arm64 "$1/Contents/MacOS/${identity.executable}" >/dev/null 2>&1 || return 1
        /usr/bin/codesign --verify --deep --strict "$1" >/dev/null 2>&1 || return 1
        /usr/bin/codesign --verify -R='anchor apple generic and identifier "${identity.bundleIdentifier}" and certificate leaf[subject.OU] = "${identity.teamIdentifier}"' "$1" >/dev/null 2>&1 || return 1
        /usr/sbin/spctl --assess --type execute "$1" >/dev/null 2>&1 || return 1
      }
      verify_marker() {
        safe_directory "$marker_parent" && safe_directory "$marker_dir" || return 1
        test -f "$marker" && ! test -L "$marker" || return 1
        test "$(/usr/bin/stat -f '%u:%g:%Lp' "$marker")" = 0:0:644 || return 1
        /usr/bin/cmp -s "$marker_source" "$marker"
      }
      verify_managed() { verify_marker && verify_app "$app"; }

      # Invoked by the EXIT trap, including error and signal paths.
      # shellcheck disable=SC2329
      cleanup() {
        status=$?
        trap - EXIT HUP INT TERM
        if $mounted; then
          if ! /usr/bin/hdiutil detach "$staging/mount" >/dev/null 2>&1; then
            echo "GameToMac lifecycle failure: retained_mounted_staging" >&2
            exit 1
          fi
        fi
        if ! $committed; then
          if $removing && test -d "$staging/GameToMac.app"; then
            if absent "$app"; then
              /bin/mv -n "$staging/GameToMac.app" /Applications/ || exit 1
              test ! -e "$staging/GameToMac.app" || exit 1
            else
              echo "GameToMac lifecycle failure: removal_restore_conflict" >&2
              exit 1
            fi
          fi
          if $removing && test -f "$staging/managed-source"; then
            absent "$marker" || exit 1
            /bin/mv -n "$staging/managed-source" "$marker_dir/" || exit 1
            absent "$staging/managed-source" || exit 1
          fi
          if test -n "$installed_id" && ! absent "$app"; then
            test ! -L "$app" && test "$(path_id "$app")" = "$installed_id" || exit 1
            /bin/rm -rf -- "$app" || exit 1
          fi
          if test -n "$created_marker_id" && ! absent "$marker"; then
            test ! -L "$marker" && test "$(path_id "$marker")" = "$created_marker_id" || exit 1
            /bin/rm -f -- "$marker" || exit 1
          fi
          if $created_dir; then /bin/rmdir "$marker_dir" 2>/dev/null || true; fi
        fi
        if test -n "$staging"; then /bin/rm -rf -- "$staging" || exit 1; fi
        exit "$status"
      }
      trap cleanup EXIT
      trap 'exit 1' HUP INT TERM

      test -d /Applications && ! test -L /Applications || fail applications_directory
      safe_directory /private/var/db || fail marker_root
      if ! absent "$marker_parent"; then safe_directory "$marker_parent" || fail marker_parent; fi

      if ${if manifest.enabled then "true" else "false"}; then
        if verify_managed; then
          committed=true
        else
          # Unknown applications/markers are never overwritten or auto-adopted.
          absent "$app" && absent "$marker" || fail competing_or_drifted_state
          if ! absent "$marker_dir"; then safe_directory "$marker_dir" || fail marker_directory; fi
          test "$(/usr/bin/shasum -a 256 '${dmg}' | /usr/bin/awk '{print $1}')" \
            = '${source.sha256}' || fail source_checksum
          staging=$(/usr/bin/mktemp -d /Applications/.gametomac-stage.XXXXXX) || fail staging
          case "$staging" in /Applications/.gametomac-stage.*) ;; *) fail staging_path ;; esac
          /bin/chmod 0700 "$staging" || fail staging_permissions
          /bin/mkdir "$staging/mount" || fail mount_directory
          /usr/bin/hdiutil attach -readonly -nobrowse -mountpoint "$staging/mount" '${dmg}' >/dev/null || fail mount_source
          mounted=true
          verify_app "$staging/mount/GameToMac.app" || fail source_application
          /usr/bin/ditto "$staging/mount/GameToMac.app" "$staging/GameToMac.app" || fail staged_copy
          verify_app "$staging/GameToMac.app" || fail staged_application
          /usr/bin/hdiutil detach "$staging/mount" >/dev/null || fail unmount_source
          mounted=false
          absent "$app" && absent "$marker" || fail destination_drift
          installed_id=$(path_id "$staging/GameToMac.app") || fail staged_identity
          /bin/mv -n "$staging/GameToMac.app" /Applications/ || fail publish_application
          absent "$staging/GameToMac.app" || fail publish_collision
          verify_app "$app" && test "$(path_id "$app")" = "$installed_id" || fail installed_application
          if absent "$marker_parent"; then
            /usr/bin/install -d -o root -g wheel -m 0755 "$marker_parent" || fail create_marker_parent
          fi
          safe_directory "$marker_parent" || fail marker_parent
          if absent "$marker_dir"; then
            /usr/bin/install -d -o root -g wheel -m 0755 "$marker_dir" || fail create_marker_directory
            created_dir=true
          fi
          safe_directory "$marker_dir" && absent "$marker" || fail marker_directory
          /usr/bin/install -o root -g wheel -m 0644 "$marker_source" "$staging/managed-source" || fail stage_marker
          created_marker_id=$(path_id "$staging/managed-source") || fail marker_identity
          /bin/ln "$staging/managed-source" "$marker" || fail publish_marker
          /bin/rm "$staging/managed-source" || fail finish_marker
          verify_managed || fail final_verification
          committed=true
        fi
      else
        if absent "$app" && absent "$marker"; then
          committed=true
        else
          verify_managed || fail unmanaged_or_drifted_removal_state
          if /usr/bin/pgrep -x '${identity.executable}' >/dev/null; then
            fail running_application
          else
            test "$?" = 1 || fail process_probe
          fi
          staging=$(/usr/bin/mktemp -d /Applications/.gametomac-stage.XXXXXX) || fail removal_staging
          /bin/chmod 0700 "$staging" || fail removal_staging_permissions
          removing=true
          /bin/mv -n "$app" "$staging/" || fail stage_removal
          absent "$app" && verify_app "$staging/GameToMac.app" || fail staged_removal
          verify_marker || fail removal_marker_drift
          /bin/mv -n "$marker" "$staging/" || fail stage_marker_removal
          absent "$marker" && /usr/bin/cmp -s "$marker_source" "$staging/managed-source" || fail staged_marker_removal
          committed=true
          /bin/rmdir "$marker_dir" 2>/dev/null || true
          # Only the app bundle and its source marker are removed. Steam,
          # runtimes, saves, support data and authentication are never touched.
        fi
      fi
    ) || exit 1
  '';
}
