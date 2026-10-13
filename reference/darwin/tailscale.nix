{ lib, pkgs, ... }:

let
  # False is the reviewed removal state. After Network Extension consent or
  # login it intentionally fails closed for the bounded owner uninstall flow.
  tailscaleStandaloneEnabled = true;

  tailscalePkg = pkgs.fetchurl {
    url = "https://pkgs.tailscale.com/stable/Tailscale-1.98.10-macos.pkg";
    hash = "sha256-wur19mCtRaZNG6Q+5yQBAppcsG5tFIxekKmHpvVGvFg=";
  };

  # The official package's postinstall writes this companion through a nested
  # sudo call.  A canonical Mac without /usr/local/bin can therefore receive
  # the signed application while the companion remains absent.  Keep the
  # reviewed vendor bytes immutable and install them from the Nix store.
  tailscaleCliWrapper = pkgs.writeTextFile {
    name = "tailscale-cli-wrapper";
    executable = true;
    text = ''
      #!/bin/sh
      /Applications/Tailscale.app/Contents/MacOS/tailscale "$@"
    '';
  };

  tailscaleManagedMarker = pkgs.writeText "tailscale-managed-source" ''
    1.98.10|c2eaf5f660ad45a64d1ba43ee72401029a5cb06e6d148c5e90a987a6f546bc58
  '';
in
{
  system.activationScripts.extraActivation.text = lib.mkAfter ''
    echo "reconciling the owner-authorized Tailscale Standalone lifecycle..." >&2

    app=/Applications/Tailscale.app
    app_binary=$app/Contents/MacOS/Tailscale
    cli=$app/Contents/MacOS/tailscale
    sysext=$app/Contents/Library/SystemExtensions/io.tailscale.ipn.macsys.network-extension.systemextension
    wrapper=/usr/local/bin/tailscale
    manpage=/usr/local/share/man/man8/tssentineld.8
    marker_dir=/var/db/agent-first-mac/tailscale
    marker=$marker_dir/managed-source
    receipt=com.tailscale.ipn.macsys
    expected_marker='1.98.10|c2eaf5f660ad45a64d1ba43ee72401029a5cb06e6d148c5e90a987a6f546bc58'
    expected_wrapper_hash=26b0e5a65e1b723e38f187619964b443e44118c2e02217e9b11165ce17afa65e
    expected_manpage_hash=723e0bf99d9b96f7eed77428bbfc518060515aaf047a880e662004081c483ca0
    installer_ran=0
    marker_installed=0
    wrapper_source='${tailscaleCliWrapper}'
    marker_source='${tailscaleManagedMarker}'

    fail() {
      echo "Tailscale lifecycle failure: $1" >&2
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

    file_sha256() {
      /usr/bin/shasum -a 256 "$1" 2>/dev/null | /usr/bin/awk '{print $1}'
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

    receipt_version() {
      /usr/sbin/pkgutil --pkg-info "$receipt" 2>/dev/null \
        | /usr/bin/sed -n 's/^version: //p' \
        | /usr/bin/sed -n '1p'
    }

    system_extension_registered() {
      /usr/bin/systemextensionsctl list 2>/dev/null \
        | /usr/bin/grep -Fq 'io.tailscale.ipn.macsys.network-extension'
    }

    system_extension_exact_enabled() {
      all_count=$(/usr/bin/systemextensionsctl list 2>/dev/null \
        | /usr/bin/grep -F 'io.tailscale.ipn.macsys.network-extension' \
        | /usr/bin/awk 'END { print NR + 0 }')
      exact_count=$(/usr/bin/systemextensionsctl list 2>/dev/null \
        | /usr/bin/grep -F 'W5364U7YZB' \
        | /usr/bin/grep -F 'io.tailscale.ipn.macsys.network-extension' \
        | /usr/bin/grep -F '(1.98.10/101.98.10)' \
        | /usr/bin/grep -F '[activated enabled]' \
        | /usr/bin/awk 'END { print NR + 0 }')
      test "$all_count" = 1 && test "$exact_count" = 1
    }

    mac_inbound_ssh_off() {
      ! /bin/launchctl print system/com.openssh.sshd >/dev/null 2>&1 \
        && ! /usr/sbin/lsof -nP -iTCP:22 -sTCP:LISTEN >/dev/null 2>&1
    }

    verify_app() {
      test -d "$app" || return 1
      test "$(plist_raw "$app" CFBundleIdentifier)" = io.tailscale.ipn.macsys \
        || return 1
      app_version=$(plist_raw "$app" CFBundleShortVersionString) || return 1
      version_at_least "$app_version" 1.98.10 || return 1
      test "$(team_id "$app")" = W5364U7YZB || return 1
      /usr/bin/codesign --verify --deep --strict "$app" >/dev/null 2>&1 \
        || return 1
      /usr/sbin/spctl --assess --type execute "$app" >/dev/null 2>&1 \
        || return 1
      test -x "$app_binary" || return 1
      test -x "$cli" || return 1
      test "$(/usr/bin/stat -f '%d:%i' "$app_binary")" \
        = "$(/usr/bin/stat -f '%d:%i' "$cli")" || return 1
      /usr/bin/file "$cli" 2>/dev/null | /usr/bin/grep -q 'x86_64' \
        || return 1
      /usr/bin/file "$cli" 2>/dev/null | /usr/bin/grep -q 'arm64' \
        || return 1
      test -d "$sysext" || return 1
      test "$(plist_raw "$sysext" CFBundleIdentifier)" \
        = io.tailscale.ipn.macsys.network-extension || return 1
      test "$(plist_raw "$sysext" CFBundleShortVersionString)" \
        = "$app_version" || return 1
      test "$(team_id "$sysext")" = W5364U7YZB || return 1
      /usr/bin/codesign --verify --strict "$sysext" >/dev/null 2>&1 \
        || return 1
    }

    verify_vendor_companions() {
      test "$(receipt_version)" = 1.98.10 \
        && test -f "$wrapper" \
        && test "$(file_sha256 "$wrapper")" = "$expected_wrapper_hash" \
        && test -f "$manpage" \
        && test "$(file_sha256 "$manpage")" = "$expected_manpage_hash"
    }

    verify_payload() {
      verify_app && verify_vendor_companions && mac_inbound_ssh_off
    }

    verify_managed_target() {
      test -f "$marker" \
        && test "$(/bin/cat "$marker")" = "$expected_marker" \
        && verify_payload
    }

    exact_wrapper_or_absent() {
      ! test -e "$wrapper" \
        || { test -f "$wrapper" \
          && test "$(file_sha256 "$wrapper")" = "$expected_wrapper_hash"; }
    }

    exact_manpage_or_absent() {
      ! test -e "$manpage" \
        || { test -f "$manpage" \
          && test "$(file_sha256 "$manpage")" = "$expected_manpage_hash"; }
    }

    install_exact_wrapper() {
      if test -e "$wrapper" || test -L "$wrapper"; then
        test -f "$wrapper" \
          && ! test -L "$wrapper" \
          && test "$(file_sha256 "$wrapper")" = "$expected_wrapper_hash"
        return
      fi
      test -f "$wrapper_source" \
        && test "$(file_sha256 "$wrapper_source")" = "$expected_wrapper_hash" \
        || return 1
      if test -e /usr/local/bin || test -L /usr/local/bin; then
        test -d /usr/local/bin \
          && ! test -L /usr/local/bin \
          && test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' /usr/local/bin)" \
            = root:wheel:755 || return 1
      else
        /usr/bin/install -d -o root -g wheel -m 0755 /usr/local/bin \
          || return 1
      fi
      /usr/bin/install -o root -g wheel -m 0755 "$wrapper_source" "$wrapper"
    }

    no_competing_variant() {
      standalone_count=$(/usr/bin/mdfind \
          "kMDItemCFBundleIdentifier == 'io.tailscale.ipn.macsys'" 2>/dev/null \
        | /usr/bin/awk 'NF { count++ } END { print count + 0 }')
      standalone_path=$(/usr/bin/mdfind \
          "kMDItemCFBundleIdentifier == 'io.tailscale.ipn.macsys'" 2>/dev/null \
        | /usr/bin/sed -n '1p')
      test "$standalone_count" = 1 \
        && test "$standalone_path" = "$app" \
        && ! /usr/bin/mdfind \
          "kMDItemCFBundleIdentifier == 'io.tailscale.ipn.macos'" 2>/dev/null \
          | /usr/bin/grep -q . \
        && ! test -e /opt/homebrew/opt/tailscale \
        && ! test -d /opt/homebrew/Cellar/tailscale
    }

    verify_exact_consent_partial() {
      ! test -e "$marker" \
        && ! test -L "$marker" \
        && verify_app \
        && test "$(receipt_version)" = 1.98.10 \
        && exact_wrapper_or_absent \
        && test -f "$manpage" \
        && test "$(file_sha256 "$manpage")" = "$expected_manpage_hash" \
        && system_extension_exact_enabled \
        && no_competing_variant \
        && mac_inbound_ssh_off
    }

    install_managed_marker() {
      test -f "$marker_source" \
        && test "$(file_sha256 "$marker_source")" \
          = "$(/usr/bin/printf '%s\n' "$expected_marker" \
            | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')" \
        || return 1
      if test -e "$marker_dir" || test -L "$marker_dir"; then
        test -d "$marker_dir" \
          && ! test -L "$marker_dir" \
          && test "$(/usr/bin/stat -f '%Su:%Sg:%Lp' "$marker_dir")" \
            = root:wheel:755 || return 1
      else
        /usr/bin/install -d -o root -g wheel -m 0755 "$marker_dir" \
          || return 1
      fi
      ! test -e "$marker" && ! test -L "$marker" \
        && /usr/bin/install -o root -g wheel -m 0644 "$marker_source" "$marker"
    }

    remove_exact_unconsented_payload() {
      if system_extension_registered; then
        fail consent_bearing_system_extension_requires_owner_uninstall
        return 1
      fi
      if test -e "$app" && ! verify_app; then
        fail refusing_unknown_application_removal
        return 1
      fi
      if ! exact_wrapper_or_absent; then
        fail refusing_unknown_cli_wrapper_removal
        return 1
      fi
      if ! exact_manpage_or_absent; then
        fail refusing_unknown_manpage_removal
        return 1
      fi
      if /usr/sbin/pkgutil --pkg-info "$receipt" >/dev/null 2>&1; then
        if test "$(receipt_version)" != 1.98.10; then
          fail refusing_unknown_receipt_removal
          return 1
        fi
      fi
      if test -e "$marker"; then
        if ! test -f "$marker" \
            || ! test "$(/bin/cat "$marker")" = "$expected_marker"; then
          fail refusing_unknown_marker_removal
          return 1
        fi
      fi

      if /usr/bin/pgrep -x Tailscale >/dev/null 2>&1; then
        /usr/bin/pkill -x Tailscale >/dev/null 2>&1 || true
      fi
      if test -e "$app"; then
        /bin/rm -rf -- "$app"
      fi
      if test -e "$wrapper"; then
        /bin/rm -f -- "$wrapper"
      fi
      /usr/bin/rmdir /usr/local/bin >/dev/null 2>&1 || true
      if test -e "$manpage"; then
        /bin/rm -f -- "$manpage"
      fi
      if /usr/sbin/pkgutil --pkg-info "$receipt" >/dev/null 2>&1; then
        /usr/sbin/pkgutil --forget "$receipt" >/dev/null
      fi
      if test -e "$marker"; then
        /bin/rm -f -- "$marker"
      fi
      /usr/bin/rmdir "$marker_dir" >/dev/null 2>&1 || true
      /usr/bin/rmdir /usr/local/share/man/man8 >/dev/null 2>&1 || true
      mac_inbound_ssh_off
    }

    rollback_failed_install() {
      status=$?
      trap - EXIT
      if test "$installer_ran" = 1 || test "$marker_installed" = 1; then
        remove_exact_unconsented_payload \
          || echo 'Tailscale first-install rollback requires owner attention' >&2
      fi
      exit "$status"
    }

    tailscale_main() {
    ${lib.optionalString tailscaleStandaloneEnabled ''
      pkg='${tailscalePkg}'

      if verify_managed_target; then
        echo "Tailscale Standalone target is already exact" >&2
        return 0
      fi

      if verify_exact_consent_partial; then
        if ! install_exact_wrapper || ! install_managed_marker; then
          fail consent_partial_adoption
          return 1
        fi
        marker_installed=1
        if ! verify_managed_target; then
          fail adopted_managed_target_identity
          return 1
        fi
        echo "Tailscale Standalone exact consent-bearing partial state adopted" >&2
        return 0
      fi

      if test -e "$app" \
          || test -e "$wrapper" \
          || test -e "$manpage" \
          || test -e "$marker" \
          || /usr/sbin/pkgutil --pkg-info "$receipt" >/dev/null 2>&1 \
          || system_extension_registered \
          || /usr/bin/pgrep -x Tailscale >/dev/null 2>&1 \
          || /usr/bin/mdfind "kMDItemCFBundleIdentifier == 'io.tailscale.ipn.macsys'" \
               2>/dev/null | /usr/bin/grep -q . \
          || /usr/bin/mdfind "kMDItemCFBundleIdentifier == 'io.tailscale.ipn.macos'" \
               2>/dev/null | /usr/bin/grep -q . \
          || test -e /opt/homebrew/opt/tailscale \
          || test -d /opt/homebrew/Cellar/tailscale; then
        fail unexpected_or_competing_prestate
        return 1
      fi
      if ! mac_inbound_ssh_off; then
        fail mac_inbound_ssh_must_remain_off
        return 1
      fi

      actual_pkg_hash=$(/usr/bin/shasum -a 256 "$pkg" | /usr/bin/awk '{print $1}')
      if test "$actual_pkg_hash" \
          != c2eaf5f660ad45a64d1ba43ee72401029a5cb06e6d148c5e90a987a6f546bc58; then
        fail package_hash
        return 1
      fi
      if ! /usr/sbin/pkgutil --check-signature "$pkg" 2>&1 \
          | /usr/bin/grep -Fq 'Developer ID Installer: Tailscale Inc. (W5364U7YZB)'; then
        fail package_signature
        return 1
      fi
      if ! /usr/sbin/spctl --assess --type install "$pkg" >/dev/null 2>&1; then
        fail package_notarization
        return 1
      fi

      trap rollback_failed_install EXIT
      installer_ran=1
      /usr/sbin/installer -pkg "$pkg" -target /
      if ! install_exact_wrapper; then
        fail installed_cli_wrapper
        return 1
      fi
      if ! verify_payload; then
        fail installed_payload_identity
        return 1
      fi
      if ! install_managed_marker; then
        fail managed_marker_install
        return 1
      fi
      marker_installed=1
      if ! verify_managed_target; then
        fail managed_target_identity
        return 1
      fi
      trap - EXIT
    ''}

    ${lib.optionalString (!tailscaleStandaloneEnabled) ''
      if ! test -e "$app" \
          && ! test -e "$wrapper" \
          && ! test -e "$manpage" \
          && ! test -e "$marker" \
          && ! /usr/sbin/pkgutil --pkg-info "$receipt" >/dev/null 2>&1 \
          && ! system_extension_registered; then
        echo "Tailscale Standalone removal state is already exact" >&2
        return 0
      fi
      if ! verify_managed_target; then
        fail refusing_nonmanaged_removal_state
        return 1
      fi
      remove_exact_unconsented_payload
    ''}
    }

    tailscale_main
  '';
}
