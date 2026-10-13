#!/bin/sh
set -eu

volume=/Volumes/CodexBridgeDrop
state_dir="${HOME}/Library/Application Support/com.aidev.codex-bridge-drop"
pause_marker="${state_dir}/automount-paused"
finder_url='smb://127.0.0.1:14445/CodexBridgeDrop'

mounted() {
  /sbin/mount | /usr/bin/grep -Fq " on ${volume} "
}

clear_owned_pause_marker() {
  expected_marker_state="$(/usr/bin/id -u):600:0"
  marker_state=$(/usr/bin/stat -f '%u:%Lp:%z' "$pause_marker" 2>/dev/null || :)
  if [ -f "$pause_marker" ] && [ ! -L "$pause_marker" ] \
      && [ "$marker_state" = "$expected_marker_state" ]; then
    /bin/rm -f -- "$pause_marker"
  fi
}

record_pause() {
  expected_dir_state="$(/usr/bin/id -u):700"
  if [ -e "$state_dir" ] || [ -L "$state_dir" ]; then
    [ -d "$state_dir" ] && [ ! -L "$state_dir" ] || return 0
    dir_state=$(/usr/bin/stat -f '%u:%Lp' "$state_dir" 2>/dev/null || :)
    [ "$dir_state" = "$expected_dir_state" ] || return 0
  else
    (umask 077 && /bin/mkdir "$state_dir") || return 0
  fi
  if [ ! -e "$pause_marker" ] && [ ! -L "$pause_marker" ]; then
    (umask 077 && : > "$pause_marker")
  fi
}

if mounted; then
  clear_owned_pause_marker
  exit 0
fi

# Any existing pause object, including a symlink or directory, fails closed.
# A regular empty marker records one unsuccessful owner-visible mount attempt
# and prevents a recurring credential prompt.
if [ -e "$pause_marker" ] || [ -L "$pause_marker" ]; then
  exit 0
fi

/usr/bin/pgrep -x Finder >/dev/null 2>&1 || exit 0
/usr/bin/nc -z -w 3 127.0.0.1 14445 >/dev/null 2>&1 || exit 0
/usr/bin/open "$finder_url" >/dev/null 2>&1 || {
  record_pause
  exit 0
}

attempt=0
while [ "$attempt" -lt 20 ]; do
  if mounted; then
    clear_owned_pause_marker
    exit 0
  fi
  /bin/sleep 1
  attempt=$((attempt + 1))
done

record_pause
exit 0
