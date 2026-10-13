#!/bin/sh
set -eu

exec /usr/bin/ssh -T \
  -o BatchMode=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o ConnectTimeout=8 \
  -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=12 \
  windows-host \
  'set -eu; [ "${CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED:-}" = 1 ]; [ "${CODEX_SSH_SKIP_APP_SERVER_BOOT:-}" = true ]; exec codex -c features.code_mode_host=true app-server --listen unix://'
