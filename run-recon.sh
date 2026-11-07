#!/usr/bin/env bash
#
# run-recon.sh  --  the toolkit's former name, kept so existing scripts and cron jobs keep working.
#
# Outcrop is run-recon renamed (1.21). This runs outcrop.sh, found next to this file (through
# symlinks, so the installed `run-recon` command works too), with the same arguments,
# environment and standard streams. `exec` replaces this process, so outcrop.sh's exit status,
# signals (Ctrl-C, SIGTERM, --resume) and PID are the caller's. Prefer `outcrop` in new work.
#
self="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
main="$(dirname "$self")/outcrop.sh"
if [ ! -f "$main" ]; then
  printf '[x] run-recon.sh: outcrop.sh not found next to it (%s). Install both together.\n' "$main" >&2
  exit 2
fi
exec bash "$main" "$@"
