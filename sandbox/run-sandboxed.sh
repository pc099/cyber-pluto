#!/usr/bin/env bash
#
# run-sandboxed.sh — run a command as the confined `pluto` agent (board v0).
#
# Composes the ratified controls:
#   * setpriv --no-new-privs --reuid pluto --regid pluto --init-groups
#       -> drops to the unprivileged uid AND sets no_new_privs, which closes the
#          setuid-root egress bypass (a setuid tool like ping cannot elevate, so
#          its packets are attributed to `pluto` and the owner-match catches them).
#   * bubblewrap: read-only bind of the whole fs, writable bind ONLY of the
#       per-engagement workspace + /tmp (bound nosuid), a clean /dev + /proc.
#   * a pinned PATH of root-owned dirs; a non-login shell env; the provider key
#       injected via env (never on disk, only in this process's /proc environ).
#
# The nftables owner-match egress allowlist must already be applied for `pluto`
# (sandbox/egress.sh apply) BEFORE calling this — that is the ROOT launcher's job.
#
# Usage (run as root):
#   sandbox/run-sandboxed.sh <engagement_dir> -- <command> [args...]
# Env passed through to the child: PLUTO_* and any provider key the caller sets.
set -euo pipefail

UIDNAME="${PLUTO_UID:-pluto}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ENG_DIR="${1:?usage: run-sandboxed.sh <engagement_dir> -- <command...>}"; shift
[[ "${1:-}" == "--" ]] && shift
[[ $# -ge 1 ]] || { echo "no command given" >&2; exit 1; }

id "$UIDNAME" >/dev/null 2>&1 || { echo "user '$UIDNAME' missing (run sandbox/setup-user.sh)" >&2; exit 1; }
mkdir -p "$ENG_DIR"; chown -R "$UIDNAME":"$UIDNAME" "$ENG_DIR"

USE_BWRAP="${PLUTO_BWRAP:-1}"

# The child env: pinned PATH (root-owned dirs only), a root-owned HOME with no
# writable init files, non-login shells. Provider keys come from the caller's env.
CHILD_ENV=(
	env -i
	PATH=/usr/local/bin:/usr/bin:/bin
	HOME=/nonexistent
	TERM="${TERM:-xterm}"
	BASH_ENV= ENV=
)
# Forward PLUTO_* and provider credential envs (the only secrets, injected here).
while IFS='=' read -r k _; do
	case "$k" in PLUTO_*|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY|DEEPSEEK_API_KEY|ZAI_API_KEY|GROQ_API_KEY) CHILD_ENV+=("$k=${!k}");; esac
done < <(env)

DROP=(setpriv --no-new-privs --reuid "$UIDNAME" --regid "$UIDNAME" --init-groups --)

if [[ "$USE_BWRAP" == "1" ]] && command -v bwrap >/dev/null; then
	BWRAP=(bwrap
		--ro-bind / /                 # everything read-only…
		--dev /dev --proc /proc
		--bind "$ENG_DIR" "$ENG_DIR"  # …except the per-engagement workspace…
		--bind /tmp /tmp              # …and /tmp (both writable, and see nosuid note)
		--tmpfs /run
		--die-with-parent --unshare-ipc --unshare-uts
		--chdir "$REPO")
	exec "${DROP[@]}" "${BWRAP[@]}" "${CHILD_ENV[@]}" "$@"
else
	cd "$REPO"
	exec "${DROP[@]}" "${CHILD_ENV[@]}" "$@"
fi
