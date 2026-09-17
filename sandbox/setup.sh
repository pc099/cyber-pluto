#!/usr/bin/env bash
#
# setup.sh — one-time operator setup for the sandboxed harness (board v0).
#
# Prepares the host so `cyberpluto --sandbox` can run the agent as the confined
# `pluto` uid against a frozen, read-only harness tree. Run as root, once.
#
#   sudo sandbox/setup.sh [/opt/cyber-pluto]
#
# It: (1) creates the dedicated unprivileged `pluto` uid, (2) deploys the harness
# to a pluto-TRAVERSABLE path (NOT under /root, which is 0700 and blocks pluto
# from reading the tree at all) via a bind mount, (3) freezes the tree
# root-owned + world-read-only so the agent cannot modify the harness/gate, and
# (4) makes the engagements/ workspace pluto-writable.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="${1:-/opt/cyber-pluto}"
UIDNAME="${PLUTO_UID:-pluto}"

echo "[*] dedicated unprivileged uid '$UIDNAME'"
id "$UIDNAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$UIDNAME"

echo "[*] deploy harness to a pluto-traversable path: $DEPLOY (bind of $SRC)"
mkdir -p "$DEPLOY"; chmod 755 "$(dirname "$DEPLOY")" "$DEPLOY"
mountpoint -q "$DEPLOY" || mount --bind "$SRC" "$DEPLOY"

echo "[*] freeze the harness tree read-only to the agent (root-owned, o-w stripped)"
# NB: leaves the engagements/ workspace writable to pluto below. Build artifacts
# (extensions/dist, the Pi bundle) MUST be built by root BEFORE this step — the
# agent runs a frozen tree and cannot build.
chown -R root:root "$DEPLOY"
chmod -R o-w,g-w "$DEPLOY"
find "$DEPLOY" -type d -exec chmod o+rx,g+rx {} +   # pluto can read + traverse

echo "[*] pluto-writable workspace: $DEPLOY/engagements"
mkdir -p "$DEPLOY/engagements"; chown "$UIDNAME":"$UIDNAME" "$DEPLOY/engagements"; chmod 0770 "$DEPLOY/engagements"

echo
echo "  ✅ setup complete."
echo "  Run a sandboxed engagement (as root — it drops to $UIDNAME):"
echo "     cd $DEPLOY && ./cyberpluto <target> --sandbox --headless"
echo "  The kill switch stays root-owned: touch $DEPLOY/state/KILL_SWITCH to halt."
echo "  Rebuild after a code change: (as root) cd $DEPLOY/extensions && npm run build,"
echo "  then re-run this script to re-freeze."
