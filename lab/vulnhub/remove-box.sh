#!/usr/bin/env bash
# remove-box.sh <name> — stop and delete a VulnHub domain and its disk.
set -euo pipefail
NAME="${1:?give the domain name (see: virsh list --all)}"
virsh destroy  "$NAME" >/dev/null 2>&1 || true
virsh undefine "$NAME" --nvram --remove-all-storage >/dev/null 2>&1 || virsh undefine "$NAME" >/dev/null 2>&1 || true
rm -f "/var/lib/libvirt/images/${NAME}.qcow2"
echo "removed '$NAME'."
