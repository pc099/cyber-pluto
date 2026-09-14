#!/usr/bin/env bash
#
# import-box.sh — boot a VulnHub box on the droplet with QEMU/KVM and hand its
# local IP to Pluto. VulnHub ships full VM images; this converts one to qcow2,
# imports it as a libvirt domain on the NAT network (default, 192.168.122.0/24),
# boots it, waits for its DHCP lease, and prints the IP + the cyberpluto command
# scoped to it. The box is reachable ONLY on the host-private NAT network — it is
# never exposed to the internet.
#
# Usage:
#   sudo lab/vulnhub/import-box.sh <box.ova|box.vmdk> [name] [ram_mb]
#   sudo lab/vulnhub/import-box.sh ~/DC-1.ova dc1 768
#
# Notes:
#   * KVM acceleration is used (/dev/kvm). Keep RAM modest — this droplet has
#     ~3 GB free, so one small box (default 768 MB) at a time, alongside Pluto.
#   * Old VulnHub Linux images lack virtio drivers, so the disk is attached as
#     SATA and the NIC as e1000 for maximum compatibility. Most VulnHub guests
#     are pre-configured for DHCP, so they lease an IP automatically.
#   * Remove a box later with:  lab/vulnhub/remove-box.sh <name>
set -euo pipefail

SRC="${1:?give a .ova or .vmdk path}"
NAME="${2:-$(basename "$SRC" | sed 's/\.[^.]*$//' | tr -c 'a-zA-Z0-9' '-' | sed 's/-*$//')}"
RAM="${3:-768}"
IMG_DIR="/var/lib/libvirt/images"
[ -f "$SRC" ] || { echo "not found: $SRC" >&2; exit 1; }
command -v virt-install >/dev/null || { echo "virt-install missing — run the qemu/libvirt install first" >&2; exit 1; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
case "$SRC" in
	*.ova)  echo "[*] extracting OVA…"; tar -xf "$SRC" -C "$work"
	        VMDK="$(find "$work" -iname '*.vmdk' | head -1)" ;;
	*.vmdk) VMDK="$SRC" ;;
	*.qcow2) VMDK="$SRC" ;;
	*) echo "unsupported source (want .ova / .vmdk / .qcow2): $SRC" >&2; exit 1 ;;
esac
[ -n "${VMDK:-}" ] || { echo "no disk image found inside $SRC" >&2; exit 1; }

QCOW="$IMG_DIR/${NAME}.qcow2"
echo "[*] converting disk → $QCOW"
if [[ "$VMDK" == *.qcow2 ]]; then cp "$VMDK" "$QCOW"; else qemu-img convert -p -O qcow2 "$VMDK" "$QCOW"; fi

# replace any prior domain of the same name
virsh destroy  "$NAME" >/dev/null 2>&1 || true
virsh undefine "$NAME" --nvram --remove-all-storage >/dev/null 2>&1 || virsh undefine "$NAME" >/dev/null 2>&1 || true

echo "[*] defining + booting domain '$NAME' (${RAM} MB, KVM)…"
virt-install \
	--name "$NAME" --memory "$RAM" --vcpus 1 --cpu host-passthrough \
	--virt-type kvm --import \
	--disk "path=$QCOW,bus=sata" \
	--network network=default,model=e1000 \
	--os-variant generic \
	--graphics vnc,listen=127.0.0.1 \
	--noautoconsole >/dev/null

MAC="$(virsh domiflist "$NAME" | awk '/network/{print $5}' | head -1)"
echo "[*] booting… waiting for a DHCP lease (MAC $MAC)"
IP=""
for _ in $(seq 1 36); do
	IP="$(virsh net-dhcp-leases default 2>/dev/null | awk -v m="$MAC" '$0 ~ m {print $5}' | cut -d/ -f1 | head -1)"
	[ -n "$IP" ] && break
	# fall back to the ARP table on virbr0
	IP="$(ip neigh show dev virbr0 2>/dev/null | awk -v m="$MAC" 'tolower($0) ~ tolower(m){print $1}' | head -1)"
	[ -n "$IP" ] && break
	sleep 5
done

echo
if [ -n "$IP" ]; then
	echo "  ================================================================"
	echo "   box '$NAME' is up at   $IP   (NAT, host-private)"
	echo "   quick check:  nmap -sT -Pn -p- --min-rate 1000 $IP"
	echo "   run Pluto:    ./cyberpluto $IP \"find a foothold and escalate\" --no-cap"
	echo "  ================================================================"
else
	echo "  box '$NAME' booted but no lease yet. It may still be starting, or the"
	echo "  guest isn't on DHCP. Check with:  virsh net-dhcp-leases default"
	echo "  and the console:                  virsh console $NAME   (or VNC on 127.0.0.1)"
fi
