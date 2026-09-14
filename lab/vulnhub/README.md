# VulnHub local lab (QEMU/KVM)

Run real **VulnHub** boxes locally on the droplet and point Pluto at them — no
VPN, no cost, reproducible. This droplet has hardware virtualization (`/dev/kvm`)
so boxes run KVM-accelerated. Each box sits on a **host-private NAT network**
(`192.168.122.0/24`), reachable only from the droplet, never the internet.

## One-time setup (already done on this droplet)

```bash
apt-get install -y qemu-system-x86 qemu-utils libvirt-daemon-system \
                   libvirt-clients virtinst libguestfs-tools
systemctl enable --now libvirtd
virsh net-start default && virsh net-autostart default   # 192.168.122.0/24 NAT
```

## Add a box

1. **Download a VulnHub image** onto the droplet (pick a *small* one — this box
   has ~3 GB RAM free, so keep the guest ≤ 1 GB and run one at a time). Good
   lightweight starters: the **DC-1…DC-9** series, **Kioptrix**, **Basic
   Pentesting**, **Mr-Robot**, **raven**. VulnHub ships `.ova` (a tar of
   `.ovf` + `.vmdk`).
   ```bash
   cd ~ && wget <vulnhub-download-url-for-the-.ova>
   ```
2. **Import + boot it** (one command; converts, imports, boots, prints the IP):
   ```bash
   sudo /root/cyber-pluto/lab/vulnhub/import-box.sh ~/DC-1.ova dc1 768
   ```
   It prints the box's NAT IP (e.g. `192.168.122.50`) and the ready-to-run
   Pluto command.
3. **Point Pluto at it:**
   ```bash
   cd /root/cyber-pluto
   nmap -sT -Pn -p- --min-rate 1000 192.168.122.50      # sanity check
   ./cyberpluto 192.168.122.50 "find a foothold and escalate" --no-cap
   ```

## Manage boxes

```bash
virsh list --all                      # what's defined / running
virsh dhcp-leases default             # (alias) IPs handed out
virsh net-dhcp-leases default         # box IP ↔ MAC
virsh start <name> / virsh shutdown <name>
virsh console <name>                  # serial console (Ctrl-] to exit)
/root/cyber-pluto/lab/vulnhub/remove-box.sh <name>   # delete box + disk
```

## Notes & gotchas

- **RAM budget.** Guest + Pluto's Node stack + OS must fit in 3.8 GB. Keep the
  guest ≤ 768–1024 MB and only one running. If Pluto's vision pipeline
  (chromium) plus a VM gets tight, drop `-e vision` for lab runs.
- **Compatibility.** Old VulnHub Linux guests lack virtio drivers, so the disk
  is attached as **SATA** and the NIC as **e1000** — that's why the import
  script sets those explicitly. Most guests DHCP automatically; if one doesn't
  lease an IP, open `virsh console <name>` and check its network config.
- **Scope.** Pluto's red-lines gate binds to the target IP you pass, so the
  box's `192.168.122.x` is automatically in scope; nothing else on the host is.
- **Why local beats HTB here.** No VPN reachability issues, no per-box cost, and
  the same box can be reset and re-run to iterate on Pluto deterministically.
- **CVE-specific testing (lighter alternative).** For reproducing a *specific*
  CVE (e.g. the OpenAM/JMX deserialization that stumped Pluto), Docker-based
  **vulhub** environments (github.com/vulhub/vulhub) are lighter than a full VM
  and map one-to-one to a CVE — a good complement once Docker is installed.
