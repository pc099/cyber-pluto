# ICA1 lab provisioning — 2026-10-01

The operator requested deletion of existing VulnHub VM images, installation of
`https://download.vulnhub.com/ica/ica1.zip`, and booting the replacement for later
harness tests. This task prepared the VM; it did not start a Pluto engagement.

## Verified installation

- Archive: `/root/vulnhub/ica1.zip`, 1,330,199,133 bytes.
- SHA-1: `56f2ca1c6694d8856a8bd132cb2be9a0666b7044`, matching the
  [VulnHub release checksum](https://www.vulnhub.com/entry/ica-1,748/).
- Extracted OVF appliance under `/root/vulnhub/ica1`; its metadata specifies
  Debian, one CPU, 1024 MB memory, SATA disk and E1000 network adapter.
- KVM/libvirt domain: `ica1`, UUID `900a06e5-8841-444b-b5be-45de75e24316`,
  running with one vCPU and 1024 MB RAM. Boot screen reached the login prompt.
- Converted base: `/var/lib/libvirt/images/ica1-base.qcow2`. `qemu-img compare`
  reported identical contents against the downloaded VMDK. The running VM uses
  `/var/lib/libvirt/images/ica1.qcow2`, an overlay backed by that base.
- Network: dedicated `pluto-lab`, bridge `virbr-pluto`, host `192.168.123.1/24`,
  no forwarding element. It is not attached to a host physical interface.
- Actual DHCP lease: **192.168.123.10/24**, MAC `52:54:00:1c:a1:01`, with an
  explicit reservation. HTTP HEAD from the host returned **200 OK**.
- VNC listens only at `127.0.0.1:5900`. Domain/network autostart is disabled.

Initial KVM boot produced no DHCP lease. Keeping the E1000 adapter at PCI slot
`0x03` and disabling PCI-root hotplug resolved the issue after a clean restart.
The [libvirt controller documentation](https://libvirt.org/formatdomain.html)
describes this hardware option. Interface naming incompatibility is the inferred
cause; the measured result is the lease and successful HTTP response. No guest
filesystem was mounted/read offline and no guest configuration was edited.

## Removed old resources

Jangow was the only existing registered VulnHub VM found. It shut down cleanly,
then its libvirt definition was removed after ICA1 started. All five old files
were deleted and their absence checked:

- `/var/lib/libvirt/images/jangow.qcow2`
- `/root/vulnhub/jangow-01.ova`
- `/root/vulnhub/jangow 01-disk001.vmdk`
- `/root/vulnhub/jangow 01.ovf`
- `/root/vulnhub/jangow 01.mf`

Historical Pluto engagement ledgers and session transcripts were preserved.
The pre-existing `default` libvirt network was left unchanged.

## Resume and proof limits

Local installation record: `/root/vulnhub/ica1/install-record.json`, including
the archive's independently computed SHA-256. VM XML and the hardware adjustment
script are stored beside it. After a host reboot, start the network before the VM:

```sh
virsh -c qemu:///system net-start pluto-lab
virsh -c qemu:///system start ica1
virsh -c qemu:///system net-dhcp-leases pluto-lab
```

Recheck the lease/reachability before testing. Target scope for a future run is
the single guest `192.168.123.10`; the subnet, host and other interfaces are not
testing targets. No model calls, exploit evaluation or root/foothold validation
occurred during provisioning. The separate Pluto sandbox startup/signing
readiness task remains open; this VM's isolated network does not establish the
harness's confinement.
