# VMware Workstation Pro — isolated host-only network

Goal: both VMs can talk to each other and to nothing else. No host, no internet.

## 1. Create an isolated host-only vmnet

Open **Edit → Virtual Network Editor** (run VMware as admin to change settings).

1. Click **Add Network…** → pick `VMnet10` (any unused 2–19). Click OK.
2. Select `VMnet10`, set type to **Host-only**.
3. **Uncheck** "Connect a host virtual adapter to this network".
   - This removes the Windows-side adapter, so your host is not on the segment at all.
4. **Uncheck** "Use local DHCP service to distribute IP addresses" (we assign static IPs).
5. Subnet IP `192.168.190.0`, mask `255.255.255.0`. Apply / OK.

There must be **no NAT device** attached to this vmnet.

## 2. Point both VMs at it, and only it

For each VM: **VM → Settings → Network Adapter**:
- Set to **Custom: VMnet10**.
- Remove any second adapter (no NAT, no Bridged).
- Leave "Connect at power on" checked.

## 3. Lock down the VM (Settings)

- **Options → Guest Isolation**: uncheck **Enable drag and drop** and **Enable copy and paste**.
- **Options → Shared Folders**: **Disabled**.
- No USB passthrough of host drives.
- Optional hardening: **Options → Advanced → Disable acceleration** not needed; do
  enable **side channel mitigations** if offered.

## 4. Static IPs (netplan, Ubuntu 24.04)

`victim`  → `/etc/netplan/50-lab.yaml`:
```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      addresses: [192.168.190.20/24]
      # no gateway, no nameservers  -> no route off-segment
```
`analysis` → same file, address `192.168.190.10/24`, no gateway/DNS.

Apply: `sudo netplan apply`.

## 5. Prove isolation (run network-check.sh on each)

Expected: can ping the *other* VM, cannot resolve DNS, cannot reach 1.1.1.1 or any
public host. If any external reach succeeds, **do not proceed** — a wrong adapter is attached.
