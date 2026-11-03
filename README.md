# FindIO

Find the machine you just plugged in, or its management controller (BMC/IPMI), on a crowded LAN.

FindIO is a small terminal tool. You snapshot the network before you plug a system in, plug it in, and diff. Whatever is new is your machine. Labels are stored against the MAC address, so a name like `bench-2` survives DHCP renewals.

## Only scan networks you are authorized to use

FindIO sends an ICMP echo to every host in the subnet, reads the ARP cache, and (by default) opens TCP port 22 on each host it found to read the SSH banner. That is active scanning. Use it only on networks you own or are explicitly authorized to test.

Built-in guard rails:

- It scans only the subnet bound to one of your own interfaces, unless you pass `--cidr`.
- It refuses publicly routable ranges unless you pass `--allow-public`.
- It refuses sweeps larger than 1024 hosts (a /22).
- Ping starts are rate limited (`--max-rate`, default 200 per second) with at most 64 workers by default.
- The SSH banner probe reads one greeting line and sends nothing. Disable it with `--no-ssh-probe`, or skip all probing beyond ping with `--no-resolve`.

## What it does

| Command | What it does |
|---|---|
| `findio scan` | ICMP sweep, ARP scrape, then name/vendor resolution. Prints a table or `--json`. |
| `findio scan --watch` | Rescans every `--interval` seconds and prints only NEW / LOST / CHANGED. |
| `findio baseline save NAME` / `list` / `drop NAME` | Named snapshots of the last recorded scan. |
| `findio diff [--against NAME]` | NEW / CHANGED (same MAC, new IP) / LOST versus a baseline or the previous scan. |
| `findio label MAC LABEL` | Attach a sticky label to a MAC (`--clear` removes it). |
| `findio pick` | Textual TUI picker. Prints the chosen device as `user@ip` (or `--json`). |
| `findio pick --label NAME` | Non-interactive lookup of a label. |
| `findio version` | Prints the API version. |

Name resolution, in order: operator label, reverse DNS, SSH banner fingerprint (recognizes HPE iLO, Dell iDRAC, Supermicro, OpenBMC, AMI MegaRAC, ASPEED, Dropbear), then OUI vendor from the MAC. The bundled `findio/data/oui.csv` is a small hand-curated subset (about 130 prefixes) of the public IEEE MA-L OUI registry (https://standards-oui.ieee.org/); OUI assignments are public registry facts, and vendor names are trademarks of their owners. Drop a full IEEE `oui.csv` into `~/.findio/` to override it.

The TUI (`findio pick`) scans on open. Enter picks, `r` rescans, `w` toggles watch mode (new rows green, lost rows struck through, moved rows amber), click a column header to sort, `q` quits. It returns the device to the caller; it does not launch SSH itself.

## Install

Requires Python 3.10+. The library and CLI use only the standard library.

```bash
pip install .            # CLI + library
pip install ".[tui]"     # adds Textual + Rich for `findio pick`
findio version
```

Or run from a checkout: `python findio.py scan`.

## Usage

```bash
findio scan                          # sweep and record (before you plug the system in)
findio baseline save pre-plug        # snapshot that scan
# ... plug the system in ...
findio scan                          # sweep again
findio diff --against pre-plug       # what is new?
findio label 00:00:5E:00:53:4D bench-2
findio pick --label bench-2 --json   # script-friendly lookup
```

Sample output, from synthetic documentation-range addresses (see `docs/sample-output.txt`):

```
$ findio scan --iface eth0 --cidr 192.0.2.0/24
# eth0 192.0.2.0/24  2026-01-01T10:00:05+00:00 -> 2026-01-01T10:00:07+00:00
IP               MAC                LABEL          HOSTNAME                 VENDOR
----------------------------------------------------------------------------------------------------
192.0.2.1        00:00:5E:00:53:01                 gateway.example.test     Example Networks
192.0.2.20       00:00:5E:00:53:14                 printer.example.test     Example Print
192.0.2.77       00:00:5E:00:53:4D                                          AMI Megarac
# 3 device(s)

$ findio diff --against pre-plug
# diff vs baseline 'pre-plug'
  NEW        192.0.2.77       00:00:5E:00:53:4D
  LOST       192.0.2.5        00:00:5E:00:53:05
# new=1 changed=0 lost=1 returned=0 unchanged=2
```

Two NICs (for example a production LAN and a separate BMC network): `findio scan --all` sweeps every UP interface and each row shows its interface.

Exit codes: 0 success, 1 cancelled, 2 error, 3 nothing found / label unknown.

Library use:

```python
from findio import Scanner, DeviceRegistry, pick_by_label
result = Scanner(iface="eth0").scan()
device = pick_by_label("bench-2")
```

## Platform support

| Platform | Status |
|---|---|
| Linux | Supported (`ip neigh`, `ip -4 -o addr`, iputils `ping`). |
| macOS | Supported (`arp -an`, `ifconfig`). |
| Windows | Not supported for live scanning (it reports "no scannable interfaces"). The test suite does run on Windows. |

## Limits

- Sees only hosts on networks your machine is directly attached to. No L3 access, no visibility.
- Cannot catch a BMC that is mid-reset while the scan runs.
- Cannot tell two identical BMCs apart without operator labels.
- IPv4 only. Not a replacement for nmap.
- mDNS, NetBIOS and HTTPS certificate probes are not implemented.
- Data note: the registry at `~/.findio/state.db` stores IPs, MACs, hostnames, SSH banners and your labels. Keep it out of shared folders and bug reports.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

See `ARCHITECTURE.md` for the data flow and the stable JSON/API contract. License: MIT.
