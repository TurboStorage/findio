# Test fixtures

Synthetic sample outputs for the parser tests. Addresses come from the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and MACs
from the RFC 7042 documentation block (00:00:5E:00:53:xx), so nothing here
identifies a real network.

If you capture new samples from your own machines, scrub IPs and MACs before
committing them.

## What each fixture covers

### arp_macos_sample.txt (`arp -an`)
- Normal rows on `en0`
- Short-octet MAC (`e:0:5e:0:53:f`) - tests normalization
- `(incomplete)` row - skipped by the parser
- `permanent` static entry - parses like a normal row
- Broadcast and multicast rows - dropped

### arp_linux_sample.txt (`ip neigh show`)
- `REACHABLE`, `STALE`, `DELAY`, `PROBE`, `PERMANENT`, `NOARP` rows - accepted
- `FAILED` / `INCOMPLETE` rows (no `lladdr`) - skipped
- Two interfaces - tests multi-iface handling
