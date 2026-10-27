# Quiet

**By Syed Sadam Hussain Shah** — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)

A lightweight ARP spoofing and bandwidth-control tool for **authorized** LAN security assessments.
Quiet places a tester silently between a target and its gateway, with a default ghost mode that
makes ARP poison packets appear to originate from the victim's own MAC — reducing the footprint
visible to ARP-inspection sensors.

> **Authorized use only.** Only run on networks you own or have written permission to test.

---

## Capabilities

| Feature | Details |
|---|---|
| **LAN discovery** | Broadcast ARP scan over any CIDR range (auto-derives `/24` from gateway) |
| **ARP MITM** | Bidirectional ARP poison — intercepts target ↔ gateway traffic |
| **Ghost mode** | Poison Ethernet frames carry the victim's own MAC as source (stealth default) |
| **Bandwidth cap** | Per-target rate limiting via Linux `tc` HTB qdisc (kbps) |
| **MAC-based cut** | Cut by MAC address; tracks IP changes automatically via live ARP sniff |
| **Clean restore** | `restore` command and Ctrl+C both send five correct ARP replies to both sides |

---

## Requirements

| Requirement | Notes |
|---|---|
| **Python 3.8+** | |
| **scapy** | `pip install scapy` |
| **Root / CAP_NET_RAW** | `sudo python3 quiet.py ...` |
| **Linux** | Uses `/proc/sys/net/ipv4/ip_forward` and `tc` (iproute2) |
| **iproute2** | `apt install iproute2` — needed for `--rate` bandwidth cap |

```bash
pip install scapy
```

---

## Usage

```bash
# Discover hosts on the local network (auto-derives /24 from gateway)
sudo python3 quiet.py scan
sudo python3 quiet.py scan 10.0.0.0/24

# Intercept a target (MITM — traffic flows through you and is forwarded)
sudo python3 quiet.py cut 192.168.1.50

# Intercept with bandwidth cap (512 kbps)
sudo python3 quiet.py cut 192.168.1.50 --rate 512

# Ghost mode: send as a custom MAC / IP instead of the victim's own
sudo python3 quiet.py cut 192.168.1.50 --src-mac de:ad:be:ef:00:01 --src-ip 192.168.1.50

# Disable ghost mode entirely (use your real MAC as ARP source)
sudo python3 quiet.py cut 192.168.1.50 --no-ghost

# Restore correct ARP and stop intercept
sudo python3 quiet.py restore 192.168.1.50

# Cut by MAC address — follows the device even if its IP changes (DHCP)
sudo python3 quiet.py cut-mac aa:bb:cc:dd:ee:ff
sudo python3 quiet.py cut-mac aa:bb:cc:dd:ee:ff --network 10.0.0.0/24
sudo python3 quiet.py cut-mac aa:bb:cc:dd:ee:ff --src-mac de:ad:be:ef:00:01
sudo python3 quiet.py cut-mac aa:bb:cc:dd:ee:ff --no-ghost
```

### Global option

```
-i / --iface ETH   Network interface (default: auto-detect from routing table)
```

### `cut` options

| Flag | Description |
|---|---|
| `-r / --rate KBPS` | Cap outgoing traffic to target at this many kilobits per second |
| `--src-mac MAC` | Override ghost source MAC (default: victim's own MAC) |
| `--src-ip IP` | Override ghost source IP displayed in ARP packets |
| `--no-ghost` | Use your real MAC as the ARP source (louder, easier to detect) |

### `cut-mac` options

| Flag | Description |
|---|---|
| `-n / --network CIDR` | Subnet to scan (default: auto from gateway) |
| `-r / --rescan SECS` | Re-scan interval in seconds (default: 120) |
| `--src-mac MAC` | Override ghost source MAC |
| `--src-ip IP` | Override ghost source IP |
| `--no-ghost` | Disable ghost mode |

---

## How it works

1. **scan** — sends a broadcast ARP request and prints every responding IP / MAC.
2. **cut** — poisons the target's ARP cache (gateway IP → attacker MAC) and the gateway's cache (target IP → attacker MAC), then enables kernel IP forwarding so traffic passes through. Repeats every 1.5 s.
3. **Ghost mode** — sets the Ethernet *source* field of each ARP reply to the victim's own MAC, so the frames look like the victim is contradicting itself rather than a third party sending updates.
4. **cut-mac** — disables IP forwarding (traffic is dropped, not forwarded), then uses both a passive ARP sniffer and a periodic active probe to track the target's current IP as it changes.
5. **restore / Ctrl+C** — sends five correct ARP replies to each side and clears `tc` rules.

---

## License

MIT — see [LICENSE](LICENSE). Contributions and issues welcome.

**Author:** Syed Sadam Hussain Shah — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)
