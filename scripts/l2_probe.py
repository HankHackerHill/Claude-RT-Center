#!/usr/bin/env python3
"""Isolation probe that bypasses the container's routing table. Runs INSIDE a range container (needs CAP_NET_RAW):

  docker exec -i <container> python3 - <bridge_mac> <dst_ip> [count] [spoofed_src_ip] < scripts/l2_probe.py

Sends `count` ICMP echo requests as raw Ethernet frames straight to the bridge's MAC, addressed to a host-local IP.
A host that accepts IP from br-range (rp_filter=0, no INPUT drop) will process them; scripts/verify.py measures that
from the host side (kernel Icmp InEchos counter + the DROP rule's packet counter). Gate 1's other probe uses normal
sockets, which the container kernel stops before any packet leaves (no route / no ARP): it cannot see this path.
Stdlib only; the payload is a fixed marker, nothing else.
"""
import socket
import struct
import sys


def csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def frame(dst_mac: bytes, src_mac: bytes, src_ip: str, dst_ip: str, seq: int) -> bytes:
    payload = b"cc-l2-isolation-probe"
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0xCC01, seq) + payload
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), seq, 0, 64, 1, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + icmp


def main() -> None:
    bridge_mac = bytes.fromhex(sys.argv[1].replace(":", ""))
    dst_ip, count = sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 3
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth0", 0))
    src_mac = s.getsockname()[4]
    own_ip = socket.inet_ntoa(__import__("fcntl").ioctl(s.fileno(), 0x8915, struct.pack("256s", b"eth0"))[20:24])
    src_ip = sys.argv[4] if len(sys.argv) > 4 else own_ip   # spoofed source: exercises tripwire 9000009
    for i in range(count):
        s.send(frame(bridge_mac, src_mac, src_ip, dst_ip, i + 1))
    print(f"sent {count} echo frames {src_ip} -> {dst_ip} via {sys.argv[1]}")


if __name__ == "__main__":
    main()
