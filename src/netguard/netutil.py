from __future__ import annotations

import ipaddress


def normalize_ip(ip: str) -> str:
    if not ip:
        return ""
    ip = ip.split("%")[0]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def parse(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_public(ip: str) -> bool:
    """True nếu là địa chỉ internet công cộng (không phải LAN/loopback/multicast...)."""
    addr = parse(ip)
    return bool(addr and addr.is_global and not addr.is_multicast)


def is_loopback(ip: str) -> bool:
    addr = parse(ip)
    return bool(addr and (addr.is_loopback or addr.is_unspecified))


def fmt_addr(ip: str, port: int) -> str:
    if not ip:
        return "—"
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def is_loopback_only(ip: str) -> bool:
    """Chỉ true với 127.0.0.0/8 và ::1 — KHÔNG gồm 0.0.0.0/:: (đang mở ra toàn mạng)."""
    addr = parse(ip)
    return bool(addr and addr.is_loopback)
