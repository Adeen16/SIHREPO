"""
datasets_gen/addresses.py
--------------------------
Address-range constants for synthetic traffic generation.

RULES (non-negotiable):
- Internal hosts: 10.0.0.0/16
- External servers: 198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24
- Botnet/DDoS spoofed sources: 100.64.0.0/10
- NEVER use real public addresses (8.8.8.8 etc.)

All address generation goes through this module.
"""
from __future__ import annotations
import ipaddress
import random
from typing import List

_INTERNAL_NET = ipaddress.IPv4Network("10.0.0.0/16")
_EXTERNAL_NETS = [
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
]
_BOTNET_NET = ipaddress.IPv4Network("100.64.0.0/10")


def _host(net: ipaddress.IPv4Network, idx: int) -> str:
    """Return the idx-th host address in a network (wraps)."""
    hosts = list(net.hosts())
    return str(hosts[idx % len(hosts)])


def internal_host(idx: int) -> str:
    return _host(_INTERNAL_NET, idx)


def external_host(idx: int) -> str:
    net = _EXTERNAL_NETS[idx % len(_EXTERNAL_NETS)]
    return _host(net, idx // len(_EXTERNAL_NETS))


def botnet_source(idx: int) -> str:
    return _host(_BOTNET_NET, idx)


def random_internal(rng: random.Random) -> str:
    hosts = list(_INTERNAL_NET.hosts())
    return str(rng.choice(hosts))


def random_external(rng: random.Random) -> str:
    net = rng.choice(_EXTERNAL_NETS)
    hosts = list(net.hosts())
    return str(rng.choice(hosts))


def random_botnet(rng: random.Random) -> str:
    hosts = list(_BOTNET_NET.hosts())
    return str(rng.choice(hosts[:65534]))  # take first /16 worth
