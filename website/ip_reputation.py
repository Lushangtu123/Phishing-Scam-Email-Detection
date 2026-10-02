"""Checked-in IP lists: Tor exit addresses and Spamhaus DROP networks.

The snapshot is built by tools/update_ip_reputation.py and never fetched at runtime, so
no address from a message ever leaves the server. Lists describe the day they were
fetched, not the day a message was sent.
"""

from __future__ import annotations

from bisect import bisect_right
from functools import lru_cache
import ipaddress
import json
from pathlib import Path

REPUTATION_SCHEMA = "phishguard-ip-reputation-v1"
DEFAULT_REPUTATION_PATH = Path(__file__).parent / "data" / "ip_reputation.json"
# A list this small means a fetch went wrong (an error page, a truncated file).
MIN_TOR_EXITS = 100
MIN_DROP_NETWORKS = 100


def validate_ip_reputation(payload: dict) -> None:
    """Raise ValueError unless payload is a well-formed snapshot."""
    if payload.get("schema") != REPUTATION_SCHEMA:
        raise ValueError("unknown IP reputation schema")
    tor, drop = payload.get("tor_exits") or {}, payload.get("spamhaus_drop") or {}
    for name, section in (("tor_exits", tor), ("spamhaus_drop", drop)):
        for key in ("source", "fetched"):
            if not isinstance(section.get(key), str) or not section[key]:
                raise ValueError(f"{name}.{key} is missing")
    addresses = tor.get("addresses")
    if not isinstance(addresses, list) or len(addresses) < MIN_TOR_EXITS:
        raise ValueError("too few Tor exit addresses")
    for address in addresses:
        ipaddress.ip_address(address)
    networks = drop.get("networks")
    if not isinstance(networks, list) or len(networks) < MIN_DROP_NETWORKS:
        raise ValueError("too few DROP networks")
    for network, listing in networks:
        ipaddress.ip_network(network)
        if not isinstance(listing, str):
            raise ValueError("DROP listing id must be text")
    if not drop.get("copyright") or not drop.get("terms"):
        raise ValueError("Spamhaus DROP requires its copyright and terms to stay with the data")


class IpReputation:
    """Lookups against one snapshot."""

    def __init__(self, payload: dict):
        validate_ip_reputation(payload)
        self.tor_date = payload["tor_exits"]["fetched"][:10]
        self.drop_date = payload["spamhaus_drop"]["fetched"][:10]
        self._tor = frozenset(ipaddress.ip_address(address) for address in payload["tor_exits"]["addresses"])
        # Sorted by first address per family: a lookup is one bisection, then a containment test.
        self._drop = {}
        for network, listing in payload["spamhaus_drop"]["networks"]:
            parsed = ipaddress.ip_network(network)
            self._drop.setdefault(parsed.version, []).append((int(parsed.network_address), parsed, listing))
        for entries in self._drop.values():
            entries.sort(key=lambda entry: entry[0])
        self._drop_starts = {version: [entry[0] for entry in entries] for version, entries in self._drop.items()}

    def tor_exit(self, address: str) -> bool:
        try:
            return ipaddress.ip_address(address) in self._tor
        except ValueError:
            return False

    def drop_listing(self, address: str) -> str | None:
        """The Spamhaus listing id (SBL…) of the DROP network holding address, or None."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return None
        entries = self._drop.get(parsed.version, [])
        # DROP networks do not overlap, so only the closest one starting at or below can hold it.
        index = bisect_right(self._drop_starts.get(parsed.version, []), int(parsed)) - 1
        if index >= 0 and parsed in entries[index][1]:
            return entries[index][2]
        return None


@lru_cache(maxsize=1)
def load_ip_reputation(path: Path = DEFAULT_REPUTATION_PATH) -> IpReputation | None:
    """The checked-in snapshot, or None when it is missing or malformed."""
    try:
        return IpReputation(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, KeyError):
        return None
