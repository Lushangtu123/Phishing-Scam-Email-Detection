"""Download the Tor exit list and Spamhaus DROP, and write website/data/ip_reputation.json.

Run by hand from the repository root, then review and commit the snapshot:

    python website/tools/update_ip_reputation.py

Sources and terms:
- Tor Project bulk exit list, https://check.torproject.org/torbulkexitlist (CC0).
- Spamhaus DROP, https://www.spamhaus.org/drop/drop_v4.json and drop_v6.json. Free to
  use and bundle with credit to The Spamhaus Project; the date and copyright stay with
  the data (https://www.spamhaus.org/drop/terms/). Do not fetch more than once an hour.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
from urllib.request import Request, urlopen

WEBSITE_DIR = Path(__file__).resolve().parents[1]
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from ip_reputation import DEFAULT_REPUTATION_PATH, REPUTATION_SCHEMA, validate_ip_reputation  # noqa: E402

TOR_URL = "https://check.torproject.org/torbulkexitlist"
DROP_URLS = ("https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json")
DROP_TERMS = "https://www.spamhaus.org/drop/terms/"
MAX_BYTES = 2 * 1024 * 1024
USER_AGENT = "PhishGuard-ip-reputation-update/1 (manual, at most daily)"


def fetch(url: str, opener=urlopen) -> str:
    with opener(Request(url, headers={"User-Agent": USER_AGENT}), timeout=30) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url} is larger than expected")
    return data.decode("utf-8")


def parse_tor(text: str) -> list[str]:
    addresses = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            addresses.add(str(ipaddress.ip_address(line)))
    return sorted(addresses, key=lambda address: (ipaddress.ip_address(address).version, ipaddress.ip_address(address)))


def parse_drop(texts: list[str]) -> tuple[list[list[str]], dict]:
    """DROP's JSON lines: one {"cidr", "sblid", "rir"} per network, then a metadata line."""
    networks, metadata = {}, {}
    for text in texts:
        for line in text.splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("type") == "metadata":
                metadata.setdefault("copyright", record.get("copyright"))
                metadata.setdefault("timestamps", []).append(record.get("timestamp"))
            elif record.get("cidr"):
                networks[str(ipaddress.ip_network(record["cidr"]))] = str(record.get("sblid") or "")
    ordered = sorted(networks.items(), key=lambda item: (ipaddress.ip_network(item[0]).version,
                                                         ipaddress.ip_network(item[0])))
    return [[network, listing] for network, listing in ordered], metadata


def build(opener=urlopen, now: datetime | None = None) -> dict:
    fetched = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%MZ")
    networks, metadata = parse_drop([fetch(url, opener) for url in DROP_URLS])
    listed = [datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
              for stamp in metadata.get("timestamps", []) if isinstance(stamp, (int, float))]
    payload = {
        "schema": REPUTATION_SCHEMA,
        "tor_exits": {
            "source": TOR_URL,
            "license": "CC0 (Tor Project)",
            "fetched": fetched,
            "addresses": parse_tor(fetch(TOR_URL, opener)),
        },
        "spamhaus_drop": {
            "source": " ".join(DROP_URLS),
            "copyright": metadata.get("copyright") or "(c) The Spamhaus Project",
            "terms": DROP_TERMS,
            "fetched": fetched,
            "list_timestamps": listed,
            "networks": networks,
        },
    }
    validate_ip_reputation(payload)
    return payload


def write(payload: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, prefix=f".{output.name}.",
                                         delete=False) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(payload, temporary, indent=1, ensure_ascii=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_REPUTATION_PATH)
    args = parser.parse_args()
    payload = build()
    write(payload, args.output)
    print(f"Tor exits: {len(payload['tor_exits']['addresses'])}; "
          f"DROP networks: {len(payload['spamhaus_drop']['networks'])}; written to {args.output}")


if __name__ == "__main__":
    main()
