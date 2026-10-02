"""Download IANA's RDAP bootstrap for domains and write website/data/rdap_bootstrap.json.

Run by hand from the repository root, then review and commit the snapshot:

    python website/tools/update_rdap_bootstrap.py

Source: https://data.iana.org/rdap/dns.json (RFC 9224), public IANA data. Only the
https server URLs are kept.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from urllib.request import Request, urlopen

WEBSITE_DIR = Path(__file__).resolve().parents[1]
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

from domain_age import BOOTSTRAP_SCHEMA, DEFAULT_BOOTSTRAP_PATH, validate_bootstrap  # noqa: E402

SOURCE = "https://data.iana.org/rdap/dns.json"
MAX_BYTES = 2 * 1024 * 1024


def build(opener=urlopen, now: datetime | None = None) -> dict:
    with opener(Request(SOURCE, headers={"User-Agent": "PhishGuard-rdap-bootstrap-update/1"}), timeout=30) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("the bootstrap is larger than expected")
    iana = json.loads(data.decode("utf-8"))
    services = []
    for tlds, urls in iana.get("services", []):
        secure = [url for url in urls if str(url).startswith("https://")]
        if secure and tlds:
            services.append([sorted(str(tld).lower() for tld in tlds), secure])
    payload = {
        "schema": BOOTSTRAP_SCHEMA,
        "source": SOURCE,
        "fetched": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%MZ"),
        "publication": iana.get("publication"),
        "services": services,
    }
    validate_bootstrap(payload)
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
    parser.add_argument("--output", type=Path, default=DEFAULT_BOOTSTRAP_PATH)
    args = parser.parse_args()
    payload = build()
    write(payload, args.output)
    print(f"RDAP services: {len(payload['services'])}, top-level domains: "
          f"{sum(len(tlds) for tlds, _urls in payload['services'])}; written to {args.output}")


if __name__ == "__main__":
    main()
