#!/usr/bin/env python3
"""Compare normalized MT5 runtime snapshot page inventories.

Input is JSONL with one object per memory page/region fragment. Required fields:
address, size, sha256. Optional fields such as type/protect/module are preserved.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_pages(path: Path) -> dict[int, dict]:
    pages: dict[int, dict] = {}
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            for key in ("address", "size", "sha256"):
                if key not in obj:
                    raise ValueError(f"{path}:{line_no}: missing {key}")
            address = int(obj["address"], 0) if isinstance(obj["address"], str) else int(obj["address"])
            if address in pages:
                raise ValueError(f"{path}:{line_no}: duplicate address {address:#x}")
            obj["address"] = address
            pages[address] = obj
    return pages


def compare_pages(a: dict[int, dict], b: dict[int, dict]) -> dict:
    added = []
    removed = []
    changed = []
    unchanged = 0

    for address in sorted(set(a) | set(b)):
        pa = a.get(address)
        pb = b.get(address)
        if pa is None:
            added.append(pb)
            continue
        if pb is None:
            removed.append(pa)
            continue
        if pa["sha256"].lower() != pb["sha256"].lower() or int(pa["size"]) != int(pb["size"]):
            changed.append({
                "address": address,
                "before": pa,
                "after": pb,
            })
        else:
            unchanged += 1

    return {
        "summary": {
            "pages_a": len(a),
            "pages_b": len(b),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": unchanged,
        },
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def target_specific(target: dict[int, dict], control: dict[int, dict]) -> list[dict]:
    out = []
    for address, page in sorted(target.items()):
        other = control.get(address)
        if other is None or other["sha256"].lower() != page["sha256"].lower():
            out.append(page)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("a", type=Path)
    ap.add_argument("b", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--mode", choices=("delta", "target-control"), default="delta")
    args = ap.parse_args()

    a = load_pages(args.a)
    b = load_pages(args.b)
    if args.mode == "delta":
        result = compare_pages(a, b)
    else:
        pages = target_specific(a, b)
        result = {"summary": {"target_specific": len(pages)}, "pages": pages}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
