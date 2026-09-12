#!/usr/bin/env python3
"""Scan normalized MT5 private-memory sidecar for known numeric values.

The capture helper stores readable MEM_PRIVATE pages consecutively in private-regions.bin
and records original virtual addresses plus sidecar offsets in page-hashes.jsonl. This
scanner maps exact little-endian representations back to runtime addresses.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct


def load_pages(path: Path) -> list[dict]:
    pages = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            for key in ("address", "size", "sidecar_offset"):
                if key not in obj:
                    raise ValueError(f"{path}:{line_no}: missing {key}")
            obj["address"] = int(obj["address"], 0) if isinstance(obj["address"], str) else int(obj["address"])
            obj["size"] = int(obj["size"])
            obj["sidecar_offset"] = int(obj["sidecar_offset"])
            pages.append(obj)
    pages.sort(key=lambda x: x["sidecar_offset"])
    return pages


def patterns_for(value: str) -> list[tuple[str, bytes, str]]:
    """Return representation name, bytes, normalized display value."""
    out: list[tuple[str, bytes, str]] = []

    # Float forms are always useful for EA inputs/prices/lots.
    f = float(value)
    out.append(("float64_le", struct.pack("<d", f), repr(f)))
    out.append(("float32_le", struct.pack("<f", f), repr(f)))

    # Integer forms are added only when the text is exactly integral.
    try:
        i = int(value, 0)
    except ValueError:
        i = None
    if i is not None:
        if -(1 << 31) <= i < (1 << 31):
            out.append(("int32_le", struct.pack("<i", i), str(i)))
            if i >= 0:
                out.append(("uint32_le", struct.pack("<I", i), str(i)))
        if -(1 << 63) <= i < (1 << 63):
            out.append(("int64_le", struct.pack("<q", i), str(i)))
            if i >= 0:
                out.append(("uint64_le", struct.pack("<Q", i), str(i)))
    return out


def find_all(blob: bytes, needle: bytes, limit: int) -> list[int]:
    hits = []
    start = 0
    while len(hits) < limit:
        idx = blob.find(needle, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
    return hits


def scan(sidecar: Path, pages_path: Path, values: list[str], max_hits_per_pattern: int = 500) -> dict:
    blob = sidecar.read_bytes()
    pages = load_pages(pages_path)
    results = []

    for requested in values:
        for representation, needle, normalized in patterns_for(requested):
            hit_count = 0
            for page in pages:
                begin = page["sidecar_offset"]
                end = begin + page["size"]
                if begin < 0 or end > len(blob):
                    raise ValueError("page sidecar range outside private-regions.bin")
                page_blob = blob[begin:end]
                remaining = max_hits_per_pattern - hit_count
                if remaining <= 0:
                    break
                for local in find_all(page_blob, needle, remaining):
                    results.append(
                        {
                            "requested": requested,
                            "normalized": normalized,
                            "representation": representation,
                            "address": hex(page["address"] + local),
                            "page_address": hex(page["address"]),
                            "page_offset": local,
                            "sidecar_offset": begin + local,
                            "protect": page.get("protect"),
                        }
                    )
                    hit_count += 1

    summary = {}
    for hit in results:
        key = f"{hit['requested']}:{hit['representation']}"
        summary[key] = summary.get(key, 0) + 1
    return {"summary": summary, "hits": results}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--memory", type=Path, required=True)
    ap.add_argument("--pages", type=Path, required=True)
    ap.add_argument("--value", action="append", required=True, help="Known number; repeatable")
    ap.add_argument("--max-hits", type=int, default=500)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    if args.max_hits < 1 or args.max_hits > 10000:
        raise SystemExit("--max-hits must be between 1 and 10000")

    result = scan(args.memory, args.pages, args.value, args.max_hits)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"patterns": len(result["summary"]), "hits": len(result["hits"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
