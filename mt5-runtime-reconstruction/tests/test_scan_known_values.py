from __future__ import annotations

import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from scan_known_values import scan  # noqa: E402


def test_scan_maps_float_and_integer_values_back_to_runtime_addresses(tmp_path: Path):
    page0 = bytearray(4096)
    page1 = bytearray(4096)

    page0[32:40] = struct.pack("<d", 5.0)
    page0[128:132] = struct.pack("<f", 0.01)
    page1[64:72] = struct.pack("<q", 1231213)

    mem = tmp_path / "private-regions.bin"
    mem.write_bytes(bytes(page0) + bytes(page1))

    pages = tmp_path / "page-hashes.jsonl"
    pages.write_text(
        "\n".join(
            [
                json.dumps({"address": "0x100000", "size": 4096, "sidecar_offset": 0, "protect": 4}),
                json.dumps({"address": "0x200000", "size": 4096, "sidecar_offset": 4096, "protect": 4}),
            ]
        ),
        encoding="utf-8",
    )

    result = scan(mem, pages, ["5.0", "0.01", "1231213"], max_hits_per_pattern=20)
    hits = result["hits"]

    assert any(h["requested"] == "5.0" and h["representation"] == "float64_le" and h["address"] == hex(0x100000 + 32) for h in hits)
    assert any(h["requested"] == "0.01" and h["representation"] == "float32_le" and h["address"] == hex(0x100000 + 128) for h in hits)
    assert any(h["requested"] == "1231213" and h["representation"] == "int64_le" and h["address"] == hex(0x200000 + 64) for h in hits)


def test_scan_rejects_page_range_outside_sidecar(tmp_path: Path):
    mem = tmp_path / "private-regions.bin"
    mem.write_bytes(b"\x00" * 8)
    pages = tmp_path / "page-hashes.jsonl"
    pages.write_text(json.dumps({"address": "0x1000", "size": 4096, "sidecar_offset": 0}), encoding="utf-8")

    try:
        scan(mem, pages, ["1"], 10)
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("expected invalid sidecar range to fail")
