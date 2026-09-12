from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from authority import (  # noqa: E402
    AuthorityError,
    AuthorityRecord,
    NonceStore,
    sign_record,
    validate_live_binding,
    validate_static,
    verify_signature,
)
from compare_snapshots import compare_pages, load_pages, target_specific  # noqa: E402


def authority_record(**changes):
    raw = dict(
        job_id="BT-20260912-TEST-0001",
        terminal_id="MT5-2",
        agent_pid=4242,
        agent_creation_time_100ns=133700000000000000,
        agent_image_path=r"C:\VibeMQL5\terminals\MT5-2\Tester\Agent-127.0.0.1-3000\metatester64.exe",
        ea_binary_ref="BIN-" + "a" * 64,
        ea_sha256="b" * 64,
        nonce="0123456789abcdef0123456789abcdef",
        expires_at_utc=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    )
    raw.update(changes)
    return AuthorityRecord(**raw)


def test_authority_signature_and_exact_live_binding():
    key = b"k" * 32
    rec = sign_record(authority_record(), key)
    verify_signature(rec, key)
    validate_static(rec, [r"C:\VibeMQL5\terminals\MT5-2\Tester"])
    validate_live_binding(
        rec,
        observed_pid=4242,
        observed_creation_time_100ns=rec.agent_creation_time_100ns,
        observed_image_path=rec.agent_image_path,
    )


def test_pid_reuse_fails_closed():
    rec = authority_record()
    with pytest.raises(AuthorityError, match="creation time"):
        validate_live_binding(
            rec,
            observed_pid=rec.agent_pid,
            observed_creation_time_100ns=rec.agent_creation_time_100ns + 1,
            observed_image_path=rec.agent_image_path,
        )


def test_wrong_process_and_wrong_terminal_fail_closed():
    with pytest.raises(AuthorityError):
        validate_static(
            authority_record(agent_image_path=r"C:\Windows\System32\notepad.exe"),
            [r"C:\VibeMQL5\terminals\MT5-2\Tester"],
        )
    with pytest.raises(AuthorityError):
        validate_static(
            authority_record(terminal_id="MT5-3"),
            [r"C:\VibeMQL5\terminals\MT5-2\Tester"],
        )


def test_expired_and_replayed_authority_fail_closed():
    expired = authority_record(expires_at_utc=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
    with pytest.raises(AuthorityError, match="expired"):
        validate_static(expired, [r"C:\VibeMQL5\terminals\MT5-2\Tester"])

    store = NonceStore()
    store.consume("nonce")
    with pytest.raises(AuthorityError, match="already used"):
        store.consume("nonce")


def test_tampered_authority_signature_fails():
    key = b"k" * 32
    signed = sign_record(authority_record(), key)
    tampered = AuthorityRecord(**{**signed.__dict__, "agent_pid": 9999})
    with pytest.raises(AuthorityError, match="signature"):
        verify_signature(tampered, key)


def test_page_delta_and_target_control(tmp_path: Path):
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    a.write_text(
        "\n".join(
            [
                json.dumps({"address": "0x1000", "size": 4096, "sha256": "a" * 64}),
                json.dumps({"address": "0x2000", "size": 4096, "sha256": "b" * 64}),
            ]
        ),
        encoding="utf-8",
    )
    b.write_text(
        "\n".join(
            [
                json.dumps({"address": "0x1000", "size": 4096, "sha256": "a" * 64}),
                json.dumps({"address": "0x2000", "size": 4096, "sha256": "c" * 64}),
                json.dumps({"address": "0x3000", "size": 4096, "sha256": "d" * 64}),
            ]
        ),
        encoding="utf-8",
    )
    pa, pb = load_pages(a), load_pages(b)
    diff = compare_pages(pa, pb)
    assert diff["summary"] == {
        "pages_a": 2,
        "pages_b": 3,
        "added": 1,
        "removed": 0,
        "changed": 1,
        "unchanged": 1,
    }
    assert len(target_specific(pb, pa)) == 2


def test_capture_cli_has_no_arbitrary_target_surface():
    source = (SCRIPTS / "runtime_capture_windows.py").read_text(encoding="utf-8")
    forbidden = ('add_argument("--pid"', 'add_argument("--process-name"', 'add_argument("--address"', 'add_argument("--command"')
    for token in forbidden:
        assert token not in source
