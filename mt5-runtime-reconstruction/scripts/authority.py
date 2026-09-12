#!/usr/bin/env python3
"""TIP-026R3 job-bound runtime capture authority.

This module deliberately does not discover processes or accept process names from callers.
The trusted bridge resolves a running tester job, signs an authority record, then the
capture layer verifies that the live process still matches that record.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import PureWindowsPath
from typing import Iterable


EXPECTED_AGENT_BASENAME = "metatester64.exe"
EXPECTED_TERMINAL_ID = "MT5-2"


class AuthorityError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorityRecord:
    job_id: str
    terminal_id: str
    agent_pid: int
    agent_creation_time_100ns: int
    agent_image_path: str
    ea_binary_ref: str
    ea_sha256: str
    nonce: str
    expires_at_utc: str
    signature: str = ""

    @classmethod
    def from_dict(cls, raw: dict) -> "AuthorityRecord":
        return cls(**raw)

    def unsigned_dict(self) -> dict:
        raw = asdict(self)
        raw.pop("signature", None)
        return raw


def canonical_payload(record: AuthorityRecord) -> bytes:
    return json.dumps(
        record.unsigned_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_record(record: AuthorityRecord, key: bytes) -> AuthorityRecord:
    if not key:
        raise AuthorityError("empty signing key")
    signature = hmac.new(key, canonical_payload(record), hashlib.sha256).hexdigest()
    return AuthorityRecord(**record.unsigned_dict(), signature=signature)


def verify_signature(record: AuthorityRecord, key: bytes) -> None:
    if not key:
        raise AuthorityError("empty signing key")
    expected = hmac.new(key, canonical_payload(record), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, record.signature.lower()):
        raise AuthorityError("authority signature mismatch")


def _norm_win(path: str) -> str:
    return str(PureWindowsPath(path)).replace("/", "\\").rstrip("\\").casefold()


def _is_under(path: str, roots: Iterable[str]) -> bool:
    p = _norm_win(path)
    for root in roots:
        r = _norm_win(root)
        if p == r or p.startswith(r + "\\"):
            return True
    return False


def validate_static(record: AuthorityRecord, allowed_agent_roots: Iterable[str], now=None) -> None:
    if not record.job_id.startswith("BT-"):
        raise AuthorityError("invalid tester job id")
    if record.terminal_id != EXPECTED_TERMINAL_ID:
        raise AuthorityError("authority is not bound to fixed terminal MT5-2")
    if record.agent_pid <= 0:
        raise AuthorityError("invalid agent pid")
    if PureWindowsPath(record.agent_image_path).name.casefold() != EXPECTED_AGENT_BASENAME:
        raise AuthorityError("target image is not metatester64.exe")
    if not _is_under(record.agent_image_path, allowed_agent_roots):
        raise AuthorityError("agent image is outside allowed tester roots")
    if not record.ea_binary_ref.startswith("BIN-"):
        raise AuthorityError("missing immutable EA binary reference")
    if len(record.ea_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in record.ea_sha256):
        raise AuthorityError("invalid EA sha256")
    if len(record.nonce) < 16:
        raise AuthorityError("authority nonce too short")

    current = now or datetime.now(timezone.utc)
    try:
        expiry = datetime.fromisoformat(record.expires_at_utc.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityError("invalid authority expiry") from exc
    if expiry.tzinfo is None:
        raise AuthorityError("authority expiry must be timezone-aware")
    if current >= expiry:
        raise AuthorityError("authority expired")


def validate_live_binding(
    record: AuthorityRecord,
    *,
    observed_pid: int,
    observed_creation_time_100ns: int,
    observed_image_path: str,
) -> None:
    if observed_pid != record.agent_pid:
        raise AuthorityError("live pid no longer matches authority")
    if observed_creation_time_100ns != record.agent_creation_time_100ns:
        raise AuthorityError("process creation time mismatch (possible PID reuse)")
    if _norm_win(observed_image_path) != _norm_win(record.agent_image_path):
        raise AuthorityError("live image path no longer matches authority")
    if PureWindowsPath(observed_image_path).name.casefold() != EXPECTED_AGENT_BASENAME:
        raise AuthorityError("live process is not metatester64.exe")


class NonceStore:
    """Minimal one-use nonce guard. Production should persist this in the bridge job store."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def consume(self, nonce: str) -> None:
        if nonce in self._used:
            raise AuthorityError("authority nonce already used")
        self._used.add(nonce)
