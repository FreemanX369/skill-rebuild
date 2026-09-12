#!/usr/bin/env python3
"""Reference integration shape for TunnelVibeMQL5 TIP-026R3.

This is intentionally framework-neutral. The production bridge should adapt its existing
job/artifact stores to these boundaries rather than copying storage code into this module.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import re
import secrets
from pathlib import PureWindowsPath
from typing import Any, Protocol

from authority import AuthorityError, AuthorityRecord, sign_record


PROFILES = {"private", "miniplus", "full"}
LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


@dataclass(frozen=True)
class CaptureRuntimeSnapshotRequest:
    job_id: str
    profile: str = "private"
    label: str | None = None


@dataclass(frozen=True)
class CompareRuntimeSnapshotsRequest:
    capture_a: str
    capture_b: str
    mode: str = "delta"
    known_values: tuple[float | int, ...] = ()


class JobStore(Protocol):
    def get(self, job_id: str) -> dict[str, Any] | None: ...


class ProcessResolver(Protocol):
    def resolve_agent_for_job(self, job_id: str) -> dict[str, Any] | None: ...


class HelperRunner(Protocol):
    def capture(self, *, authority: AuthorityRecord, profile: str, label: str | None) -> dict[str, Any]: ...


class ArtifactStore(Protocol):
    def persist_runtime_capture(self, job_id: str, helper_result: dict[str, Any]) -> dict[str, Any]: ...


class ComparisonEngine(Protocol):
    def compare(self, request: CompareRuntimeSnapshotsRequest) -> dict[str, Any]: ...


def validate_public_capture_request(req: CaptureRuntimeSnapshotRequest) -> None:
    if not req.job_id.startswith("BT-"):
        raise AuthorityError("JOB_NOT_FOUND")
    if req.profile not in PROFILES:
        raise AuthorityError("PROFILE_INVALID")
    if req.label is not None and not LABEL_RE.fullmatch(req.label):
        raise AuthorityError("LABEL_INVALID")


def assert_no_arbitrary_target_surface() -> None:
    public_fields = {f.name for f in fields(CaptureRuntimeSnapshotRequest)}
    forbidden = {"pid", "process_name", "address", "command", "shell", "executable"}
    exposed = public_fields & forbidden
    if exposed:
        raise AssertionError(f"forbidden public runtime-capture fields: {sorted(exposed)}")


def make_authority(job: dict[str, Any], live: dict[str, Any], signing_key: bytes) -> AuthorityRecord:
    if job.get("state") != "RUNNING":
        raise AuthorityError("JOB_NOT_RUNNING")
    if job.get("terminal_id") != "MT5-2":
        raise AuthorityError("AGENT_NOT_BOUND")
    if not job.get("ea_binary_ref") or not job.get("ea_sha256"):
        raise AuthorityError("AGENT_NOT_BOUND")

    if live.get("job_id") != job.get("job_id"):
        raise AuthorityError("AGENT_NOT_BOUND")
    if live.get("terminal_id") != job.get("terminal_id"):
        raise AuthorityError("AGENT_NOT_BOUND")
    image = str(live.get("image_path") or "")
    if PureWindowsPath(image).name.casefold() != "metatester64.exe":
        raise AuthorityError("AGENT_IMAGE_MISMATCH")

    durable_pid = job.get("agent_pid")
    durable_create = job.get("agent_creation_time_100ns")
    if durable_pid is not None and int(durable_pid) != int(live["pid"]):
        raise AuthorityError("PID_REUSE_DETECTED")
    if durable_create is not None and int(durable_create) != int(live["creation_time_100ns"]):
        raise AuthorityError("AGENT_CREATION_TIME_MISMATCH")

    expires = datetime.now(timezone.utc) + timedelta(seconds=90)
    record = AuthorityRecord(
        job_id=job["job_id"],
        terminal_id=job["terminal_id"],
        agent_pid=int(live["pid"]),
        agent_creation_time_100ns=int(live["creation_time_100ns"]),
        agent_image_path=image,
        ea_binary_ref=job["ea_binary_ref"],
        ea_sha256=job["ea_sha256"],
        nonce=secrets.token_hex(24),
        expires_at_utc=expires.isoformat(),
    )
    return sign_record(record, signing_key)


def capture_runtime_snapshot(
    req: CaptureRuntimeSnapshotRequest,
    *,
    jobs: JobStore,
    processes: ProcessResolver,
    helper: HelperRunner,
    artifacts: ArtifactStore,
    signing_key: bytes,
) -> dict[str, Any]:
    """Reference MCP handler. No caller-controlled process identifier reaches this API."""
    validate_public_capture_request(req)
    assert_no_arbitrary_target_surface()

    job = jobs.get(req.job_id)
    if job is None:
        raise AuthorityError("JOB_NOT_FOUND")
    if job.get("state") != "RUNNING":
        raise AuthorityError("JOB_NOT_RUNNING")

    live = processes.resolve_agent_for_job(req.job_id)
    if live is None:
        raise AuthorityError("AGENT_NOT_BOUND")

    authority = make_authority(job, live, signing_key)
    result = helper.capture(authority=authority, profile=req.profile, label=req.label)
    if result.get("status") != "COMPLETED" or result.get("complete") is not True:
        raise AuthorityError("CAPTURE_FAILED")

    receipt = artifacts.persist_runtime_capture(req.job_id, result)
    return {
        "capture_id": receipt["capture_id"],
        "job_id": req.job_id,
        "profile": req.profile,
        "label": req.label,
        "status": "COMPLETED",
        "complete": True,
        "manifest_artifact": receipt["manifest_artifact"],
        "dump_artifact": receipt["dump_artifact"],
        "regions_artifact": receipt["regions_artifact"],
        "private_memory_artifact": receipt["private_memory_artifact"],
        "page_hashes_artifact": receipt["page_hashes_artifact"],
    }


def compare_runtime_snapshots(
    req: CompareRuntimeSnapshotsRequest,
    *,
    engine: ComparisonEngine,
) -> dict[str, Any]:
    if not req.capture_a.startswith("RTC-") or not req.capture_b.startswith("RTC-"):
        raise AuthorityError("CAPTURE_NOT_FOUND")
    if req.mode not in {"delta", "target-control"}:
        raise AuthorityError("COMPARE_MODE_INVALID")
    return engine.compare(req)
