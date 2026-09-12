from __future__ import annotations

from dataclasses import fields
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from authority import AuthorityError  # noqa: E402
from tunnel_adapter_reference import (  # noqa: E402
    CaptureRuntimeSnapshotRequest,
    CompareRuntimeSnapshotsRequest,
    assert_no_arbitrary_target_surface,
    capture_runtime_snapshot,
    make_authority,
)


class Jobs:
    def __init__(self, state="RUNNING"):
        self.job = {
            "job_id": "BT-20260912-TEST-0001",
            "state": state,
            "terminal_id": "MT5-2",
            "ea_binary_ref": "BIN-" + "a" * 64,
            "ea_sha256": "b" * 64,
            "agent_pid": 4242,
            "agent_creation_time_100ns": 777,
        }

    def get(self, job_id):
        return self.job if job_id == self.job["job_id"] else None


class Processes:
    def __init__(self, image=r"C:\VibeMQL5\MT5-2\Tester\Agent\metatester64.exe"):
        self.live = {
            "job_id": "BT-20260912-TEST-0001",
            "terminal_id": "MT5-2",
            "pid": 4242,
            "creation_time_100ns": 777,
            "image_path": image,
        }

    def resolve_agent_for_job(self, job_id):
        return self.live if job_id == self.live["job_id"] else None


class Helper:
    def capture(self, *, authority, profile, label):
        return {
            "status": "COMPLETED",
            "complete": True,
            "capture_id": "RTC-20260912-TEST0001",
            "profile": profile,
            "label": label,
        }


class Artifacts:
    def persist_runtime_capture(self, job_id, helper_result):
        cid = helper_result["capture_id"]
        base = f"runtime/{cid}"
        return {
            "capture_id": cid,
            "manifest_artifact": f"{base}/capture-manifest.json",
            "dump_artifact": f"{base}/runtime.dmp",
            "regions_artifact": f"{base}/regions.jsonl",
            "private_memory_artifact": f"{base}/private-regions.bin",
            "page_hashes_artifact": f"{base}/page-hashes.jsonl",
        }


def test_public_capture_schema_has_no_pid_or_shell_surface():
    assert_no_arbitrary_target_surface()
    names = {f.name for f in fields(CaptureRuntimeSnapshotRequest)}
    assert names == {"job_id", "profile", "label"}
    compare_names = {f.name for f in fields(CompareRuntimeSnapshotsRequest)}
    assert compare_names == {"capture_a", "capture_b", "mode", "known_values"}


def test_capture_handler_resolves_process_internally():
    result = capture_runtime_snapshot(
        CaptureRuntimeSnapshotRequest("BT-20260912-TEST-0001", "private", "pre_signal"),
        jobs=Jobs(),
        processes=Processes(),
        helper=Helper(),
        artifacts=Artifacts(),
        signing_key=b"k" * 32,
    )
    assert result["status"] == "COMPLETED"
    assert result["complete"] is True
    assert result["capture_id"].startswith("RTC-")


def test_non_running_job_fails_before_process_capture():
    with pytest.raises(AuthorityError, match="JOB_NOT_RUNNING"):
        capture_runtime_snapshot(
            CaptureRuntimeSnapshotRequest("BT-20260912-TEST-0001"),
            jobs=Jobs(state="COMPLETED"),
            processes=Processes(),
            helper=Helper(),
            artifacts=Artifacts(),
            signing_key=b"k" * 32,
        )


def test_wrong_agent_image_fails_closed():
    job = Jobs().job
    live = Processes(image=r"C:\Windows\System32\notepad.exe").live
    with pytest.raises(AuthorityError, match="AGENT_IMAGE_MISMATCH"):
        make_authority(job, live, b"k" * 32)


def test_pid_reuse_fails_before_authority_is_issued():
    job = Jobs().job
    live = Processes().live.copy()
    live["creation_time_100ns"] = 778
    with pytest.raises(AuthorityError, match="AGENT_CREATION_TIME_MISMATCH"):
        make_authority(job, live, b"k" * 32)
