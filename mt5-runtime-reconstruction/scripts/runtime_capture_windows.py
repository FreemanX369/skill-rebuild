#!/usr/bin/env python3
"""TIP-026R3 Windows runtime capture prototype.

Security property: there is intentionally NO --pid, --process-name, --address or --command
argument. The only target authority is a short-lived HMAC-signed record emitted by the
trusted TunnelVibeMQL5 bridge for an exact running tester job.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from authority import (
    AuthorityError,
    AuthorityRecord,
    validate_live_binding,
    validate_static,
    verify_signature,
)


PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_INFORMATION = 0x0400
STILL_ACTIVE = 259

PSS_CAPTURE_VA_CLONE = 0x00000001
PSS_CAPTURE_THREADS = 0x00000080
PSS_CAPTURE_VA_SPACE = 0x00000800
PSS_QUERY_VA_CLONE_INFORMATION = 1

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

MINIDUMP_WITH_DATA_SEGS = 0x00000001
MINIDUMP_WITH_FULL_MEMORY = 0x00000002
MINIDUMP_WITH_HANDLE_DATA = 0x00000004
MINIDUMP_WITH_UNLOADED_MODULES = 0x00000020
MINIDUMP_WITH_PROCESS_THREAD_DATA = 0x00000100
MINIDUMP_WITH_PRIVATE_READ_WRITE_MEMORY = 0x00000200
MINIDUMP_WITH_FULL_MEMORY_INFO = 0x00000800
MINIDUMP_WITH_THREAD_INFO = 0x00001000
MINIDUMP_WITH_CODE_SEGS = 0x00002000
MINIDUMP_WITH_PRIVATE_WRITE_COPY_MEMORY = 0x00010000
MINIDUMP_IGNORE_INACCESSIBLE_MEMORY = 0x00020000

GENERIC_WRITE = 0x40000000
CREATE_ALWAYS = 2
FILE_ATTRIBUTE_NORMAL = 0x80
PAGE_SIZE = 4096


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class PSS_VA_CLONE_INFORMATION(ctypes.Structure):
    _fields_ = [("VaCloneHandle", wintypes.HANDLE)]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def configure_apis(kernel32, dbghelp) -> None:
    """Declare x64-safe WinAPI signatures; ctypes defaults would truncate HANDLE values."""
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessId.restype = wintypes.DWORD

    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL

    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL

    kernel32.PssCaptureSnapshot.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    kernel32.PssCaptureSnapshot.restype = wintypes.DWORD

    kernel32.PssQuerySnapshot.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.PssQuerySnapshot.restype = wintypes.DWORD

    kernel32.PssFreeSnapshot.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.PssFreeSnapshot.restype = wintypes.DWORD

    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE

    dbghelp.MiniDumpWriteDump.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def filetime_to_int(ft: FILETIME) -> int:
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)


def load_key() -> bytes:
    raw = os.environ.get("VIBEMQL5_RUNTIME_AUTH_KEY_HEX", "")
    if len(raw) < 64:
        raise AuthorityError("VIBEMQL5_RUNTIME_AUTH_KEY_HEX missing/too short")
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise AuthorityError("invalid runtime authority key encoding") from exc


def query_process_facts(kernel32, handle) -> tuple[str, int]:
    exit_code = wintypes.DWORD(0)
    if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
    if exit_code.value != STILL_ACTIVE:
        raise AuthorityError("bound testing agent is no longer running")

    buf = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(buf))
    if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        raise OSError(ctypes.get_last_error(), "QueryFullProcessImageNameW failed")

    creation = FILETIME()
    exit_ft = FILETIME()
    kernel_ft = FILETIME()
    user_ft = FILETIME()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_ft),
        ctypes.byref(kernel_ft),
        ctypes.byref(user_ft),
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")

    return buf.value, filetime_to_int(creation)


def open_bound_process(kernel32, pid: int):
    rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE
    handle = kernel32.OpenProcess(rights, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    try:
        image_path, creation_time = query_process_facts(kernel32, handle)
        return handle, image_path, creation_time
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def capture_snapshot(kernel32, process_handle):
    snapshot = ctypes.c_void_p()
    flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_VA_SPACE
    rc = kernel32.PssCaptureSnapshot(process_handle, flags, 0, ctypes.byref(snapshot))
    if rc != 0:
        raise OSError(rc, "PssCaptureSnapshot failed")

    clone_info = PSS_VA_CLONE_INFORMATION()
    rc = kernel32.PssQuerySnapshot(
        snapshot,
        PSS_QUERY_VA_CLONE_INFORMATION,
        ctypes.byref(clone_info),
        ctypes.sizeof(clone_info),
    )
    if rc != 0 or not clone_info.VaCloneHandle:
        kernel32.PssFreeSnapshot(kernel32.GetCurrentProcess(), snapshot)
        raise OSError(rc, "PssQuerySnapshot(VA_CLONE) failed")
    return snapshot, clone_info.VaCloneHandle


def is_readable_private(mbi: MEMORY_BASIC_INFORMATION) -> bool:
    if mbi.State != MEM_COMMIT or mbi.Type != MEM_PRIVATE:
        return False
    if mbi.Protect & PAGE_GUARD:
        return False
    if mbi.Protect & PAGE_NOACCESS:
        return False
    return True


def dump_private_pages(kernel32, clone_handle, out_dir: Path) -> tuple[int, int]:
    mem_path = out_dir / "private-regions.bin"
    pages_path = out_dir / "page-hashes.jsonl"
    regions_path = out_dir / "regions.jsonl"

    address = 0
    max_address = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
    sidecar_offset = 0
    region_count = 0
    page_count = 0

    with mem_path.open("wb") as mem_out, pages_path.open("w", encoding="utf-8") as page_out, regions_path.open(
        "w", encoding="utf-8"
    ) as region_out:
        mbi = MEMORY_BASIC_INFORMATION()
        while address < max_address:
            got = kernel32.VirtualQueryEx(
                clone_handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not got:
                break

            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize)
            if size <= 0:
                break

            if is_readable_private(mbi):
                region_count += 1
                region_out.write(
                    json.dumps(
                        {
                            "base_address": hex(base),
                            "size": size,
                            "protect": int(mbi.Protect),
                            "type": int(mbi.Type),
                            "state": int(mbi.State),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )

                end = base + size
                page = base
                while page < end:
                    want = min(PAGE_SIZE, end - page)
                    buf = ctypes.create_string_buffer(want)
                    read = ctypes.c_size_t(0)
                    ok = kernel32.ReadProcessMemory(
                        clone_handle,
                        ctypes.c_void_p(page),
                        buf,
                        want,
                        ctypes.byref(read),
                    )
                    if ok and read.value > 0:
                        data = buf.raw[: read.value]
                        mem_out.write(data)
                        digest = hashlib.sha256(data).hexdigest()
                        page_out.write(
                            json.dumps(
                                {
                                    "address": hex(page),
                                    "size": len(data),
                                    "sha256": digest,
                                    "type": "MEM_PRIVATE",
                                    "protect": int(mbi.Protect),
                                    "sidecar_offset": sidecar_offset,
                                },
                                sort_keys=True,
                            )
                            + "\n"
                        )
                        sidecar_offset += len(data)
                        page_count += 1
                    page += PAGE_SIZE

            next_address = base + size
            if next_address <= address:
                break
            address = next_address

    return region_count, page_count


def minidump_flags(profile: str) -> int:
    private = (
        MINIDUMP_WITH_DATA_SEGS
        | MINIDUMP_WITH_UNLOADED_MODULES
        | MINIDUMP_WITH_PROCESS_THREAD_DATA
        | MINIDUMP_WITH_PRIVATE_READ_WRITE_MEMORY
        | MINIDUMP_WITH_FULL_MEMORY_INFO
        | MINIDUMP_WITH_THREAD_INFO
        | MINIDUMP_WITH_PRIVATE_WRITE_COPY_MEMORY
        | MINIDUMP_IGNORE_INACCESSIBLE_MEMORY
    )
    if profile == "private":
        return private
    if profile == "miniplus":
        return private | MINIDUMP_WITH_HANDLE_DATA | MINIDUMP_WITH_CODE_SEGS
    if profile == "full":
        return private | MINIDUMP_WITH_FULL_MEMORY | MINIDUMP_WITH_HANDLE_DATA | MINIDUMP_WITH_CODE_SEGS
    raise ValueError(f"unsupported profile: {profile}")


def write_minidump(kernel32, dbghelp, clone_handle, profile: str, path: Path) -> None:
    invalid_handle = ctypes.c_void_p(-1).value
    hfile = kernel32.CreateFileW(
        str(path),
        GENERIC_WRITE,
        0,
        None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if hfile == invalid_handle:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    try:
        clone_pid = kernel32.GetProcessId(clone_handle)
        if not clone_pid:
            raise OSError(ctypes.get_last_error(), "GetProcessId(VA clone) failed")
        ok = dbghelp.MiniDumpWriteDump(
            clone_handle,
            clone_pid,
            hfile,
            minidump_flags(profile),
            None,
            None,
            None,
        )
        if not ok:
            raise OSError(ctypes.get_last_error(), "MiniDumpWriteDump failed")
    finally:
        kernel32.CloseHandle(hfile)


def consume_nonce(out_root: Path, nonce: str) -> None:
    ledger = out_root / ".runtime-capture-nonces"
    ledger.mkdir(parents=True, exist_ok=True)
    marker = ledger / hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    try:
        fd = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise AuthorityError("authority nonce already used") from exc
    else:
        os.close(fd)


def main() -> int:
    if os.name != "nt":
        print("runtime_capture_windows.py requires Windows", file=sys.stderr)
        return 2

    ap = argparse.ArgumentParser()
    ap.add_argument("--authority", type=Path, required=True)
    ap.add_argument("--out-root", type=Path, required=True)
    ap.add_argument("--profile", choices=("private", "miniplus", "full"), default="private")
    ap.add_argument("--allowed-agent-root", action="append", required=True)
    args = ap.parse_args()

    record = AuthorityRecord.from_dict(json.loads(args.authority.read_text(encoding="utf-8")))
    key = load_key()
    verify_signature(record, key)
    validate_static(record, args.allowed_agent_root)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("Dbghelp", use_last_error=True)
    configure_apis(kernel32, dbghelp)

    process_handle = None
    snapshot = None
    started = time.perf_counter()
    started_at = datetime.now(timezone.utc)

    try:
        process_handle, image_path, creation_time = open_bound_process(kernel32, record.agent_pid)
        validate_live_binding(
            record,
            observed_pid=record.agent_pid,
            observed_creation_time_100ns=creation_time,
            observed_image_path=image_path,
        )
        consume_nonce(args.out_root, record.nonce)

        snapshot, clone_handle = capture_snapshot(kernel32, process_handle)

        capture_id = "RTC-" + started_at.strftime("%Y%m%d-%H%M%S-") + record.nonce[:8].upper()
        out_dir = args.out_root / capture_id
        out_dir.mkdir(parents=True, exist_ok=False)

        region_count, page_count = dump_private_pages(kernel32, clone_handle, out_dir)
        dump_path = out_dir / "runtime.dmp"
        write_minidump(kernel32, dbghelp, clone_handle, args.profile, dump_path)

        # Post-capture revalidation uses the original bound handle; no new PID lookup/open occurs.
        image_after, creation_after = query_process_facts(kernel32, process_handle)
        validate_live_binding(
            record,
            observed_pid=record.agent_pid,
            observed_creation_time_100ns=creation_after,
            observed_image_path=image_after,
        )

        helper_path = Path(__file__).resolve()
        private_path = out_dir / "private-regions.bin"
        completed_at = datetime.now(timezone.utc)
        manifest = {
            "schema": "1.0",
            "capture_id": capture_id,
            "job_id": record.job_id,
            "terminal_id": record.terminal_id,
            "ea_binary_ref": record.ea_binary_ref,
            "ea_sha256": record.ea_sha256.lower(),
            "agent_pid": record.agent_pid,
            "agent_creation_time_100ns": record.agent_creation_time_100ns,
            "agent_image_path": image_path,
            "agent_image_sha256": sha256_file(Path(image_path)),
            "profile": args.profile,
            "capture_started_at": started_at.isoformat().replace("+00:00", "Z"),
            "capture_completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "capture_duration_ms": int((time.perf_counter() - started) * 1000),
            "helper_version": "1.0.1-prototype",
            "helper_sha256": sha256_file(helper_path),
            "dump_sha256": sha256_file(dump_path),
            "dump_bytes": dump_path.stat().st_size,
            "private_memory_sha256": sha256_file(private_path),
            "private_memory_bytes": private_path.stat().st_size,
            "region_count_private": region_count,
            "private_page_count": page_count,
            "complete": True,
        }
        (out_dir / "capture-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(json.dumps({"status": "COMPLETED", **manifest}, sort_keys=True))
        return 0
    except (AuthorityError, OSError, ValueError) as exc:
        print(json.dumps({"status": "FAILED", "error": str(exc)}), file=sys.stderr)
        return 1
    finally:
        if snapshot:
            kernel32.PssFreeSnapshot(kernel32.GetCurrentProcess(), snapshot)
        if process_handle:
            kernel32.CloseHandle(process_handle)


if __name__ == "__main__":
    raise SystemExit(main())
