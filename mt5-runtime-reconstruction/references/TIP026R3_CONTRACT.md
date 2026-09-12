# TIP-026R3 Runtime Forensics Contract

Status: implementation-ready proposal for TunnelVibeMQL5 fixed terminal `MT5-2`.

## Goals

Add runtime evidence capture for authorized EA reconstruction without exposing arbitrary process access or shell execution to the model.

## Non-goals

- no arbitrary `pid` input in MCP schema;
- no process-name search exposed to the model;
- no arbitrary address reads;
- no command/shell execution;
- no change to trading semantics;
- no change to fixed-terminal policy.

## `server_info` additions

```json
{
  "runtime_capture_schema": "1.0",
  "runtime_capture_transport": "job-bound/pss-minidump",
  "runtime_capture_profiles": ["private", "miniplus", "full"]
}
```

## Tool 1 — `capture_runtime_snapshot`

Input:

```json
{
  "job_id": "BT-...",
  "profile": "private",
  "label": "pre_signal"
}
```

`profile` enum: `private | miniplus | full`. `label` is optional, max 64 characters, restricted to `[A-Za-z0-9_.-]`.

The adapter MUST:

1. Load the durable job record.
2. Require job state `RUNNING` (or a tightly bounded terminal-state grace window when the process is still the exact recorded agent).
3. Resolve the agent PID internally; never accept caller-supplied PID.
4. Bind PID + process creation time + canonical image path + terminal id + job id + EA binary ref/hash.
5. Require basename exactly `metatester64.exe` and image path under the configured MT5-2 tester-agent root.
6. Generate a short-lived one-use authority nonce and signed authority record.
7. Invoke the fixed hash-pinned capture helper without a shell.
8. Revalidate the job/process binding after capture.
9. Hash all output artifacts and persist an immutable receipt.

Success result:

```json
{
  "capture_id": "RTC-YYYYMMDD-HHMMSS-XXXXXXXX",
  "job_id": "BT-...",
  "profile": "private",
  "label": "pre_signal",
  "status": "COMPLETED",
  "complete": true,
  "manifest_artifact": "runtime/<capture_id>/capture-manifest.json",
  "dump_artifact": "runtime/<capture_id>/runtime.dmp",
  "regions_artifact": "runtime/<capture_id>/regions.jsonl",
  "private_memory_artifact": "runtime/<capture_id>/private-regions.bin",
  "page_hashes_artifact": "runtime/<capture_id>/page-hashes.jsonl"
}
```

Required failure codes:

- `JOB_NOT_FOUND`
- `JOB_NOT_RUNNING`
- `AGENT_NOT_BOUND`
- `AGENT_IMAGE_MISMATCH`
- `AGENT_CREATION_TIME_MISMATCH`
- `PID_REUSE_DETECTED`
- `AUTHORITY_EXPIRED`
- `AUTHORITY_REPLAY`
- `CAPTURE_HELPER_MISMATCH`
- `CAPTURE_FAILED`
- `POST_CAPTURE_BINDING_MISMATCH`

## Tool 2 — `compare_runtime_snapshots`

Input:

```json
{
  "capture_a": "RTC-...",
  "capture_b": "RTC-...",
  "mode": "delta",
  "known_values": [5.0, 2.0, 150.0, 0.01]
}
```

`mode` enum:

- `delta`: same target at two runtime states;
- `target-control`: target EA vs minimal control EA on the same MT5 build/data window.

Output artifacts:

- `changed-pages.json`
- `target-specific-pages.json` when applicable
- `value-hits.json`
- `comparison-manifest.json`

The comparison service MUST operate on stored captures only; it never receives process identifiers.

## Capture receipt schema

Minimum fields:

```json
{
  "schema": "1.0",
  "capture_id": "RTC-...",
  "job_id": "BT-...",
  "job_state_at_start": "RUNNING",
  "terminal_id": "MT5-2",
  "ea_binary_ref": "BIN-...",
  "ea_sha256": "...",
  "agent_pid": 1234,
  "agent_creation_time_100ns": 0,
  "agent_image_path": "C:\\...\\metatester64.exe",
  "agent_image_sha256": "...",
  "profile": "private",
  "label": "pre_signal",
  "capture_started_at": "...Z",
  "capture_completed_at": "...Z",
  "capture_duration_ms": 0,
  "helper_version": "1.0.0",
  "helper_sha256": "...",
  "dump_sha256": "...",
  "dump_bytes": 0,
  "private_memory_sha256": "...",
  "private_memory_bytes": 0,
  "region_count_total": 0,
  "region_count_private": 0,
  "complete": true
}
```

PID is evidence only. It is never accepted as a model-controlled tool argument.

## Artifact/export integration

Extend existing evidence storage rather than adding a third file transport.

- `read_artifact(job/capture, name)` reads JSON/text evidence.
- `export_file(scope="runtime_capture", source_id=<capture_id>, name=<artifact>)` returns the normal ResourceLink with bytes/SHA256/complete metadata.

Raw dumps should not be inlined into MCP JSON.

## Capture implementation

Preferred sequence on Windows:

1. `OpenProcess` with the minimum required query/read/duplicate rights.
2. `GetProcessTimes` + `QueryFullProcessImageNameW` and authority verification.
3. `PssCaptureSnapshot` with `PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_VA_SPACE`.
4. `PssQuerySnapshot(PSS_QUERY_VA_CLONE_INFORMATION)` to obtain the VA clone handle.
5. Enumerate clone memory with `VirtualQueryEx`; persist committed `MEM_PRIVATE` readable/executable regions into a normalized sidecar.
6. Generate profile minidump from the clone using `MiniDumpWriteDump`.
7. Hash outputs; write manifest atomically.
8. `PssFreeSnapshot` and close all handles.

No PowerShell/rundll32/ProcDump command constructed from model input is permitted in production.

## Profile mapping

`private`:
- all committed `MEM_PRIVATE` readable regions in normalized sidecar (including executable private regions);
- compact minidump with private RW/WC memory, thread/process and VA metadata.

`miniplus`:
- `private` sidecar;
- compact minidump plus handles and code segments.

`full`:
- `private` sidecar;
- full accessible user-mode memory minidump with inaccessible pages ignored.

## Acceptance suite

Mandatory tests:

1. exact running job -> capture PASS;
2. non-existent job -> fail closed;
3. completed job without live bound agent -> fail closed;
4. stale/reused PID -> fail creation-time check;
5. wrong image basename/path -> fail closed;
6. wrong terminal id -> fail closed;
7. expired authority -> fail closed;
8. replayed nonce -> fail closed;
9. helper binary hash mismatch -> fail before capture;
10. capture does not terminate/stall tester beyond configured budget;
11. post-capture binding still matches;
12. artifact hashes reproduce exactly through `export_file`;
13. `compare_runtime_snapshots` is deterministic on identical inputs;
14. no MCP schema field exposes PID/address/command/shell.

## VibeCode MQL5 Full integration

Add a `RUNTIME_RECONSTRUCTION` phase after normal static/runtime audit when unresolved behavior is material:

`authority -> reference run -> capture matrix -> normalize -> target/control diff -> known-value correlation -> optional VM/code classification -> source reconstruction -> native compile -> exact differential tester -> acceptance evidence`.

This phase is opt-in and should be skipped when normal source/runtime evidence already answers the task.
