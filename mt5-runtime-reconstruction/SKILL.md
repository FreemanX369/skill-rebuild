---
name: mt5-runtime-reconstruction
description: "Job-bound runtime capture and differential reconstruction for authorized MetaTrader 5 Strategy Tester EA analysis. Designed for TunnelVibeMQL5 TIP-026R3; never accepts arbitrary shell or free-form target processes."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# MT5 Runtime Reconstruction

Use this skill when an authorized MQL5 EX5 artifact cannot be understood sufficiently by static inspection and exact behavior must be reconstructed from Strategy Tester runtime evidence.

## Design invariant

Runtime capture is **job-bound**. The model/user supplies a `job_id`, never an arbitrary PID, process name, address, command, or shell fragment. The trusted bridge resolves the process and emits a short-lived authority record. Capture must fail closed if any binding no longer matches.

Required binding:

- `job_id`
- fixed terminal id (`MT5-2` for TIP-026)
- `agent_pid` resolved internally
- `agent_creation_time_100ns`
- canonical `agent_image_path`
- expected process basename `metatester64.exe`
- `ea_binary_ref` and EA SHA256
- expiry/nonce

## Workflow

### Phase A — Reference authority

1. Verify exact EX5 hash / `ea_binary_ref`.
2. Launch or select the exact Strategy Tester job.
3. Confirm job is `RUNNING`.
4. Resolve its testing-agent process internally.
5. Generate a one-use authority record.

### Phase B — Capture matrix

Capture at meaningful behavioral boundaries:

- `loaded`
- `pre_signal`
- `post_signal`
- `post_entry`
- `post_recovery`

Default profile is `private`; escalate to `miniplus` then `full` only when evidence is insufficient.

### Phase C — Normalize and compare

Produce:

- `capture-manifest.json`
- `regions.jsonl`
- `page-hashes.jsonl`
- `strings.txt`
- `value-hits.json`
- `changed-pages.json`
- `target-specific-pages.json`

Compare target EX5 captures with a minimal control EA on the same terminal/build/data window. Prioritize `MEM_PRIVATE` regions and state changes synchronized with decision events.

### Phase D — Reconstruct only the missing semantics

Do not attempt to recover the entire EA when most behavior is already evidenced. For WSLOW-style work, isolate the unknown signal function and keep already-proven basket/recovery/execution logic unchanged.

Only route candidate executable/VM regions to `vm-and-bytecode-reverse` after runtime evidence shows a stable dispatcher or private executable blob.

### Phase E — Differential acceptance

Compile the reconstructed MQ5 and run it against the original EX5 using the same:

- terminal build
- symbol/timeframe
- real-tick source
- date window
- inputs
- deposit/leverage/delay

Compare event streams (signal timestamps, side, entry price tolerance, recovery levels, lot sequence, TP/SL modifications), not only final P/L.

## TIP-026R3 tool contract

Preferred MCP additions:

- `capture_runtime_snapshot(job_id, profile, label?)`
- `compare_runtime_snapshots(capture_a, capture_b, known_values?)`

Existing `read_artifact` and `export_file` should expose the resulting evidence. See `references/TIP026R3_CONTRACT.md`.

## Profiles

- `private`: committed private readable/executable regions + modules/threads/VA metadata. Default for reconstruction.
- `miniplus`: compact minidump containing private memory plus thread/module/full-memory metadata.
- `full`: full user-mode process dump. Escalation only.

## Acceptance rules

A capture is valid only when:

- job is still the same running job;
- PID creation time matches authority;
- image basename is exactly `metatester64.exe`;
- canonical image path is under the fixed terminal/agent root;
- authority nonce is unused and unexpired;
- dump/capture hashes and helper provenance are recorded;
- tester remains alive unless the job naturally finishes;
- no arbitrary shell/PID surface is exposed to the model.

## Output

The reconstruction report must distinguish:

- **evidence-locked behavior**
- **inferred behavior**
- **unresolved behavior**
- **runtime-memory findings**
- **differential acceptance status**

Never claim verbatim original MQ5 source recovery unless independently verified.
