# TIP-026R3 — Run on Windows VPS / TunnelVibeMQL5

Authority checkpoint for this package:

- Branch: `feat/tip026r3-mt5-runtime-forensics`
- Base implementation HEAD before this guide: `fd27855c834022ac3e16f89df2ad50c36faacc42`
- Fixed tester terminal: `MT5-2`
- Target bridge proposal: `0.2.32 / TIP-026R3 / result_schema=1.4`
- Runtime-capture schema: `1.0`

This package is the implementation-ready runtime-forensics extension. It does **not** by itself replace the production TunnelVibeMQL5 backend. The production bridge must wire the provided reference adapter into its existing job/process/artifact stores.

## 1. Stage the package

Open **PowerShell as Administrator** on the Windows VPS and extract the ZIP, for example:

```powershell
New-Item -ItemType Directory -Force C:\VibeMQL5\tip026r3 | Out-Null
Expand-Archive -Force .\TIP026R3-MT5-Runtime-Forensics.zip C:\VibeMQL5\tip026r3
Set-Location C:\VibeMQL5\tip026r3
```

If the ZIP expands into a wrapper directory, change into the directory that contains `mt5-runtime-reconstruction`.

## 2. Static qualification before touching the live bridge

Use Python 3.10+.

```powershell
python --version
python -m pip install --disable-pip-version-check pytest
python -m py_compile .\mt5-runtime-reconstruction\scripts\authority.py
python -m py_compile .\mt5-runtime-reconstruction\scripts\compare_snapshots.py
python -m py_compile .\mt5-runtime-reconstruction\scripts\scan_known_values.py
python -m py_compile .\mt5-runtime-reconstruction\scripts\runtime_capture_windows.py
python -m py_compile .\mt5-runtime-reconstruction\scripts\tunnel_adapter_reference.py
pytest -q .\mt5-runtime-reconstruction\tests
```

Expected: all tests PASS and all Python modules compile.

Verify that the capture helper does not expose arbitrary targeting:

```powershell
python .\mt5-runtime-reconstruction\scripts\runtime_capture_windows.py --help
```

The public CLI must expose only:

- `--authority`
- `--out-root`
- `--profile`
- `--allowed-agent-root`

It must not expose `--pid`, `--process-name`, `--address`, `--command` or shell execution.

## 3. Create the bridge-only signing key

Generate a 32-byte random key once and store it in the Tunnel service environment/secret store. Do not send this key through ChatGPT/MCP.

PowerShell compatible form:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
[Environment]::SetEnvironmentVariable('VIBEMQL5_RUNTIME_AUTH_KEY_HEX', $hex, 'Machine')
```

Restart only the Tunnel service/process that owns the environment after integrating the backend. Do not restart MT5-2 while a tester acceptance job is running.

## 4. Integrate into the Tunnel backend

Use these files as the reference implementation/contract:

```text
mt5-runtime-reconstruction/scripts/tunnel_adapter_reference.py
mt5-runtime-reconstruction/scripts/authority.py
mt5-runtime-reconstruction/scripts/runtime_capture_windows.py
mt5-runtime-reconstruction/scripts/compare_snapshots.py
mt5-runtime-reconstruction/scripts/scan_known_values.py
mt5-runtime-reconstruction/references/tip026r3-tool-schemas.json
mt5-runtime-reconstruction/references/TIP026R3_CONTRACT.md
```

Wire the reference protocols to the existing Tunnel subsystems:

```text
JobStore            -> existing durable Strategy Tester job store
ProcessResolver     -> existing internal job -> metatester64.exe binding
HelperRunner        -> fixed Python/native helper invocation, shell=False
ArtifactStore       -> existing immutable evidence/artifact store
ComparisonEngine    -> stored-capture comparison only
```

### Required public MCP tools

Register exactly:

```text
capture_runtime_snapshot(job_id, profile, label?)
compare_runtime_snapshots(capture_a, capture_b, mode, known_values?)
```

Do not add public PID/process/address/command fields.

### Required job record fields

At tester launch/bind time persist at least:

```text
job_id
state
terminal_id = MT5-2
ea_binary_ref
ea_sha256
agent_pid
agent_creation_time_100ns
agent_image_path
```

`agent_pid` is internal evidence only. It must never be accepted from MCP/model input.

### Helper invocation

The bridge should write a short-lived signed authority JSON and invoke the helper using a fixed argument array with `shell=False` equivalent:

```text
python runtime_capture_windows.py
  --authority <bridge-created-authority.json>
  --out-root <immutable-runtime-evidence-root>
  --profile private
  --allowed-agent-root <configured-MT5-2-tester-agent-root>
```

The authority must be HMAC-SHA256 signed, expire quickly (reference adapter uses 90 s) and use a one-use nonce.

## 5. Expected server_info after deploy

After the production backend is wired and restarted, `server_info` should report the production team's final catalog hash plus at least:

```text
version = 0.2.32
bridge_build = TIP-026R3
result_schema = 1.4
server_tool_count = 48
model_visible_tool_count = 47
runtime_capture_schema = 1.0
runtime_capture_transport = job-bound/pss-minidump
runtime_capture_profiles = private,miniplus,full
```

If the production catalog already changed after TIP-026R2, preserve the real counts and regenerate the catalog SHA rather than forcing the proposal counts above.

## 6. Live E2E on the existing MT5-2 tester

Use the existing imported WSLOW binary authority when still valid:

```text
EA SHA256 = 68e5f04634fa211cadabd6cab73f23a9727daf1f3805bfc598071a76c880684a
EA binary ref = BIN-180ba96604dd66991ebdce2ebe665b39ca68e34de9a3a69180b0cd39a4af146b
```

Launch a short deterministic tester run first, using the same authority family already used in prior acceptance:

```text
terminal = MT5-2
symbol = XAUUSDm
period = M1
model = 4 (Every Tick Based on Real Ticks)
delay = 150 ms
deposit = 10000
leverage = 1:1000
visual = false
```

Choose a short interval that contains a known P1/recovery episode. Keep the job in `RUNNING` long enough to capture.

Then call, from ChatGPT/Tunnel:

```text
capture_runtime_snapshot
  job_id=<BT-...>
  profile=private
  label=loaded
```

Repeat at reproducible boundaries when the test harness/bridge can coordinate them:

```text
pre_signal
post_signal
post_entry
post_recovery
```

Every successful capture must return an immutable `RTC-...` id and evidence paths for:

```text
capture-manifest.json
runtime.dmp
regions.jsonl
private-regions.bin
page-hashes.jsonl
```

The tester must remain alive unless it naturally completes.

## 7. Delta and target/control analysis

Temporal comparison:

```text
compare_runtime_snapshots
  capture_a=<RTC-pre_signal>
  capture_b=<RTC-post_signal>
  mode=delta
  known_values=[5.0,2.0,150.0,0.01,1231213]
```

Target/control comparison:

1. Run a minimal no-strategy control EA on the same terminal/build/tick window.
2. Capture the same runtime phase.
3. Compare:

```text
compare_runtime_snapshots
  capture_a=<RTC-target>
  capture_b=<RTC-control>
  mode=target-control
  known_values=[5.0,2.0,150.0,0.01,1231213]
```

Prioritize pages that are both target-specific and change across `pre_signal -> post_signal`.

## 8. Offline analysis commands

If captures are exported to disk, page-hash diff can also be run directly:

```powershell
python .\mt5-runtime-reconstruction\scripts\compare_snapshots.py `
  C:\path\pre_signal\page-hashes.jsonl `
  C:\path\post_signal\page-hashes.jsonl `
  --mode delta `
  --out C:\path\analysis\changed-pages.json
```

Known-value correlation uses `private-regions.bin` plus `page-hashes.jsonl`; inspect the script help on the packaged version before invoking:

```powershell
python .\mt5-runtime-reconstruction\scripts\scan_known_values.py --help
```

Use values already evidenced in the EA first: `5.0`, `2.0`, `150.0`, `0.01`, magic `1231213`, then one-variable-at-a-time tester perturbations.

## 9. WSLOW reconstruction loop

Do not rewrite basket/recovery/protection modules unless new runtime evidence contradicts them. The unresolved target is `SignalCore()`.

Use this loop:

```text
original WSLOW run
 -> capture matrix
 -> target/control subtraction
 -> temporal page delta
 -> known-value/state correlation
 -> signal hypothesis
 -> replace SignalCore() only
 -> native compile 0 errors / 0 warnings
 -> exact same real-tick tester
 -> compare entry/event ledger
 -> holdout window
```

Primary acceptance metrics are event parity, not only P/L:

```text
signal timestamp match
direction match
P1 entry tolerance
recovery time/level match
lot sequence equality
TP/SL target tolerance
basket-close reason match
```

## 10. Fail-closed acceptance gates

Before calling TIP-026R3 accepted, verify all of these:

```text
wrong/nonexistent job -> FAIL
completed job without live bound agent -> FAIL
wrong terminal -> FAIL
wrong image path/name -> FAIL
PID reuse/creation-time mismatch -> FAIL
expired authority -> FAIL
replayed nonce -> FAIL
helper hash mismatch -> FAIL
public MCP PID/address/command/shell fields -> NONE
capture exact RUNNING job -> PASS
post-capture tester alive -> PASS
artifact SHA/bytes reproduce through export -> PASS
same captures compare deterministically -> PASS
```

## 11. ChatGPT acceptance prompt after deploy

Use this in a new chat after the production Tunnel server exposes TIP-026R3:

```text
@TunnelVibeMQL5 @Vibecode MQL5 Full

Run TIP-026R3 runtime-reconstruction acceptance on fixed terminal MT5-2.

1. server_info; require TIP-026R3/runtime_capture_schema=1.0.
2. Launch the existing WSLOW EX5 binary ref on XAUUSDm, Every Tick Based on Real Ticks, delay 150 ms, deposit 10000, leverage 1:1000.
3. While the job is RUNNING, capture profile=private with labels loaded/pre_signal/post_signal/post_entry where reproducible.
4. Verify every capture is job-bound and tester survives.
5. Export manifest/page-hashes/private-memory evidence by ResourceLink and verify SHA/bytes.
6. Run temporal delta and target/control comparison with known values 5.0, 2.0, 150.0, 0.01, 1231213.
7. Use runtime evidence only to refine SignalCore(); leave evidence-locked basket/recovery/protection logic unchanged.
8. Compile reconstructed MQ5 natively and differential-test it against original WSLOW on identical ticks.
9. Report event-parity metrics and unresolved assumptions. Do not merge/deploy trading changes automatically.
```
