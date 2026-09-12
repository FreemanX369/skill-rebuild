# VibeCode MQL5 Full — Runtime Reconstruction Extension

This extension is used only when normal source/static/runtime analysis leaves a material algorithmic gap (for example an unknown EX5 signal core). It must not replace cheaper evidence paths when source is already available.

## Entry criteria

Enter `RUNTIME_RECONSTRUCTION` only when all are true:

1. exact artifact identity is known (`sha256`, bytes, immutable binary ref when available);
2. the EX5 runs successfully in the fixed Strategy Tester terminal;
3. unresolved behavior changes the reconstruction materially;
4. ordinary logs/events/input perturbation cannot determine it with sufficient confidence.

## Full flow

### R0 — Authority freeze

Record:

- repository/source checkpoint if any;
- original EX5 SHA256/bytes;
- `ea_binary_ref` and import receipt;
- Tunnel version/build/catalog hash;
- terminal id/build;
- symbol, timeframe, tick model, delay, deposit, leverage;
- complete EA input set;
- historical-data coverage.

No reconstruction result is accepted if these authorities drift unnoticed.

### R1 — Reference behavior extraction

Run the original EX5 and build an event ledger containing at least:

- decision-bar timestamp;
- signal/entry side;
- P1 price/lot;
- each recovery entry price/lot;
- SL/TP changes;
- position/deal ticket mapping;
- basket close reason and realized result.

Prefer a short window with multiple representative episodes before a full-range run.

### R2 — Control EA

Use a minimal EA that loads the same symbol/timeframe history and does no strategy work. Run it with the same terminal build and data window. This provides platform/runtime noise for later subtraction.

### R3 — Capture matrix

For target and control, capture job-bound runtime snapshots at reproducible boundaries:

- `loaded`
- `pre_signal`
- `post_signal`
- `post_entry`
- `post_recovery`

Default `profile=private`. Escalate only when needed.

### R4 — Normalize

For every capture:

- hash each captured private page;
- record base address, size, protection and memory type;
- extract UTF-8/UTF-16 strings separately;
- scan for known numeric values in little-endian `double`, `float`, signed/unsigned integers;
- keep artifact hashes and manifest provenance.

ASLR means raw addresses are not stable across independent processes. Prefer page content signatures, relative offsets within discovered structures, and target-vs-control classification over absolute addresses.

### R5 — Delta classification

Perform two comparisons:

1. **temporal delta** — same EA, adjacent behavioral states;
2. **target/control delta** — target EA vs minimal control.

Prioritize pages that are both target-specific and synchronized with signal-state transitions.

### R6 — Parameter perturbation

Run one-variable-at-a-time experiments when the input can be changed legally through tester configuration/set files. Examples:

- distance 5.0 -> 7.0;
- TP 2.0 -> 3.0;
- emergency SL 150 -> 120;
- base lot 0.01 -> 0.02;
- direction enum changes.

Correlate changed runtime bytes/pages with the known changed value. Do not fit multiple unknowns at once.

### R7 — Signal hypothesis

Form the smallest model that explains the observed BUY/SELL/NONE sequence. Example hypothesis families:

- moving-average ordering/crossover;
- oscillator threshold/state machine;
- volatility-normalized trend/reversal;
- candle/price structure;
- hybrid state machine.

Do not introduce parameters unsupported by evidence merely to improve P/L similarity.

### R8 — Optional executable/VM analysis

Only when runtime evidence contains a stable target-specific executable/private region:

1. classify native code vs dispatcher/VM behavior;
2. map call/branch/data references around state pages;
3. route VM-like regions to `vm-and-bytecode-reverse`;
4. recover only semantics needed to settle the unresolved hypothesis.

This step is optional, not the default.

### R9 — Source reconstruction

Replace only the unresolved module in the reconstructed EA. Preserve evidence-locked modules unchanged.

Mark every module/function as one of:

- `EVIDENCE_LOCKED`
- `INFERRED_HIGH`
- `INFERRED_LOW`
- `UNRESOLVED`

### R10 — Native compile gate

MetaEditor must report:

- EX5 emitted;
- 0 errors;
- 0 warnings;
- source SHA and EX5 SHA recorded.

### R11 — Differential tester acceptance

Original EX5 and reconstruction must run on identical tester authorities. Compare episode/event streams.

Primary metrics:

- signal timestamp match rate;
- direction match rate;
- P1 entry tolerance;
- recovery level/time match;
- lot sequence equality;
- TP/SL target tolerance;
- basket-close reason match.

P/L similarity is secondary and cannot replace event parity.

### R12 — Holdout verification

Use date windows that were not used to infer the algorithm. A signal model is not promoted to `EVIDENCE_LOCKED` merely because it fits the discovery window.

## WSLOW completion target

For the current WSLOW reconstruction, basket/recovery/protection behavior is already separated from `SignalCore()`. Runtime reconstruction should therefore focus on matching the original signal sequence and must not rewrite the known basket math unless new evidence contradicts it.

## Stop conditions

Stop/escalate rather than overfit when:

- target/control captures show no useful target-specific state;
- the tester job cannot remain bound through capture;
- historical data differ between runs;
- exact signal parity cannot generalize to holdout windows;
- an assumption requires changing multiple unrelated modules.

The correct result may remain a behavioral reconstruction with a clearly marked unresolved signal implementation.
