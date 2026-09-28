# SIH 26145 --- NTRO Cyber Threat Detection

## Project Baseline / Persistent Chat Instructions

**Purpose:** This file is the persistent baseline for every ChatGPT
conversation concerning this project.\
**Rule:** A new chat must treat this document as the starting context
and must NOT require the user to re-explain the project, architecture,
completed work, review history, constraints, or development order.

------------------------------------------------------------------------

# 1. PROJECT IDENTITY

-   **Hackathon:** Smart India Hackathon (SIH) 2026
-   **Problem Statement:** SIH 26145
-   **Problem Title:** AI-Based Detection of Cyber Threats in
    Unidirectional IP Traffic
-   **Sponsor / Organization:** National Technical Research Organisation
    (NTRO)
-   **Project type:** Passive cyber-threat detection and analysis
    platform
-   **Primary development environment:** Windows
-   **Primary coding agent / IDE:** Google Antigravity
-   **Repository:** `https://github.com/Adeen16/SIHREPO`
-   **Default branch:** `main`
-   **Current Python version:** Python 3.14.0
-   **Virtual environment:** `.venv`
-   **Current project status:** Phases 3--6 have been implemented.
    Phases 4--6 have undergone an audit/correction cycle. The corrected
    local changes must be reviewed from the actual diff before being
    approved and committed.

------------------------------------------------------------------------

# 2. CORE PROJECT OBJECTIVE

The system is intended to detect and analyse cyber threats present in
**one-directional IP traffic** received through a passive monitoring
path / traffic mirror / data-diode-like architecture.

The system must:

1.  passively ingest packet captures or equivalent traffic records;
2.  construct packet events;
3.  construct network flows;
4.  process traffic in sliding time windows;
5.  extract meaningful traffic and behavioural features;
6.  use AI/ML to detect and classify threats;
7.  calculate confidence;
8.  assign severity;
9.  provide supporting evidence for each detection;
10. expose results through an API/streaming layer;
11. provide a visual dashboard;
12. demonstrate measurable real-time/near-real-time processing
    performance.

The final prototype must be technically defensible, not merely visually
impressive.

------------------------------------------------------------------------

# 3. NON-NEGOTIABLE NTRO / PASSIVE MONITORING CONSTRAINTS

The system is a **passive detector**.

It MUST NOT:

-   send packets to observed sources or destinations;
-   initiate TCP handshakes;
-   perform active scanning;
-   send probes;
-   replay captured packets onto a network;
-   inject packets into the monitored path;
-   perform mitigation actions;
-   block traffic;
-   modify routing;
-   contact suspicious IPs/domains for verification;
-   perform DNS lookups against observed domains as an active
    verification step;
-   perform reverse connections;
-   execute malware samples;
-   decrypt TLS/QUIC traffic merely to inspect its contents;
-   assume bidirectional communication is available on the monitoring
    path.

The system may use:

-   PCAP files;
-   passive packet metadata;
-   flow records;
-   timestamps;
-   IP addresses;
-   ports;
-   protocol metadata;
-   packet sizes;
-   timing information;
-   TLS/QUIC metadata where available;
-   DNS metadata;
-   statistical and behavioural features;
-   ML/anomaly-detection models.

**Important:** TLS/QUIC analysis is metadata-based unless plaintext is
already legitimately available in the captured data. Do not design the
project around decrypting encrypted traffic.

------------------------------------------------------------------------

# 4. REQUIRED THREAT CATEGORIES

The final detection system must support these categories:

1.  **Volumetric / Protocol DDoS**
2.  **Botnet C2 Beaconing**
3.  **DGA / DNS Tunnelling**
4.  **Malware in Encrypted Sessions**
5.  **Reconnaissance / Port Scanning**
6.  **Data Exfiltration**
7.  **Benign / Normal traffic**

The implementation should be designed so these categories can be
supported without repeatedly rewriting the lower-level ingestion, flow,
windowing, and feature layers.

------------------------------------------------------------------------

# 5. TARGET ARCHITECTURE

The intended high-level pipeline is:

``` text
ONE-WAY TRAFFIC
      ↓
PASSIVE INGESTION
      ↓
PACKET / FLOW PROCESSING
      ↓
SLIDING-WINDOW STREAM PROCESSING
      ↓
FEATURE EXTRACTION
      ↓
AI / ML DETECTION
      ↓
THREAT CLASSIFICATION
      ↓
CONFIDENCE SCORING
      ↓
SEVERITY + SUPPORTING EVIDENCE
      ↓
ALERT GENERATION
      ↓
VISUALIZATION DASHBOARD
```

The architecture should remain modular.

Expected conceptual layers:

``` text
ingestion/
processing/
ml/
api/
dashboard/
tests/
docs/
scripts/
models/
datasets/
```

Do not create unnecessary complexity merely to make the architecture
look sophisticated.

------------------------------------------------------------------------

# 6. DEVELOPMENT ORDER

Do NOT skip ahead.

The agreed development order is:

1.  Environment setup --- COMPLETED
2.  Project structure / AGENTS.md --- COMPLETED
3.  Passive PCAP ingestion --- COMPLETED
4.  Flow construction --- IMPLEMENTED
5.  Sliding-window streaming engine --- IMPLEMENTED
6.  Feature extraction --- IMPLEMENTED
7.  Dataset preparation / preprocessing / baseline detection pipeline
    --- NEXT
8.  ML training
9.  ML inference / six-threat detection
10. Confidence / severity / evidence
11. FastAPI
12. WebSocket streaming
13. React dashboard
14. Performance measurement
15. End-to-end testing
16. Final demo-ready prototype

**Critical rule:** A coding agent must never silently implement Phase 7+
while being asked to audit or correct Phases 4--6.

------------------------------------------------------------------------

# 7. CURRENT REPOSITORY / GIT BASELINE

The known GitHub history is:

``` text
6af5669  Implement Phase 6 feature extraction
2106d19  Implement Phase 5 sliding-window streaming engine
0f519b2  Implement Phase 4 bidirectional flow construction
85146f8  Initial commit: Project setup and Phase 3 Passive PCAP Ingestion implementation
```

The last known trusted checkpoint before the unreviewed Phase 4--6 work
was:

``` text
85146f8d62b22b369de4f14ca33cbf1820a9e6f8
```

The repository currently contains committed implementations for Phases
4--6.

A later audit/correction pass was performed locally but, at the time
this baseline was written, those corrections had **not yet been approved
for commit**.

Therefore:

-   Do not assume the local corrected code is already on GitHub.
-   Do not claim a correction has been verified merely because
    Antigravity reported it.
-   For code-review decisions, inspect the actual diff or pushed code.
-   GitHub is the source that ChatGPT can directly inspect for committed
    project code in this workflow.
-   Antigravity's local uncommitted working tree is not directly visible
    unless its diff/code is provided or pushed.

------------------------------------------------------------------------

# 8. PHASE 3 --- PASSIVE PCAP INGESTION

## Status

**COMPLETED and previously reviewed.**

Key implementation:

### `ingestion/packet_event.py`

The project uses a normalized `PacketEvent` dataclass containing:

-   timestamp
-   packet length
-   raw packet
-   source IP
-   destination IP
-   source port
-   destination port
-   protocol

Conceptually:

``` python
@dataclass
class PacketEvent:
    timestamp: float
    length: int
    raw_packet: Any
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
```

### `ingestion/pcap_reader.py`

Uses Scapy's incremental `PcapReader`.

It:

-   validates the path;
-   reads packets incrementally;
-   preserves capture timestamps;
-   records packet length;
-   extracts IPv4/IPv6 addresses;
-   extracts TCP/UDP ports;
-   identifies TCP/UDP protocol;
-   produces `PacketEvent` objects;
-   does not transmit or replay traffic.

### Tests

Phase 3 has tests for:

-   invalid files;
-   invalid paths;
-   TCP/UDP metadata;
-   timestamps;
-   packet counts.

### Phase 3 review conclusions

Phase 3 was considered correct enough to proceed.

Known technical notes:

1.  A future improvement would be a specific PCAP-read exception instead
    of wrapping all exceptions in generic `ValueError`.
2.  `timestamp: float` is acceptable but should remain a deliberate
    interface.
3.  Later layers should primarily consume normalized `PacketEvent`
    fields rather than depend on Scapy internals.
4.  Current protocol extraction focuses on TCP/UDP. Other protocols may
    later matter for protocol-DDoS detection.
5.  The CLI's packet-rate-style output is based on capture timestamps
    and is NOT a measurement of processing throughput.
6.  The synthetic PCAP generator should eventually use
    documentation/reserved IP ranges instead of public addresses such as
    `8.8.8.8`.
7.  The README needs a later improvement.

Do not perform a large Phase 3 refactor unless it becomes necessary.

------------------------------------------------------------------------

# 9. PHASE 4 --- FLOW CONSTRUCTION

## Status

**IMPLEMENTED. AUDITED. CORRECTIONS REPORTED BY ANTIGRAVITY. ACTUAL DIFF
MUST BE VERIFIED BEFORE FINAL COMMIT APPROVAL.**

Main file:

``` text
processing/flow.py
```

The flow layer consumes `PacketEvent` objects.

It supports:

-   TCP;
-   UDP;
-   bidirectional flow identity;
-   directional statistics.

A flow tracks at minimum:

-   flow_id
-   src_ip
-   dst_ip
-   src_port
-   dst_port
-   protocol
-   first_seen
-   last_seen
-   duration
-   packet_count
-   byte_count
-   forward packet count
-   reverse packet count
-   forward byte count
-   reverse byte count

The flow key is bidirectional/canonicalized so traffic in both
directions belongs to the same logical flow.

Directionality is preserved separately using the first observed
direction as the forward direction.

### Important audit correction

The original implementation did not reject missing TCP/UDP ports before
canonicalization. This was identified as a real correctness issue.

The audit report says the correction now:

-   rejects missing source/destination ports;
-   preserves identity/directionality;
-   verifies flow accounting invariants.

This correction must be checked in the actual diff before approval.

### Tests

Relevant tests include:

-   new flow creation;
-   bidirectional packets;
-   forward/reverse counts;
-   byte accounting;
-   timestamps;
-   duration;
-   multiple flows;
-   TCP/UDP;
-   malformed/incomplete packets.

------------------------------------------------------------------------

# 10. PHASE 5 --- SLIDING-WINDOW STREAM PROCESSING

## Status

**IMPLEMENTED. AUDITED. CORRECTIONS REPORTED BY ANTIGRAVITY. ACTUAL DIFF
MUST BE VERIFIED BEFORE FINAL COMMIT APPROVAL.**

Main file:

``` text
processing/window.py
```

The sliding-window manager is intended to:

-   accept packet events incrementally;
-   retain a bounded time window;
-   emit snapshots at a configurable slide interval;
-   aggregate packet/byte/flow information;
-   provide snapshots for feature extraction.

Default conceptual behaviour:

``` text
window = 10 seconds
slide = 1 second
```

These are engineering defaults, not immutable requirements.

### Important semantics

The current design uses:

``` text
[start_time, end_time]
```

inclusive boundaries.

This convention must remain explicit and tested.

### Timestamp handling

The audit correction introduced a requirement that packet timestamps
must be non-decreasing.

This is acceptable because the streaming engine relies on an ordered
capture stream.

If an out-of-order packet is received, the implementation is expected to
reject it rather than silently corrupt the deque-based eviction logic.

### Important issue requiring verification

A **large timestamp jump** can expose a subtle interaction between:

1.  buffer eviction;
2.  window emission;
3.  historical windows.

Before approving Phase 5, there must be an explicit test defining what
happens when timestamps jump forward by more than one or several slide
intervals.

Do not merely accept "all tests pass."

The exact emitted-window behaviour must be intentional and tested.

### Other Phase 5 requirements

Do not:

-   use wall-clock time for capture processing;
-   silently clamp timestamps to zero;
-   mutate snapshots unexpectedly;
-   claim throughput improvements that were not measured.

The implementation may remain a straightforward reconstruction-based
prototype for now. Performance optimization can happen in the dedicated
performance phase.

------------------------------------------------------------------------

# 11. PHASE 6 --- FEATURE EXTRACTION

## Status

**IMPLEMENTED. AUDITED. ONE IMPORTANT SEMANTIC ISSUE WAS IDENTIFIED.
ACTUAL DIFF MUST BE VERIFIED BEFORE FINAL COMMIT APPROVAL.**

Main file:

``` text
processing/features.py
```

The current feature extractor produces per-flow features from a
`WindowSnapshot`.

Current conceptual features include:

-   flow duration;
-   forward packet count;
-   reverse packet count;
-   forward byte count;
-   reverse byte count;
-   forward bytes/sec;
-   reverse bytes/sec;
-   forward packets/sec;
-   reverse packets/sec;
-   byte ratio;
-   source-IP flow count;
-   source-IP unique destination IP count;
-   source-IP unique destination port count;
-   TCP indicator;
-   UDP indicator.

Source-IP context is calculated only from the current snapshot.

This is important: features should not accidentally leak future-window
information into the current window.

------------------------------------------------------------------------

# 12. CRITICAL PHASE 6 ISSUE: `byte_ratio`

The audit report claimed:

``` text
if reverse bytes == 0:
    byte_ratio = forward_bytes
```

This is **NOT acceptable**.

`byte_ratio` is a ratio and must remain mathematically a ratio.

Returning `forward_bytes` when reverse bytes are zero changes the
feature's meaning and duplicates an existing feature.

The implementation must choose and document a mathematically consistent
convention for:

``` text
forward_bytes / reverse_bytes
```

when:

``` text
reverse_bytes == 0
```

Possible engineering conventions include:

-   `0.0`;
-   positive infinity;
-   a documented finite cap.

The choice must be deliberate and consistent with the later ML pipeline.

Do NOT accept:

``` python
byte_ratio = fwd_bytes
```

as a ratio definition.

This issue must be resolved before Phase 6 is considered fully approved.

------------------------------------------------------------------------

# 13. ZERO-DURATION FEATURES

The audit report changed rate calculations so that zero-duration flows
produce:

``` text
0.0
```

instead of relying on a tiny epsilon such as:

``` python
max(duration, 1e-6)
```

This is acceptable as an engineering convention, provided that:

1.  it is explicitly documented;
2.  tests cover it;
3.  later ML preprocessing understands that a zero-duration flow has
    zero rate under this convention.

A rate should never result in an accidental division-by-zero exception.

------------------------------------------------------------------------

# 14. FEATURE DESIGN PRINCIPLES FOR LATER PHASES

Do not assume the current Phase 6 feature set is sufficient for the
final detector.

Later feature engineering should map features to the required threat
classes.

Examples:

## DDoS

Potential features:

-   packets/sec;
-   bytes/sec;
-   protocol distribution;
-   destination concentration;
-   source concentration;
-   SYN/UDP/ICMP behaviour where available;
-   packet-size statistics;
-   flow creation rate.

## Botnet C2 Beaconing

Potential features:

-   periodicity;
-   inter-arrival-time statistics;
-   repeated destination;
-   repeated destination port;
-   connection frequency;
-   packet-size consistency;
-   session duration consistency.

## DGA / DNS Tunnelling

Potential features:

-   DNS query rate;
-   domain length;
-   entropy;
-   character distribution;
-   label length;
-   unique-domain rate;
-   NXDOMAIN ratio if metadata supports it;
-   repeated encoded-looking labels.

## Malware in Encrypted Sessions

Potential features:

-   TLS/QUIC metadata;
-   session duration;
-   packet-size sequences;
-   directionality;
-   burst behaviour;
-   byte/packet ratios;
-   destination reputation only if legitimately available as
    passive/local metadata, not via active lookup.

## Reconnaissance / Port Scanning

Potential features:

-   unique destination ports;
-   unique destination IPs;
-   connection attempt rate;
-   failed/sparse responses where observable;
-   fan-out;
-   short-duration flow concentration.

## Data Exfiltration

Potential features:

-   sustained outbound bytes;
-   destination concentration;
-   unusual byte ratios;
-   long-lived sessions;
-   burst/sustained transfer patterns;
-   protocol/session metadata.

Feature design must remain tied to observable passive evidence.

------------------------------------------------------------------------

# 15. MACHINE LEARNING STRATEGY

The exact final model is not yet locked.

The architecture should allow supervised and/or anomaly-detection
components.

Potential models already considered for this project include:

-   Random Forest;
-   XGBoost;
-   Isolation Forest;
-   Logistic Regression as a baseline;
-   other lightweight models if justified.

Do not add complex deep-learning architectures merely for appearance.

The model choice must be justified by:

-   available dataset;
-   feature type;
-   training cost;
-   inference speed;
-   interpretability;
-   demonstration reliability;
-   ability to produce useful confidence/evidence.

The final system must not fake model accuracy, F1, throughput, latency,
or detection rates.

All reported metrics must be measured from actual experiments.

------------------------------------------------------------------------

# 16. DATASET / TRAINING PRINCIPLES

The project requires controlled datasets and synthetic/lab traffic where
appropriate.

Important:

-   Do not commit large datasets to Git.
-   Do not commit huge PCAP files.
-   Use `.gitignore` for datasets/models/captures as already configured.
-   Keep dataset preparation reproducible.
-   Record class mappings.
-   Record preprocessing steps.
-   Avoid train/test leakage.
-   Preserve the relationship between windows, flows, labels, and
    features.
-   If a synthetic dataset is used, clearly label it as synthetic/lab
    data.
-   Do not present synthetic performance as if it were real-world
    validation.

------------------------------------------------------------------------

# 17. CONFIDENCE, SEVERITY, AND EVIDENCE

These are separate concepts.

## Confidence

Represents how strongly the model supports the predicted class.

Do not treat confidence as an arbitrary decorative percentage.

## Severity

Represents operational importance based on measurable characteristics.

Potential inputs may include:

-   threat category;
-   traffic volume;
-   persistence;
-   number of affected destinations;
-   exfiltration volume;
-   scan breadth;
-   confidence;
-   temporal persistence.

The exact formula should be documented.

## Supporting evidence

Every alert should eventually be explainable using observable evidence
such as:

``` text
Threat: Port Scanning
Confidence: 0.94
Severity: High

Evidence:
- 1 source IP contacted 137 unique destination ports
- activity occurred over 4.2 seconds
- 129 connections were short-lived
- destination fan-out increased rapidly
```

Do not fabricate evidence.

Evidence must be derived from actual observed features/flow/window data.

------------------------------------------------------------------------

# 18. API / STREAMING / DASHBOARD

These are later phases.

Expected direction:

``` text
Python detection engine
        ↓
FastAPI
        ↓
WebSocket / streaming updates
        ↓
React dashboard
```

The dashboard should prioritize operational usefulness over visual
decoration.

Important views eventually include:

-   live alert stream;
-   threat category;
-   confidence;
-   severity;
-   timestamp;
-   source/destination context;
-   evidence;
-   traffic volume;
-   threat distribution;
-   time-series trends;
-   flow/session details;
-   system processing statistics.

The dashboard must clearly distinguish:

-   captured traffic;
-   processed traffic;
-   detected threats;
-   alerts;
-   system performance.

------------------------------------------------------------------------

# 19. PERFORMANCE MEASUREMENT

Do not confuse capture traffic rate with system processing throughput.

For example:

``` text
capture packets/sec
```

is not automatically:

``` text
detector processing packets/sec
```

Final performance evaluation should measure actual processing.

Potential metrics:

-   packets/sec;
-   flows/sec;
-   windows/sec;
-   feature extraction latency;
-   inference latency;
-   end-to-end alert latency;
-   memory usage;
-   CPU usage;
-   sustained throughput;
-   burst handling.

All metrics must come from actual measured runs.

Never invent values such as:

``` text
1M packets/sec
99.9% accuracy
50 ms latency
```

unless the project actually measured them.

------------------------------------------------------------------------

# 20. TESTING REQUIREMENTS

Every phase must have tests.

At minimum:

-   unit tests for individual components;
-   malformed input tests;
-   boundary tests;
-   empty-input tests;
-   state-transition tests;
-   timestamp tests;
-   regression tests for previously fixed bugs.

Before approving a phase:

``` text
pytest
```

must pass.

But:

> Passing tests does not automatically mean the implementation is
> correct.

Tests must test semantics, not just execution.

Examples:

-   A byte ratio test must verify that the result is actually a ratio.
-   A sliding-window test must verify exact boundaries.
-   A large timestamp jump test must verify exact emitted windows.
-   A flow test must verify forward/reverse invariants.
-   A feature test must verify no accidental future-window leakage.

------------------------------------------------------------------------

# 21. CURRENT TEST BASELINE

Antigravity reported:

``` text
19 passed in 0.65s
```

This was a report from the audit/correction pass.

Treat it as **reported**, not independently verified, until the actual
corrected code/diff is inspected.

The next review should verify:

1.  all 19 tests still pass;
2.  tests include the new required large timestamp jump case;
3.  tests include zero-duration rate behaviour;
4.  tests include correct zero-reverse-byte ratio behaviour;
5.  no unrelated tests were weakened or removed.

------------------------------------------------------------------------

# 22. DOCUMENTATION REQUIREMENTS

Important documentation files include:

``` text
AGENTS.md
README.md
docs/architecture.md
docs/features.md
```

`AGENTS.md` is the authoritative repository development policy.

The README is currently weaker than it should be and should eventually
explain:

-   problem statement;
-   project purpose;
-   architecture;
-   setup;
-   how to run tests;
-   how to generate/use test PCAPs;
-   development phases;
-   current status;
-   demo workflow.

A dedicated `docs/features.md` should eventually document:

-   feature name;
-   mathematical definition;
-   unit;
-   source;
-   interpretation;
-   edge-case convention;
-   threat relevance.

Do not create documentation merely for volume.

------------------------------------------------------------------------

# 23. ANTIGRAVITY WORKFLOW

Google Antigravity is the primary coding agent.

When giving Antigravity instructions:

1.  Tell it to read `AGENTS.md`.
2.  State the exact phase.
3.  Explicitly state what it must NOT implement.
4.  Require inspection of existing code before editing.
5.  Require tests.
6.  Require a final report.
7.  Require it to stop after the requested phase.
8.  Do not allow unrelated refactoring.
9.  Do not allow it to silently move to later phases.
10. Do not approve commits solely from a summary report.

Preferred workflow:

``` text
ChatGPT defines task
        ↓
Antigravity edits code
        ↓
Antigravity runs tests
        ↓
Antigravity reports changes
        ↓
Actual diff/code is inspected
        ↓
ChatGPT reviews correctness
        ↓
Corrections if necessary
        ↓
Tests
        ↓
Commit
        ↓
Push
        ↓
Next phase
```

------------------------------------------------------------------------

# 24. IMPORTANT GIT / REVIEW RULE

The previous workflow exposed an important limitation:

ChatGPT cannot automatically see Antigravity's uncommitted local working
tree.

Therefore, when actual code review is required, use one of these:

### Preferred

Push the code to GitHub after a controlled checkpoint so ChatGPT can
inspect the committed version.

### Or

Have Antigravity provide the exact:

``` bash
git diff
```

or specific source files.

Do NOT say:

> "The code is fixed, so it is correct."

Instead distinguish:

-   **reported** by Antigravity;
-   **inspected** by ChatGPT;
-   **tested**;
-   **approved**;
-   **committed**;
-   **pushed**.

These are different states.

------------------------------------------------------------------------

# 25. DO NOT REVERT WHOLE PHASES WITHOUT EVIDENCE

The project previously reached a point where the user considered
reverting Phases 4--6 after they were committed before review.

The conclusion was:

-   do not revert the phases wholesale;
-   inspect the implementation;
-   correct concrete issues;
-   preserve valid work;
-   commit a reviewed correction.

This is the preferred approach going forward.

Avoid destructive Git operations unless there is a concrete reason.

------------------------------------------------------------------------

# 26. CURRENT OPEN ITEMS

At the baseline date, the most important unresolved items are:

### A. Verify actual corrected Phase 4 code

Check:

``` text
processing/flow.py
tests/test_flow.py
```

Specifically verify:

-   missing TCP/UDP ports are rejected;
-   bidirectional key remains symmetric;
-   directional accounting remains correct;
-   flow invariants hold;
-   no unrelated changes exist.

### B. Verify actual corrected Phase 5 code

Check:

``` text
processing/window.py
tests/test_window.py
```

Specifically verify:

-   timestamp monotonicity;
-   inclusive boundaries;
-   buffer eviction;
-   snapshot isolation;
-   large timestamp jumps;
-   exact emitted-window behaviour;
-   no timestamp clamping;
-   no wall-clock dependence.

### C. Verify actual corrected Phase 6 code

Check:

``` text
processing/features.py
tests/test_features.py
```

Specifically verify:

-   rate calculations;
-   zero-duration convention;
-   `byte_ratio` semantics;
-   source-IP context;
-   no future-window leakage;
-   TCP/UDP flags;
-   feature documentation.

### D. Resolve `byte_ratio`

Do not approve:

``` text
reverse_bytes == 0 → byte_ratio = forward_bytes
```

The final convention must preserve the ratio's meaning.

### E. Run full test suite

Require the exact output.

### F. Only then commit the reviewed Phase 4--6 correction

No Phase 7 implementation should be mixed into this commit.

------------------------------------------------------------------------

# 27. NEXT DEVELOPMENT PHASE

After Phase 4--6 corrections are fully verified and committed:

## Phase 7 --- Dataset Preparation / Preprocessing / Baseline Detection

The next task should NOT immediately jump into the final dashboard or
API.

Phase 7 should establish:

-   dataset sources;
-   class mapping;
-   preprocessing;
-   feature alignment with the streaming feature extractor;
-   train/validation/test strategy;
-   baseline labels;
-   handling of missing values;
-   scaling/encoding where needed;
-   reproducible preprocessing;
-   baseline detection experiment.

The exact Phase 7 scope should be defined before coding.

------------------------------------------------------------------------

# 28. REVIEW STANDARD

When reviewing code for this project, use this order:

## 1. Requirements

Does it satisfy the stated phase requirements?

## 2. Semantics

Does each variable/feature actually mean what its name says?

## 3. Edge cases

Check:

-   empty input;
-   missing fields;
-   zero values;
-   duplicate values;
-   out-of-order timestamps;
-   large timestamp gaps;
-   single-packet flows;
-   zero reverse traffic;
-   unsupported protocols.

## 4. Architecture

Does the implementation preserve clean boundaries between:

``` text
ingestion
→ flow
→ window
→ features
→ ML
→ API
→ dashboard
```

## 5. Security / passive constraints

Ensure nothing accidentally transmits, probes, scans, resolves, replays,
or modifies network traffic.

## 6. Testing

Tests must verify actual behaviour.

## 7. Performance

Do not optimize prematurely, but do not claim performance without
measurement.

## 8. Maintainability

Avoid unnecessary complexity and hidden state.

## 9. Documentation

Important semantics should be documented.

## 10. Git scope

Only requested changes should be included.

------------------------------------------------------------------------

# 29. RESPONSE STYLE FOR CHATGPT IN THIS PROJECT

The user prefers:

-   direct answers;
-   technical precision;
-   no filler;
-   no motivational speech;
-   no unnecessary emojis;
-   no generic explanations when the exact project context is available;
-   blunt identification of bugs;
-   explicit distinction between verified facts and reported claims;
-   implementation-focused recommendations.

When reviewing code, say things such as:

``` text
This is correct.
This is incorrect.
This is acceptable but has a limitation.
This is not yet verified.
Do not commit this yet.
This can remain for the prototype.
This must be fixed before the next phase.
```

Do not hide uncertainty.

Do not hallucinate code, test results, repository state, or
implementation details.

If the actual code has not been inspected, say so.

------------------------------------------------------------------------

# 30. RULE FOR NEW PROJECT CHATS

Every new chat about this project should begin from this baseline.

The assistant should assume:

-   the user is continuing SIH 26145;
-   the architecture above is the intended architecture;
-   passive monitoring constraints remain mandatory;
-   Phases 1--3 are established;
-   Phases 4--6 are implemented but their latest correction state must
    be verified;
-   Phase 7 is the next major development phase after the correction
    checkpoint;
-   the repository is `Adeen16/SIHREPO`;
-   Antigravity is the coding agent;
-   ChatGPT is the architecture/review layer;
-   the user does not want to repeatedly re-explain the project.

If the user asks:

> "Continue the project."

First use this baseline to determine the current state.

Do NOT restart the project from scratch.

Do NOT assume the latest local changes are committed unless GitHub or an
exact diff confirms it.

------------------------------------------------------------------------

# 31. STATE TRANSITION DEFINITIONS

Use these terms consistently:

### Implemented

Code exists.

### Tested

Tests were executed and passed.

### Audited

The implementation has been reviewed for correctness.

### Corrected

Known issues identified during audit were fixed.

### Verified

The actual resulting code/diff was inspected and the claimed behaviour
was confirmed.

### Approved

The phase meets the project's review standard.

### Committed

The approved code is in Git history.

### Pushed

The commit exists on the remote GitHub repository.

A phase should ideally move through:

``` text
Implemented
→ Tested
→ Audited
→ Corrected
→ Verified
→ Approved
→ Committed
→ Pushed
```

Do not collapse these states into one.

------------------------------------------------------------------------

# 32. FINAL PRINCIPLE

This project is being built for a technical hackathon, but the
implementation must remain defensible as an actual passive cyber-threat
detection system.

Prioritize, in order:

1.  correctness;
2.  NTRO requirement compliance;
3.  passive architecture;
4.  meaningful detection;
5.  evidence/explainability;
6.  reproducibility;
7.  measured performance;
8.  robustness;
9.  clean architecture;
10. dashboard polish.

Do not sacrifice technical correctness for visual complexity.

Do not fabricate results.

Do not skip review.

Do not silently expand scope.

Do not let the coding agent move to a later phase before the current
phase is verified.

This document is the persistent baseline for all future project
conversations.
