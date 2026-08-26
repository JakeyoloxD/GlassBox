# Glassbox — Product Direction and AI Build Doctrine

**Purpose:** This file defines the intended direction of Glassbox so an AI or developer can extend the project without drifting into a generic crypto dashboard, disconnected visualiser, or collection of unrelated analysis tools.

Read this before making architectural or UX changes.

---

## 1. Product thesis

> **Give Glassbox bytes. It tells you what they are and shows you why.**

That is the core of the product.

Glassbox is not primarily a cryptography calculator.

It is an **interactive binary structure and cryptographic analysis workbench** for interrogating unknown data.

Its job is to move through a reasoning chain:

```text
UNKNOWN BYTES
    ↓
DISCOVER STRUCTURE
    ↓
FORM HYPOTHESES
    ↓
SHOW EVIDENCE
    ↓
DRILL INTO RELEVANT ANALYSIS
    ↓
LET THE USER INTERROGATE THE RESULT
```

The structure engine is the front door.

Cryptography is a specialist drill-down when the data or the user gives sufficient reason to perform it.

---

## 2. The defining Glassbox interaction

The strongest interaction model for Glassbox is:

```text
"What are these bytes?"
        ↓
Glassbox proposes a finding
        ↓
"Why do you think that?"
        ↓
Glassbox shows the byte range / measurement / visual evidence
        ↓
"What does that imply?"
        ↓
Glassbox opens the relevant deeper analysis
        ↓
"Show me exactly where that result came from."
        ↓
Glassbox traces the conclusion back to specific bytes or maths
```

Every major future feature should strengthen this loop.

If a feature produces a chart but cannot answer **why the chart exists**, **what bytes it represents**, or **what conclusion is justified**, it probably does not belong in the default Glassbox workflow.

---

## 3. Core product layers

### Layer 1 — Input

Glassbox accepts bytes and keeps the import/analyse workflow simple.

Input should remain broadly agnostic:

- binary files
- pasted data
- text
- encoded material
- packet captures or extracted payloads in future
- firmware or embedded blobs in future
- arbitrary unknown byte sequences

Do not force the user to classify the data before Glassbox examines it.

---

### Layer 2 — Structure discovery

This is the primary analysis surface.

The structure engine should identify or visualise evidence such as:

- file or format signatures
- periodicity / stride
- repeating records
- likely fields / columns
- string regions
- entropy changes
- segments / region boundaries
- byte-frequency structure
- repetition
- digraph structure
- Hilbert spatial structure
- bit-level structure
- candidate permutation tables
- cryptographic constants
- possible encoded or transformed regions

This layer answers:

> **What appears to be present?**

---

### Layer 3 — Hypotheses and evidence

Glassbox should never behave like a magic classifier.

A hypothesis must carry evidence.

Evidence should resolve to one or more of:

- byte ranges
- measured numeric properties
- transformations
- structural relationships
- dependency ancestry

Examples:

```text
Possible 64-byte records
Evidence:
- strong stride peak at 64
- repeated field boundaries
- matching entropy profile
```

```text
Candidate 8-bit S-box
Evidence:
- 256-byte region
- all values 0..255 occur exactly once
- permutation discovered at offset 0x1A40
```

The user should be able to move from the hypothesis to the supporting evidence.

---


## 3A. Input doctrine

Glassbox begins with **data**, not with a choice of analysis tool.

The user should not need to decide whether they want entropy analysis, a DDT, a record detector, a Walsh test, or any other specialist view before supplying input.

The correct model is:

```text
SOURCE
  ↓
NORMALISE TO EXACT BYTES
  ↓
DATA-01
  ↓
DEPENDENCY GRAPH
  ↓
STRUCTURE DISCOVERY
  ↓
HYPOTHESES / EVIDENCE
  ↓
RELEVANT DRILL-DOWN
```

All supported input sources should converge on one canonical ingestion path.

Conceptually:

```javascript
loadInputBytes(bytes, name, sourceKind)
```

The rest of the structure engine should not need to care whether the bytes came from pasted text, a binary file, an extracted protocol payload, firmware, or a future importer.

### Current intended behaviour

The existing structure-engine input flow is the model to preserve:

- pasted or typed text is converted to UTF-8 bytes
- `.txt` and `.bin` files are read byte-for-byte
- both paths become a `Uint8Array`
- both enter through the same `loadInputBytes()` path
- `DATA-01` becomes the canonical byte source
- changing `DATA-01` marks its dependency graph dirty
- dependent analysis recomputes from the new bytes
- the UI then presents structure derived from those exact bytes

The input overlay is intentionally simple:

```text
Give Glassbox bytes to investigate

[ paste / type data ]

Analyse text
Open .txt / .bin
Close
```

This is good product behaviour and should not be replaced by a tool-selection screen.

### Future input sources

Future importers may include:

```text
hex text
Base64
packet / PCAP payloads
firmware images
executable sections
embedded files
clipboard byte streams
decoded regions
decompressed regions
custom binary formats
```

These should not become separate analysis engines.

They should either:

1. produce exact bytes and call the canonical ingestion path, or
2. create a transformation / extraction node whose output becomes a byte source in the same dependency graph.

Example:

```text
PCAP
  ↓
packet extraction
  ↓
payload bytes
  ↓
structure discovery
```

Example:

```text
Base64 text
  ↓
decode node
  ↓
decoded bytes
  ↓
structure discovery
```

Example:

```text
Firmware image
  ↓
selected region
  ↓
region byte source
  ↓
crypto drill-down
```

### Preserve provenance when input is transformed

Direct file input and transformed input are not the same thing.

If bytes are decoded, decompressed, extracted, reordered, XORed, or otherwise transformed, Glassbox must preserve that ancestry.

Do not silently replace the original source with transformed bytes.

The user should be able to trace:

```text
original input
  ↓
transformation
  ↓
derived byte source
  ↓
finding
```

### Do not fragment ingestion

Avoid architectures like:

```text
TXT analyser
BIN analyser
PCAP analyser
Firmware analyser
Hex analyser
Crypto analyser
```

with separate computation pipelines.

That would destroy one of the strongest properties of the current architecture.

Prefer:

```text
many input adapters
        ↓
common byte-source model
        ↓
common discovery engine
```

### File type is metadata, not destiny

A filename or extension may help form hypotheses, but it should not dictate the analysis.

A `.bin` file may contain text.

A text file may contain Base64.

Firmware may contain compressed, executable, textual, and encrypted regions simultaneously.

Glassbox should analyse what the bytes show, not merely what the filename claims.

### Input limits and safety

Input limits should remain explicit and deterministic.

The application should:

- reject inputs above its configured byte limit
- avoid network access
- avoid remote parsers
- avoid executing input
- treat loaded content purely as data
- safely parse native Glassbox investigation files separately from arbitrary binary input

Input handling must never become a code-execution path.

### New and Open semantics

`New` should mean:

```text
start a new byte investigation
```

not:

```text
create a blank collection of analysis widgets
```

`Open input` should mean:

```text
supply new source data
```

Native `.glass` investigation files remain a separate concept because they restore an investigation document rather than provide raw bytes.

### Camera exception for new input

Loading completely new source data may initialise or fit the workspace once because the investigation itself has changed.

This is the narrow exception to the normal camera doctrine.

After that initial load:

- semantic selection must not move the camera
- tutorial steps must not move the camera
- `Show me` must not move the camera
- drill-down spawning should avoid moving the camera unless explicitly designed as a new-workspace transition
- analysis commands must not automatically zoom or pan
- only explicit View operations should reposition the workspace

Do not use the existence of an input-time `zoomExtents()` call as justification for automatic camera movement elsewhere.

---

## 4. Crypto is a drill-down, not the front page

Crypto panels should not appear simply because Glassbox contains crypto features.

They should open when:

1. Glassbox finds relevant evidence, or
2. the user explicitly asks for the analysis.

Example:

```text
Structure engine detects a 256-byte permutation
        ↓
Hypothesis:
"Candidate S-box"
        ↓
User clicks Open / Analyse
        ↓
Glassbox spawns the linked crypto cluster
```

This avoids producing convincing-looking analysis of arbitrary bytes.

### Default S-box drill-down cluster

When justified, open a linked cluster containing:

```text
S-box Grid
    │
    ├── DDT
    ├── LAT
    ├── Walsh
    ├── ANF
    └── Influence / SAC
```

Deeper specialist tools can sit another level down:

```text
AES derivation
GF field microscope
Walsh ancestry
WHT randomness analysis
Null-distribution calibration
```

Do not crowd every possible crypto panel into the default workspace.

---

## 5. Evidence-triggered visuals

Visualisations should exist because they communicate something meaningful.

Good:

```text
Entropy timeline
because Glassbox detected meaningful regional changes.
```

Good:

```text
DDT
because a candidate substitution box was identified or explicitly supplied.
```

Bad:

```text
Render every available chart for every file.
```

That creates visual noise and increases the chance of confident but meaningless interpretation.

Glassbox should prefer **fewer justified panels** over many decorative panels.

---

## 6. Glassbox should be interrogable

Every significant visual should support interaction.

A user should be able to click a result and discover more.

Examples:

### S-box

```text
click cell
→ input 0x53
→ output 0xED
→ show exact mapping
```

### DDT

```text
click Δx / Δy cell
→ show count
→ show contributing input pairs
→ highlight those S-box mappings
```

### LAT / Walsh

```text
click coefficient
→ show masks
→ show bias / correlation
→ expose ancestry / contributing relation
```

### Entropy

```text
click peak or region
→ highlight corresponding byte range
```

### Stride

```text
click candidate period
→ show where repetition occurs
→ highlight inferred record boundaries
```

### Hypothesis

```text
click evidence
→ select / highlight originating byte range or measurement
```

The application should behave like an instrument, not a slideshow.

---

## 7. Preserve provenance

A major future advantage of Glassbox should be that findings preserve their origin.

If analysis is performed after decoding or transformation:

```text
raw bytes
    ↓
base64 decode
    ↓
decompression
    ↓
structure analysis
    ↓
crypto finding
```

Glassbox must retain that chain.

A finding from decoded bytes must never silently appear as though it came directly from the original file.

The user should be able to answer:

```text
Where did this result come from?
What transformation produced these bytes?
What byte range in that stage was analysed?
```

---

## 8. Measurements are not conclusions

Glassbox must remain disciplined about language.

Avoid:

```text
SECURE
BROKEN
ENCRYPTED
AES
```

unless the evidence actually supports those conclusions.

Prefer:

```text
Strong differential profile
Candidate AES constants
High entropy
Permutation consistent with an 8-bit S-box
No obvious structural weakness detected by this test
```

A strong DDT does not prove a cipher is secure.

High entropy does not prove encryption.

A repeated block pattern may suggest ECB-like behaviour but should not be labelled as AES-ECB without supporting evidence.

The interface should distinguish:

```text
MEASUREMENT
INTERPRETATION
HYPOTHESIS
CONFIRMED STRUCTURE
```

---

## 9. Weakness / quality indicators

The old weakness-assessment system is worth retaining, but it must describe the metric being assessed.

Preferred presentation:

```text
DIFFERENTIAL PROFILE
STRONG

Uniformity: 4
```

rather than:

```text
SECURE
```

Useful quality indicators include:

- differential uniformity
- linear bias / nonlinearity
- Walsh magnitude
- algebraic degree
- SAC / influence deviation
- WHT peak significance
- randomness test p-values
- repetition / block structure

Scoring should remain dimension-aware.

Do not compare raw values across differently sized S-boxes without normalisation.

---

## 10. The guided tour should teach Glassbox, not cryptography first

The tutorial should explain the application's reasoning model.

### Act 1 — What are these bytes?

Use an embedded sample so the tutorial always has meaningful data.

Recommended sequence:

1. Load sample
2. Read the high-level verdict / hypothesis board
3. Examine stride / periodicity
4. Examine inferred columns / record structure
5. Show digraph and Hilbert views
6. Examine entropy and segmentation
7. Examine strings

This demonstrates the core promise:

> Glassbox can reveal structure you did not already know was present.

### Act 2 — Drill deeper

When the sample exposes a crypto candidate:

1. Open the S-box cluster
2. Inspect a mapping
3. Open the DDT
4. Examine a differential
5. Inspect LAT / Walsh
6. Explain the quality indicator
7. Trace the result back to exact mappings or coefficients

The guide must never point at missing objects.

If a target does not exist, skip cleanly and explain why.

### Camera doctrine

The tutorial must not hijack zoom or pan.

`Show me` should:

- select
- highlight
- trace
- explain
- update Inspector / Understand content

It should not reposition the workspace unless the user explicitly requests a View operation.

---

## 11. Preserve the visual "money shots"

The following views are especially valuable because they make hidden structure immediately visible:

- digraph
- Hilbert map
- byte raster
- entropy timeline
- field / column visualisation
- DDT
- LAT
- Walsh spectrum

Digraph + Hilbert are particularly important in onboarding because they communicate the central concept of Glassbox visually:

> data that looks opaque as bytes can expose structure when viewed correctly.

Do not bury these views behind obscure commands.

---

## 12. Raster regions should become a general investigation tool

The old drag-select raster concept should be integrated into the current byte map rather than restored as a disconnected legacy mode.

Desired workflow:

```text
drag over region
    ↓
create persistent region
    ↓
show byte / bit statistics
    ↓
allow analysis of that region
```

Possible region actions over time:

- calculate entropy
- inspect %ones
- decode as text
- analyse as S-box
- run WHT randomness test
- compare with another region
- inspect repetition
- export selected bytes
- create a named hypothesis

Regions should become reusable investigation objects.

---

## 13. Future expansion direction

Glassbox should remain general enough to grow beyond its current crypto focus.

Strong future directions include:

### Binary formats

- magic / signatures
- headers
- record structures
- checksums
- offsets
- alignment
- padding
- tables
- embedded files

### Protocol analysis

- message framing
- length fields
- counters
- timestamps
- repeated fields
- command IDs
- binary protocol inference

### Firmware

- compressed sections
- entropy boundaries
- executable regions
- lookup tables
- keys / constants
- embedded filesystems
- strings
- configuration blocks

### Encoding and transforms

- Base64
- hex
- XOR
- byte swaps
- endian transformations
- compression candidates
- lightweight obfuscation

### Cryptography

- substitution boxes
- permutations
- AES constants
- lookup tables
- keystream analysis
- block repetition
- avalanche / influence
- linear and differential properties
- randomness diagnostics

These should all fit into the same model:

```text
discover
→ hypothesise
→ show evidence
→ drill down
```

---

## 14. Avoid becoming these products

Glassbox should **not** become:

### A generic hex editor

Hex editing may eventually be useful, but raw editing is not the identity.

### A crypto calculator collection

Do not build a ribbon containing dozens of disconnected formulas.

### A malware reverse-engineering suite

Glassbox can help inspect binary structure, but it does not need to become Ghidra, IDA, Binary Ninja, or a debugger.

### A statistical dashboard

Statistics must connect back to the data and the question being investigated.

### A chart gallery

Every chart needs a claim, hypothesis, evidence source, or explicit user request.

### An AI guessing machine

Do not replace deterministic analysis with unexplained model-generated labels.

AI may help explain results in future, but the underlying evidence should remain inspectable and deterministic.

---

## 15. Architecture doctrine

Preserve these properties.

### Offline-first

Glassbox should remain usable without network access.

No remote scripts, fonts, APIs, telemetry, or cloud requirements.

### Single-file release

The released product should remain a self-contained:

```text
Glassbox.html
```

Development source can be modular if needed, but the release remains one offline HTML file.

### Deterministic computation

Core analysis should remain:

- pure
- synchronous
- reproducible

The same bytes and settings should produce the same result.

### Renderers do not perform analysis

Renderers display computed results.

They should not quietly calculate new analysis that bypasses the computation/dependency system.

### Computed state is not document state

Definitions and user-created investigation state may serialise.

Caches and derived computation should not.

### Dependency graph matters

When one analysis depends on another, represent that dependency explicitly.

Do not create visually adjacent but computationally disconnected objects.

---

## 16. AI coding rules for this repository

When an AI edits Glassbox:

1. Read:
   - this file
   - `GLASSBOX-TODO.md`
   - roadmap / README if present
   - relevant source before changing code

2. Preserve existing working architecture before adding features.

3. Do not rewrite large working systems merely to add one capability.

4. Add capability at the correct architectural layer.

5. Reuse existing computation / renderer / resolver machinery before creating duplicates.

6. Do not add external libraries or network dependencies to the product.

7. Do not create fake tutorial data unless it is clearly an intentional embedded sample.

8. Never fabricate analysis results for presentation.

9. Every new hypothesis must have supporting evidence.

10. Every new visual analysis should identify its byte source.

11. Every transformation must preserve ancestry.

12. Do not introduce automatic camera movement into semantic actions.

13. Do not make a panel always-on merely because it exists.

14. Prefer evidence-triggered drill-down.

15. Run interaction-level regression tests before claiming completion.

---

## 17. Testing doctrine

Do not trust static parsing or shallow DOM stubs as sufficient verification.

Important behaviours must be tested through real event dispatch in the available browser-like harness.

At minimum protect:

- application boot
- input overlay
- pasted data analysis
- file byte loading
- keyboard input isolation
- pan
- pointer cancel
- drag-select
- object selection
- dependency recomputation
- crypto cluster spawning
- renderer execution
- guide steps
- guide missing-target behaviour
- no automatic camera movement
- structure classification regressions

When fixing an interaction bug, add a test reproducing that exact failure.

A bug fixed without a regression test is likely to return.

---

## 18. Near-term development priority

Recommended order:

### Priority 1 — Make the current architecture complete

- restore reachable crypto drill-down
- restore weakness / quality assessment
- rebuild the tutorial
- restore raster region investigation

### Priority 2 — Improve interrogation

- click-through evidence
- better cross-highlighting
- region → analysis workflow
- readable explanation of metrics
- provenance display

### Priority 3 — Improve discovery

- stronger record inference
- more robust field inference
- better encoded-data detection
- better transformation hypotheses
- richer constant / table detection

### Priority 4 — Expand specialist analysis

- WHT randomness panel
- null distributions
- AES derivation
- GF field microscope
- deeper Walsh ancestry
- additional crypto primitives only when justified

### Priority 5 — General binary workbench expansion

- protocol inference
- firmware structure
- embedded data
- checksums
- compression indicators
- transform chain tooling

---

## 19. Decision test for any proposed feature

Before adding something, ask:

### Does it help answer:

```text
What are these bytes?
Why does Glassbox think that?
Where is the evidence?
What can I learn next?
```

If yes, it probably belongs.

If it is merely:

```text
This would be a cool chart.
```

it probably does not belong yet.

---

## 20. The long-term identity

The strongest long-term interpretation of Glassbox is:

> **An instrument for interrogating unknown data.**

Its differentiation is not that it contains the most algorithms.

Its differentiation is that it connects:

```text
bytes
→ structure
→ evidence
→ analysis
→ explanation
→ provenance
```

while keeping the whole chain visible and interactive.

That is the direction future work should reinforce.
