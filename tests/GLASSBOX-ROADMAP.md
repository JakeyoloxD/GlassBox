# Glassbox Roadmap

**Thesis: give it bytes, it tells you what they are and shows you why.**

Single file. Fully offline. Zero install. Runs from a USB stick on an assessment
box where nothing can be installed. Explains its reasoning instead of making you
write a pattern first.

Status: 2026-08-26. Engine regions 10E-10L built and tested (157 tests).
Integration into the app shell pending.

---

## 0. Scope discipline

This document exists so the project does not drift. Two rules.

**Everything is subordinate to the thesis.** A feature earns its place by making
Glassbox better at taking unknown bytes and returning defensible statements
about them. Cryptographic mathematics is no longer the headline; it is the
drill-down that fires when structure discovery finds crypto. If a proposed
feature does not sharpen the front door, it goes in Deferred.

**No claim without evidence.** Every finding carries the measurement that
produced it and the byte ranges that support it. A number with no attribution
cannot be argued with, and arguing with it is the entire point.

### Open decisions

| # | Decision | Status |
|---|---|---|
| 1 | Structure discovery as front door, crypto as drill-down | **Open** — assumed yes, not confirmed |
| 2 | Chained transform topology rather than flat star | **Taken** — implemented |
| 3 | Max input size; Web Workers yes/no | **Open** — blocks Phase 3 |
| 4 | Hypothesis engine in v1 | **Taken** — implemented, it defines the atom contract |
| 5 | Build order | **Taken** — as laid out below |

---

## 1. Invariants

Inherited from the existing skeleton, extended for the new purpose. Region 23
asserts against these.

| ID | Invariant |
|---|---|
| I1 | Definitions serialise. Computed results never serialise. |
| I2 | `COMPUTED` and `CACHE` live outside `S.doc` and outside history. |
| I3 | Renderers never compute mathematics. They match atoms only. |
| I4 | Cross-view knowledge lives in the resolver, never renderer-to-renderer. |
| I5 | No `eval`, no `new Function`, no network, no remote resources. |
| **I6** | **Every hypothesis carries at least one piece of evidence, and every piece of evidence carries a byte range or a measured number.** |
| **I7** | **Analysis reads the bytes at its own node in the transform chain. A finding derived from decoded bytes says so and cites the decode.** |
| **I8** | **Confidence is bounded by the weakest link in the chain that produced it.** |
| **I9** | **Every compute function is pure and synchronous. Async decoding would break topological recompute in region 06.** |
| **I10** | **Section numbers are permanent. New material gets a suffix.** |

---

## 2. Architecture

### Transform chain

The single most important structural change. The old topology was a flat star:
one `DATA-01`, every analysis hanging off it. Real input is wrapped, and every
statistic is meaningless until it is unwrapped.

```
data.bytes (raw)
   └─ transform.decode (base64)
        └─ transform.decode (gzip)
             └─ data.bytes'  ← analyses attach HERE
                  ├─ analysis.stride ─ analysis.columns
                  ├─ analysis.signatures
                  ├─ analysis.segments
                  ├─ analysis.digraph
                  ├─ analysis.strings
                  └─ hypothesis.board
```

A transform object **is** a byte source: its `compute` returns the same shape as
`computeByteSource`. Lookups move from `sourceOfType(eid, "data.bytes")` to
`byteSourceOf(eid)`, which walks upstream for the first node whose computed
`kind` is `bytes`. Everything else in region 06 already supports chains.

### Output contract

The hypothesis is the product. Shape:

```js
{
  id: "H001",
  kind: "record structure",
  title: "48-byte record structure",
  confidence: 0.97,
  evidence: [ { text, estimator?, value?, ref?: {start,end} } ],
  ranges:   [ { start, end, role } ],
  extra:    { stride, records, fields, drillable, actionable }
}
```

`ranges` flatten into `byteRange` atoms. Clicking a hypothesis highlights its
supporting bytes across every open view through the existing resolver. This is
why the hypothesis engine had to ship in v1: it dictates the atom contract every
renderer must satisfy.

---

## 3. Region map

Permanent numbers. Existing regions unchanged.

| Region | Name | State |
|---|---|---|
| 00-09 | Constants, security, state, entity model, history, dependency graph, atoms, resolver, bus | existing |
| 10A-10D | Boolean primitives, finite fields, budget, crypto kernel | existing |
| **10E** | **Signatures and constants** — 51 magic entries, offset-0 ID, binwalk carving, 21 crypto tables, permutation finder | **built** |
| **10F** | **Codecs and decode ladder** — 12 codecs, synchronous DEFLATE/zlib/gzip, scored recursive unwrap | **built** |
| **10G** | **Period and stride** — equality autocorrelation, IoC, column dispersion, harmonic suppression, XOR, ECB, unaligned repeats | **built** |
| **10H** | **Column typing** — scored field proposals, alignment-aware competition, struct rendering | **built** |
| **10I** | **Classification and segmentation** | **built** |
| **10J** | **Strings** | **built** |
| **10K** | **Digraph and space-filling** | **built** |
| **10L** | **Hypothesis engine** | **built** |
| 10Z | Original raw-input structure | superseded, retained |
| 11-24 | Render core, renderers, hit test, highlight, annotation, layers, inspector, commands, persistence, export, UI shell, input, self-tests, boot | existing, extended |

---

## 4. Phases

### Phase 1 — Engine ✅ COMPLETE

Regions 10E-10L, pure and synchronous, 157 tests.

Verified behaviours:

- `base64(gzip(json))` unwraps both layers, reports the text underneath
- `hex(base64(zlib(x)))` unwraps three layers
- English prose and CSPRNG output are left alone by the ladder
- 48-byte binary log: correct stride, `u32` counter at `+0x00`, unix timestamp
  at `+0x04` with step 11, constant, enum, `"LOGREC"` tag, random payload
- Firmware blob: AES S-box at `0x8000`, embedded gzip and PNG at exact offsets
- AES-128-ECB: mode detected, CBC of the same plaintext correctly not flagged
- Repeating-key XOR over English: 8-byte key `CANBERRA` recovered
- Pure CSPRNG: one hypothesis, correctly quiet
- Plain prose: text, no crypto claims, no phantom record structure

Performance, single-threaded, 4 MB: full pipeline ~4.8 s. Constant scan 150 ms,
carve 37 ms, segmentation 26 ms, strings 41 ms, Hilbert 102 ms. Stride analysis
dominates.

<details>
<summary><b>Defects found and fixed during Phase 1 — read before changing the scoring</b></summary>

Each of these was caught by a test, not by inspection. They are recorded because
the fixes are load-bearing and easy to undo by accident.

1. **Decode ladder refused base64-of-gzip.** The plausibility scorer rewarded
   only readable text or entropy above 7.4, and a small gzip stream is neither.
   Grounded the scorer in magic recognition instead.
2. **Harmonic suppression was order-dependent.** Reported lag 768 for a 48-byte
   record format. Divisibility is a property of the candidate set, not the
   iteration order.
3. **Column dispersion had an uncorrected small-sample entropy bias.** Fewer
   records per column at larger strides mechanically lowers per-column entropy,
   producing a smooth upward ramp of fake signal. Identified a 64-byte format as
   800-byte. Fixed with Miller-Madow correction.
4. **Field detectors claimed greedily and ignored alignment.** A `u32` read at
   `+0x03` straddling two real fields passed the date test and destroyed seven of
   ten fields. Replaced with scored competition.
5. **ECB detector fired on plain English at 93% confidence.** Gated on entropy —
   then discovered the gate was circular, because the duplication that defines
   ECB is what depresses the entropy. Now measures entropy over *distinct*
   blocks against what a uniform source of that size could actually reach.
6. **Constant runs fused an ASCII tag with an f64's zero mantissa bytes.** Split
   at printability boundaries.
7. **A `u32` whose high bytes never vary lost to a `u16` plus a constant run.**
   The constant run straddles the field edge, so containment could not catch it.
   Added absorption plus remainder re-proposal.
8. **Alignment bonus fired on a 10-byte field at offset 10.** Alignment means
   machine word widths, not any length that divides its own offset.
9. **Printable ASCII read as `u32` spans 1994-2038 in unix seconds.** The
   printable range and the plausible-date range are nearly the same interval, so
   any four bytes of text passed the timestamp test. English prose reported four
   timestamp fields at 93%. A timestamp whose every byte is printable is text.
10. **XOR search took its period from the top overall stride.** On XOR'd English
    the strongest periodicity is the plaintext's sentence length, not the key
    length, so the real key was never tried. Now searches short periods on their
    own terms and accepts only if decryption moves word-separator frequency into
    the natural-language band.
11. **Structural claims about ciphertext.** Field typing on XOR ciphertext
    produced a keystream artefact reported as a timestamp. Structure claims are
    now withdrawn once encryption is asserted with confidence.
12. **Stride analysis took 3.4 s on 2 MB.** Two-stage coarse sweep then refine,
    plus sparse histogram resets. Now ~1.0 s.

</details>

### Phase 2 — Integration (next)

Wire the engine into the app shell. No new algorithms.

- [ ] Splice regions 10E-10L into the single-file HTML
- [ ] `byteSourceOf()` replacing `sourceOfType(eid, "data.bytes")`
- [ ] New object types: `transform.decode`, `analysis.stride`, `analysis.columns`,
      `analysis.signatures`, `analysis.segments`, `analysis.digraph`,
      `analysis.strings`, `hypothesis.board`
- [ ] New atoms: `stride`, `column`, `hypothesis`, `signature`, `stringAt`
- [ ] Resolvers for each new fact kind
- [ ] Renderers: hypothesis board, decode chain, stride plot, column/struct grid,
      signature list, segment ribbon, digraph raster, Hilbert map, strings list
- [ ] Boot topology as a chain, not a star
- [ ] Paste modes: text, hex, base64, with auto-detection
- [ ] Self-tests in region 23 asserting I6-I9

**Acceptance:** load a `.bin`, get a ranked hypothesis board; click any
hypothesis and its supporting bytes light up in every open view.

### Phase 3 — Scale

Blocked on decision 3.

- [ ] Raise `maxFileBytes` from 8 MB (firmware images run 16-64 MB)
- [ ] Windowed/sampled mode above a threshold, with sampling disclosed in the UI
- [ ] Web Worker via Blob URL, with chunked main-thread fallback for CSP-blocked
      contexts, driven by the existing region 10D budget
- [ ] Progressive results: hypotheses stream in as each analysis completes

### Phase 4 — Crypto drill-down

Where the existing kernel earns its place. This is the differentiator: nothing
on the market goes from "unknown blob" to "here is the DDT of the S-box I found
inside it".

- [ ] Click an AES constant hit → open the existing S-box view on those bytes
- [ ] Candidate S-box (256-byte permutation, not a known table) → DDT, LAT,
      Walsh, ANF on the discovered table
- [ ] Apply-XOR action: decrypt in place, push a new node onto the chain,
      re-run the whole analysis on the plaintext
- [ ] Padding detection: PKCS#7, zero, 0x80
- [ ] Key/IV candidate spotting: high-entropy 16/32-byte runs inside structured data

### Phase 5 — Depth

- [ ] Suffix array for exact longest-repeated-substring
- [ ] ASN.1/DER structure tree
- [ ] Protobuf wire-format probe
- [ ] Bit-shift alignment search for sub-byte-aligned data
- [ ] Bit planes
- [ ] Export a discovered layout as a Kaitai Struct `.ksy` or a C header
- [ ] `.glass` round-trip of a full investigation including hypotheses accepted
      and rejected by the analyst

---

## 5. Deferred, deliberately

Recorded so they are not silently rediscovered as good ideas.

- DFT/FFT, LFSR lab, general cipher builder, full comparison workspace (cut from
  the original v1 and still cut)
- Disassembly. Identifying architecture is in scope; disassembling is not.
- Decompression beyond DEFLATE. bzip2, xz, zstd and LZMA are detected by
  signature and left to the analyst.
- Network anything. Permanently out.
- Multi-file corpus analysis. One buffer at a time.

---

## 6. Competitive position

| Tool | Overlap | Why Glassbox is different |
|---|---|---|
| binwalk | carving, entropy | CLI, no interactive cross-highlighting, install required |
| binvis.io | Hilbert, digraph | visualisation only, no hypotheses, hosted |
| Veles | digraph, structure | dead |
| CyberChef | decode ladder | manual recipe building; magic is shallow and does not reason across steps |
| Kaitai WebIDE | struct definitions | you must write the pattern first; it cannot find one |
| ImHex | closest live competitor | desktop, install required, pattern-language driven |

The open niche is narrow and real: **single file, fully offline, zero install,
hypothesis-driven, and it shows its working.** That combination does not exist,
and it is exactly the combination that matters on an assessment box you do not
own.

---

## 7. Anti-goals

Things that would count as drift.

- Becoming a hex editor. Glassbox reads and reasons; it does not author bytes.
- Becoming a crypto teaching tool. The mathematics is a drill-down.
- Requiring the user to know the answer first. If it needs a pattern file, a
  format name, or a schema before it can help, the thesis has been abandoned.
- Charts without claims. A wall of plots is what everything else already does.
- Confident wrong answers. Twelve of the defects above were confident wrong
  answers. Silence beats a fluent mistake.
