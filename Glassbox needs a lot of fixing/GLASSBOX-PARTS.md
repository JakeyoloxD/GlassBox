# Glassbox — Program Parts & Status

A map of the whole program broken into **independently-shippable parts**, so any
one can be done in a single turn if the build is running long. Status as of this
session. Working file: `Glassbox.html` (structure-engine build). Port source for
anything marked "port": `Glassbox-original-reference.html`. Verify with jsdom via
`se_env.harness.js` (real DOM + dispatched events — never a static stub).

---

## Layer A — Input & ingestion (DONE, do not disturb)
- Canonical path `loadInputBytes(bytes, name, kind)`; paste→UTF-8, `.txt`/`.bin`→raw bytes; `DATA-01` is the one byte source; dependency graph recomputes.
- Input overlay is intentionally simple. **Camera exception:** new input may `zoomExtents()` once; nothing else moves the camera.
- Status: **working.** The user likes this; leave it.

## Layer B — Structure discovery (DONE)
- Panels booted and live: hypotheses board, signatures, stride, columns, segments, strings, digraph, Hilbert, bit-structure, byte-frequency, entropy-timeline, repetition, byte-map, decode-chain.
- Engine tested (module tests 156/157; the one is a 4 MB perf threshold).
- Status: **working.**

## Layer C — Hypotheses & verdict (DONE this session)
- Ranked findings with confidence + evidence; click a row → cross-highlight byte ranges.
- **Verdict banner** at top of the board; labels softened to measurement language per DIRECTION §8: `STRUCTURE DETECTED`, `REPEATED BLOCK STRUCTURE`, `TEXT / PLAINTEXT`, `HIGH ENTROPY — NO STRUCTURE FOUND`.
- Status: **working, verified** (structured/random/text/records/AES-ECB classify correctly).

## Layer D — Crypto drill-down cluster (DONE this session) ★
- Drillable crypto hypotheses show an **OPEN ▸** chip. Clicking it (real-event verified) or `COMMANDS.sbox` / `openCryptoView()` spawns a linked cluster: `crypto.sbox` (fed the discovered 256 bytes, `construction:"explicit", bits:8`) → `ddt, lat, walsh, anf, influence`, wired with `registerDependency`, recomputed, and framed (explicit new-workspace transition — the one allowed camera move).
- Idempotent per source offset; falls back to `findPermutationTables` scan when a hypothesis has no offset.
- Verified: AES S-box → DDT uniformity 4, LAT nonlinearity 112, 6-object cluster, renderers draw.
- Key fns: `spawnSboxCluster(bytes, offset, label)`, `drillFromHypothesis(hypEid, idx)`, `openCryptoView()` (region 10M-b).

## Layer E — Weakness / quality indicators (DONE this session)
- `assessObject(o, data)` + `WEAK_COLOUR`; `drawWeaknessStrip` renders a bottom strip on each crypto panel that **names the metric** (DIFFERENTIAL / LINEAR / WALSH / DEGREE / SAC / S-BOX) + level + measured value — never a bare "secure/broken" (DIRECTION §9). Dimension-aware bands; Walsh compares on the LAT scale (`maxAbs/2`).
- Verified: AES DDT → `DIFFERENTIAL · STRONG · uniformity 4`.

## Layer F — Guided tour (REBUILT this session) ★
- Was orphaned (every step targeted `SBOX-01`/`DDT-01`, never booted → walked empty space). Rebuilt as a robust **two-act** tour (11 steps), each guarding its target and skipping cleanly if absent; no step moves the camera (only the sample-load input exception).
- Act 1 (front door): load embedded sample → verdict board → stride → columns → digraph/Hilbert → entropy → strings.
- Act 2 (drill): `openCryptoView()` → S-box mapping → DDT differential → metric read.
- Embedded deterministic sample `buildTourSample()` (header + 40 records + AES S-box + high-entropy tail), no network.
- Verified: all 11 steps run without throwing; Act 2 opens the cluster; sample S-box = AES (uniformity 4).

---

# REMAINING PARTS (each ≈ one turn)

## Part 1 — Raster region investigation (DIRECTION §12, Priority 1) — DONE
Drag a box on the byte map → persistent byte-range region in `S.doc.regions` (serialises + undoes) with a live **%ones + entropy** readout drawn on the map; a plain click still selects; middle/empty drag still pans; `pointercancel` clears the marquee. Press **S** (or `region` command) to **analyse a ≥256-byte region as an S-box** → opens the crypto cluster on those exact bytes. Also fixed a latent bug: boot was overwriting `data.visual` and dropping `renderer`, so DATA-01 (the byte map) had no renderer. Key fns: `summariseByteRegion`, `byteMapRangeOf`, `createByteRegion`, `analyseRegionAsSbox`, `drawByteRegions`, `view.byteMap.regionHitTest`. Verified end-to-end in jsdom (real drag events) + full regression green.

## Part 2 — WHT randomness panel + null-distribution (DIRECTION §18 Priority 4) — NOT DONE
Port `computeWhtTest`, `view.whtSpectrum`, `computeNullDistribution`, `view.nullDist` and helpers (`makeRng, binomSfHalf, whtPeak, whtPeakPValue, runsTestP, columnPeriodicity`; reuse existing `fwht`) from the reference. Mark `statistical:true`; exempt from any no-float self-test. Open inside the crypto cluster or via a region action. Copy the calibration wording as measured (not "~2×").

## Part 3 — Deeper crypto tools one level down (DIRECTION §4) — PARTIAL
`aesDerivation`, `walshAncestry`, `math.gfMultiply`, `fieldMicroscope` renderers exist but aren't opened by the cluster. Add a second-level "deeper" action from the S-box (spawn AES-derivation + Walsh-ancestry on demand). Low priority.

## Part 4 — Interrogation polish (DIRECTION §18 Priority 2) — NOT DONE
Region→analysis workflow, richer cross-highlight, provenance display ("where did this come from"), readable metric explanations in the Inspector.

## Part 5 — Discovery improvements (Priority 3) & workbench expansion (Priority 5) — FUTURE
Stronger record/field inference, encoded-data detection (Base64/hex decode nodes preserving ancestry), protocol/firmware structure. Each is its own multi-turn effort.

---


## Refinement pass (this session) — DONE
- **Smart input parsing:** a pasted pure 0/1 string is packed into bits, an even-length hex string becomes bytes, everything else is UTF-8 text; the reading is recorded as the source kind (provenance kept). `parseSmartInput` in `analyseTextInput`.
- **Small inputs render boldly:** the byte map now uses adaptive columns (`ceil(sqrt(n))` up to 256 bytes) so short inputs fill the panel instead of a few specks top-left.
- **Overlap fixes:** the weakness RAG moved off the panel body into a compact **header chip** (it used to sit over the grid); the crypto cluster now spawns in a clear band **below all existing panels** and its six panels are laid out with no mutual overlap.
- **Verdict accuracy:** split the cipher verdict into a genuine **REPEATED BLOCK STRUCTURE** (ECB, weak/red) vs **CRYPTO COMPONENT FOUND** (S-box/AES present, amber) so an S-box is no longer mislabelled as repeated blocks.
- **Test sample shipped:** `glassbox-test-sample.txt` (binary bytes in a .txt; open via *Open .txt*) — header + 64 fixed-width records + a readable text block + the AES S-box (drillable) + a high-entropy tail. Exercises records/stride/columns, strings, entropy shift, and the crypto drill-down in one file.

# Verification status this session
Real-DOM (jsdom) audits all pass: boot; import (random/records/prose verdicts); typing isolation (`f` in input doesn't zoom/steal focus); middle-drag pan; crypto drill (OPEN chip real click + `openCryptoView`) spawns the 6-panel cluster; weakness RAG; 11-step tour runs with no throw and opens the cluster. Engine module tests unchanged (156/157).

Harnesses in workspace: `se_env.harness.js` (+ `t1.js`, `t5.js`, `reg.js` style drivers). Rebuild with `npm install jsdom` if the environment reset.

# Suggested split if continuing
1 turn: Part 1 (raster regions) — highest remaining user value.
1 turn: Part 2 (WHT panel).
1 turn: Parts 3–4 (deeper tools + interrogation polish).
Everything in Layers A–F is already in the delivered `Glassbox.html`.
