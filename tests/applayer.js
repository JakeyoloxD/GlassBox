//#region 10M CHAIN-AWARE COMPUTE ADAPTERS
/**
 * Adapters between the pure engine (10E-10L) and the object graph.
 *
 * Nothing here computes mathematics. Each function locates its inputs in the
 * dependency graph, calls one engine function, and returns the result. That
 * separation is why the engine could be tested to 157 assertions outside the
 * browser before any of it was wired to a canvas.
 */

/**
 * Walk upstream for the nearest node that produces bytes.
 *
 * Replaces sourceOfType(eid, "data.bytes"). The old lookup assumed a flat star
 * with exactly one byte source, which is wrong the moment a transform sits
 * between the raw input and an analysis: everything downstream of a base64
 * decode must read the DECODED bytes, or every statistic it reports describes
 * the envelope rather than the contents (I7).
 */
function byteSourceOf(eid){
  const seen = new Set(), stack = sourcesOf(eid).slice();
  while (stack.length){
    const id = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    const d = COMPUTED.get(id);
    if (d && d.kind === "bytes") return id;
    sourcesOf(id).forEach(s => stack.push(s));
  }
  return null;
}
function bytesOf(eid, get){
  const id = byteSourceOf(eid);
  const d = id ? get(id) : null;
  if (!d) throw new Error("no byte source upstream");
  return d;
}
/** Find an upstream or sibling computed result by its `kind`. */
function upstreamKind(eid, kind, get){
  for (const id of sourcesOf(eid)){
    const d = get(id);
    if (d && d.kind === kind) return d;
  }
  return null;
}

function computeDecodeChain(o, get){
  const src = bytesOf(o.eid, get);
  const mode = o.definition.mode || "auto";
  let chain;
  if (mode === "off"){
    chain = [{ step: 0, id: "raw", label: "raw input", bytes: src.bytes, score: 1, outLen: src.bytes.length }];
  } else if (mode === "auto"){
    chain = decodeLadder(src.bytes, { maxDepth: safeInt(o.definition.maxDepth, 1, 8, 6) });
  } else {
    const codec = CODECS.find(c => c.id === mode);
    chain = [{ step: 0, id: "raw", label: "raw input", bytes: src.bytes, score: 1, outLen: src.bytes.length }];
    if (codec){
      let res = null;
      try { res = codec.fn(src.bytes); } catch { res = null; }
      if (res && res.length) chain.push({ step: 1, id: codec.id, label: codec.label, bytes: res, score: 1, outLen: res.length });
    }
  }
  const final = chain[chain.length - 1].bytes;
  const facts = bytesFacts(final, src.name, src.sourceKind);
  facts.chain = chain.map(c => ({ step: c.step, id: c.id, label: c.label, score: c.score, outLen: c.outLen, alternatives: c.alternatives || [] }));
  facts.decoded = chain.length > 1;
  facts.rawLength = src.bytes.length;
  return facts;
}

function computeSignatures(o, get){
  const src = bytesOf(o.eid, get);
  const format = identifyFormat(src.bytes);
  const carved = carveSignatures(src.bytes, { limit: 512 });
  const constants = scanCryptoConstants(src.bytes, { limit: 256 });
  const permutations = findPermutationTables(src.bytes, { limit: 24, step: 1 });
  const rows = [];
  if (format) rows.push({ offset: format.offset, label: format.label, group: "format", detail: format.kind });
  for (const h of carved.hits) if (h.offset > 0) rows.push({ offset: h.offset, label: h.label, group: "embedded", detail: h.kind, len: h.len });
  for (const h of constants.hits) rows.push({ offset: h.offset, label: h.label, group: "crypto", detail: h.algo, len: h.len });
  const known = new Set(constants.hits.map(h => h.offset));
  for (const p of permutations) if (!p.identity && !known.has(p.offset))
    rows.push({ offset: p.offset, label: "candidate S-box (256-byte permutation)", group: "crypto", detail: "unknown table", len: 256 });
  rows.sort((a, b) => a.offset - b.offset);
  return { kind: "signatures", format, carved, constants, permutations, rows: rows.slice(0, 512), total: rows.length };
}

function computeStrideAnalysis(o, get){
  const src = bytesOf(o.eid, get);
  const budget = beginBudget("stride");
  const r = analyseStride(src.bytes, {
    maxLag: safeInt(o.definition.maxLag, 8, 4096, 1024),
    sampleBytes: safeInt(o.definition.sampleBytes, 4096, 1 << 21, 262144)
  });
  endBudget(budget);
  return { kind: "stride", ...r, n: src.bytes.length };
}

function computeColumnLayout(o, get){
  const src = bytesOf(o.eid, get);
  const st = upstreamKind(o.eid, "stride", get);
  let stride = safeInt(o.definition.stride, 0, COLUMN_LIMITS.maxStride, 0);
  let chosenBy = "manual";
  if (!stride){
    const best = st && st.candidates && st.candidates[0];
    if (!best || best.score < 0.2) return { kind: "columns", stride: 0, fields: [], columns: [], idle: true };
    stride = best.lag; chosenBy = "stride analysis";
  }
  if (stride > COLUMN_LIMITS.maxStride) return { kind: "columns", stride, fields: [], columns: [], idle: true, tooWide: true };
  const r = analyseColumns(src.bytes, stride, { skip: safeInt(o.definition.skip, 0, 1 << 20, 0) });
  r.kind = "columns";
  r.chosenBy = chosenBy;
  r.structText = r.fields.length ? fieldsToStruct(r, o.definition.name || "record") : "";
  return r;
}

function computeSegments(o, get){
  const src = bytesOf(o.eid, get);
  const sig = upstreamKind(o.eid, "signatures", get);
  const segs = segmentBuffer(src.bytes, { bins: safeInt(o.definition.bins, 32, 2048, 512) });
  const whole = classifyRange(src.bytes, 0, src.bytes.length, { format: sig ? sig.format : null });
  return { kind: "segments", rows: segs, whole, n: src.bytes.length };
}

function computeStringTable(o, get){
  const src = bytesOf(o.eid, get);
  const r = extractStrings(src.bytes, { min: safeInt(o.definition.min, 3, 64, 6), limit: 4096 });
  return { kind: "strings", ...r };
}

function computeDigraph(o, get){
  const src = bytesOf(o.eid, get);
  return { kind: "digraph", ...digraphMatrix(src.bytes) };
}

function computeHilbert(o, get){
  const src = bytesOf(o.eid, get);
  return { kind: "hilbert", ...hilbertMap(src.bytes, { order: safeInt(o.definition.order, 3, 9, 7) }) };
}

/**
 * The board. Reads every sibling analysis out of the graph and hands the lot to
 * the engine. It deliberately recomputes nothing (I3 in spirit): if an upstream
 * analysis failed, its section is simply absent and the board still renders.
 */
function computeHypothesisBoard(o, get){
  const src = bytesOf(o.eid, get);
  const sig = upstreamKind(o.eid, "signatures", get);
  const st  = upstreamKind(o.eid, "stride", get);
  const col = upstreamKind(o.eid, "columns", get);
  const seg = upstreamKind(o.eid, "segments", get);
  const str = upstreamKind(o.eid, "strings", get);
  const bytes = src.bytes;

  const ecb = detectEcb(bytes, 16);
  const xor = searchXor(bytes);
  const repeats = findRepeats(bytes, { seed: 8, limit: 32 });

  resetHypothesisIds();
  const r = buildHypotheses({
    bytes,
    format: sig ? sig.format : null,
    carved: sig ? sig.carved : null,
    constants: sig ? sig.constants : null,
    permutations: sig ? sig.permutations : null,
    stride: st,
    columns: col && !col.idle ? col : null,
    classification: seg ? seg.whole : null,
    segments: seg ? seg.rows : null,
    strings: str,
    repeats, ecb, xor,
    chain: src.chain ? src.chain.map((c, i) => ({ ...c, bytes: i === src.chain.length - 1 ? bytes : null })) : null
  });
  return { kind: "hypotheses", ...r, n: bytes.length };
}
//#endregion

//#region 10N HYPOTHESIS RESOLVERS
registerResolver("hypothesis", (f, A) => {
  const d = COMPUTED.get(f.eid);
  if (!d) return;
  const h = d.hypotheses[f.index];
  if (!h) return;
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "hypothesis", id: h.id }, "primary");
  h.ranges.forEach((r, i) => A.add({ t: "byteRange", start: r.start, end: r.end }, i === 0 ? "primary" : "contributing"));
  for (const e of h.evidence) if (e.ref) A.add({ t: "byteRange", start: e.ref.start, end: e.ref.end }, "contributing");
  if (h.extra && h.extra.stride) A.add({ t: "stride", n: h.extra.stride }, "contributing");
  // every other open view is context: this is the cross-highlight the whole
  // application exists to provide
  for (const o of S.doc.objects) if (o.eid !== f.eid) addRelatedObject(A, o.eid, "context");
});

registerResolver("signature-hit", (f, A) => {
  const d = COMPUTED.get(f.eid);
  if (!d || !d.rows[f.index]) return;
  const r = d.rows[f.index];
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "byteRange", start: r.offset, end: r.offset + (r.len || 8) - 1 }, "primary");
  A.add({ t: "signature", off: r.offset }, "primary");
});

registerResolver("stride-lag", (f, A) => {
  const d = COMPUTED.get(f.eid);
  if (!d) return;
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "stride", n: f.lag }, "primary");
  // light up the first few spans at this stride so the period is visible
  for (let i = 0; i < 6; i++) A.add({ t: "byteRange", start: i * f.lag, end: (i + 1) * f.lag - 1 }, i === 0 ? "primary" : "contributing");
});

registerResolver("column-field", (f, A) => {
  const d = COMPUTED.get(f.eid);
  if (!d || !d.fields[f.index]) return;
  const fl = d.fields[f.index];
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "column", stride: d.stride, col: fl.start }, "primary");
  A.add({ t: "stride", n: d.stride }, "contributing");
  const n = Math.min(64, d.count);
  for (let r = 0; r < n; r++)
    A.add({ t: "byteRange", start: (d.skip || 0) + r * d.stride + fl.start, end: (d.skip || 0) + r * d.stride + fl.start + fl.len - 1 }, r === 0 ? "primary" : "contributing");
});

registerResolver("segment", (f, A) => {
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "byteRange", start: f.start, end: f.end }, "primary");
});

registerResolver("string-hit", (f, A) => {
  const d = COMPUTED.get(f.eid);
  if (!d || !d.strings[f.index]) return;
  const s = d.strings[f.index];
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "stringAt", start: s.start }, "primary");
  A.add({ t: "byteRange", start: s.start, end: s.end }, "primary");
});

registerResolver("decode-step", (f, A) => {
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "byteRange", start: 0, end: Math.max(0, (COMPUTED.get(f.eid) || { length: 1 }).length - 1) }, "context");
});

registerResolver("digraph-cell", (f, A) => {
  A.add({ t: "object", eid: f.eid }, "primary");
  A.add({ t: "pair", x0: f.a, x1: f.b }, "primary");
  A.add({ t: "byteVal", v: f.a }, "contributing");
  A.add({ t: "byteVal", v: f.b }, "contributing");
});
//#endregion
