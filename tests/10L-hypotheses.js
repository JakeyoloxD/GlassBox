//#region 10L HYPOTHESIS ENGINE
/**
 * The output contract of the whole application.
 *
 * Every other region produces a measurement. This one produces CLAIMS: ranked,
 * confidence-scored statements about what the buffer is, each carrying the
 * evidence that produced it and the byte ranges that support it. A chart tells
 * you the data has a peak at lag 48. A hypothesis tells you it is a 48-byte
 * record format, that 812 records fit exactly, that offset 0 is a u32 counter,
 * and which bytes to look at to disagree.
 *
 * Rules this file holds itself to:
 *   - No hypothesis without at least one piece of evidence.
 *   - No evidence without a byte range or a measured number.
 *   - Confidence is bounded by the weakest link in the chain that produced it.
 *   - A hypothesis derived from decoded bytes says so, and cites the decode.
 */

const HYP = Object.freeze({
  FORMAT: "format", ENCODING: "encoding", RECORD: "record structure", FIELD: "field",
  CRYPTO: "cryptography", REGION: "region", REPEAT: "repetition", STRING: "strings",
  CLASS: "content class"
});

let _hid = 0;
function _hyp(kind, title, confidence, evidence, ranges, extra){
  return {
    id: `H${String(++_hid).padStart(3, "0")}`,
    kind, title,
    confidence: Math.max(0, Math.min(1, confidence)),
    evidence: evidence || [],
    ranges: (ranges || []).slice(0, 256),
    extra: extra || {}
  };
}
function resetHypothesisIds(){ _hid = 0; }

/**
 * Build the hypothesis list.
 *
 * `inputs` is whatever the caller managed to compute; every section is optional
 * so a partial or budget-limited analysis still produces a usable board rather
 * than throwing. Nothing here recomputes: this region reasons over results.
 */
function buildHypotheses(inputs){
  const {
    bytes, format, carved, constants, permutations, stride, columns,
    classification, segments, strings, repeats, ecb, xor, chain
  } = inputs || {};
  const out = [];
  const n = bytes ? bytes.length : 0;
  if (!n) return { hypotheses: [], summary: "No input loaded." };

  const decoded = chain && chain.length > 1;
  const decodeNote = decoded
    ? `after unwrapping ${chain.slice(1).map(c => c.label).join(" then ")}`
    : null;

  /* -- 1. container format ------------------------------------------------ */
  if (format){
    out.push(_hyp(HYP.FORMAT, `Container is ${format.label}`, 0.95,
      [{ text: `magic signature for ${format.label} at offset 0x${format.offset.toString(16).toUpperCase()}`, ref: { start: format.offset, end: format.offset + 3 } }],
      [{ start: format.offset, end: Math.min(n - 1, format.offset + 15), role: "header" }],
      { formatId: format.id, kind: format.kind }));
  }

  /* -- 2. encoding chain -------------------------------------------------- */
  if (decoded){
    const steps = chain.slice(1);
    out.push(_hyp(HYP.ENCODING, `Input is ${steps.map(s => s.label).join(" wrapped in ").split(" wrapped in ").reverse().join(" of ")}`, Math.min(...steps.map(s => s.score)),
      steps.map(s => ({ text: `step ${s.step}: ${s.label} decoded ${s.outLen.toLocaleString()} bytes, confidence ${(s.score * 100).toFixed(0)}%` })),
      [{ start: 0, end: n - 1, role: "whole input" }],
      { steps: steps.map(s => ({ id: s.id, label: s.label, outLen: s.outLen })) }));
  }

  /* -- 3. embedded content ------------------------------------------------ */
  if (carved && carved.hits && carved.hits.length){
    const nonZero = carved.hits.filter(h => h.offset > 0);
    if (nonZero.length){
      const byId = new Map();
      for (const h of nonZero){
        let g = byId.get(h.id);
        if (!g) byId.set(h.id, g = { label: h.label, kind: h.kind, offsets: [] });
        if (g.offsets.length < 64) g.offsets.push(h.offset);
      }
      for (const [id, g] of byId){
        const conf = g.offsets.length > 8 ? 0.55 : 0.8;   // many hits of one type suggests coincidence
        out.push(_hyp(HYP.FORMAT, `Embedded ${g.label} at ${g.offsets.length} offset${g.offsets.length === 1 ? "" : "s"}`, conf,
          g.offsets.slice(0, 8).map(o => ({ text: `${g.label} signature at 0x${o.toString(16).toUpperCase()}`, ref: { start: o, end: o + 7 } })),
          g.offsets.slice(0, 64).map(o => ({ start: o, end: Math.min(n - 1, o + 63), role: "embedded header" })),
          { formatId: id, kind: g.kind, count: g.offsets.length }));
      }
    }
  }

  /* -- 4. cryptographic constants ----------------------------------------- */
  if (constants && constants.algos && constants.algos.length){
    for (const a of constants.algos){
      const hits = constants.hits.filter(h => h.algo === a.algo);
      out.push(_hyp(HYP.CRYPTO, `${a.algo} implementation present`, Math.min(0.97, 0.7 + 0.1 * Math.min(3, a.count)) * a.weight,
        hits.slice(0, 6).map(h => ({ text: `${h.label} matches exactly at 0x${h.offset.toString(16).toUpperCase()} (${h.len} bytes)`, ref: { start: h.offset, end: h.offset + h.len - 1 } })),
        hits.slice(0, 32).map(h => ({ start: h.offset, end: h.offset + h.len - 1, role: h.label })),
        { algo: a.algo, count: a.count, drillable: /AES/.test(a.algo) }));
    }
  }
  if (permutations && permutations.length){
    const novel = permutations.filter(p => !p.identity);
    const known = new Set((constants && constants.hits || []).map(h => h.offset));
    const unknown = novel.filter(p => !known.has(p.offset));
    if (unknown.length){
      out.push(_hyp(HYP.CRYPTO, `${unknown.length} candidate S-box${unknown.length === 1 ? "" : "es"} (256-byte permutation, not a known table)`, 0.6,
        unknown.slice(0, 6).map(p => ({ text: `all 256 byte values appear exactly once starting at 0x${p.offset.toString(16).toUpperCase()}`, ref: { start: p.offset, end: p.offset + 255 } })),
        unknown.slice(0, 16).map(p => ({ start: p.offset, end: p.offset + 255, role: "permutation table" })),
        { offsets: unknown.slice(0, 16).map(p => p.offset), drillable: true }));
    }
  }

  /* -- 5. block cipher mode ----------------------------------------------- */
  if (ecb && ecb.duplicateBlocks >= 2){
    const conf = Math.min(0.93, 0.4 + ecb.ratio * 3);
    out.push(_hyp(HYP.CRYPTO, `Encrypted in electronic codebook mode (ECB), ${ecb.blockSize}-byte blocks`, conf,
      [
        { text: `${ecb.duplicateBlocks} of ${ecb.blocks} aligned ${ecb.blockSize}-byte blocks are duplicates` },
        { text: `${ecb.distinctRepeated} distinct block value${ecb.distinctRepeated === 1 ? "" : "s"} repeats, the most frequent ${ecb.maxRepeat} times` },
        { text: `identical ciphertext blocks mean identical plaintext blocks, which no chaining mode produces` }
      ],
      (ecb.positions[0] ? ecb.positions[0].positions : []).slice(0, 32).map(p => ({ start: p, end: p + ecb.blockSize - 1, role: "repeated block" })),
      { blockSize: ecb.blockSize, ratio: ecb.ratio }));
  }

  /* -- 6. repeating-key XOR ------------------------------------------------ */
  if (xor && xor.confidence > 0.15){
    const printable = [...xor.key].every(k => k >= 32 && k <= 126);
    out.push(_hyp(HYP.CRYPTO, `Repeating-key XOR, ${xor.period}-byte key`, Math.min(0.9, 0.35 + xor.confidence),
      [
        { text: `index of coincidence peaks at period ${xor.period}` },
        { text: `per-column chi-square against an English byte distribution recovers a ${xor.period}-byte key` },
        printable ? { text: `recovered key is printable: "${String.fromCharCode(...xor.key)}"` }
                  : { text: `recovered key: ${[...xor.key].map(k => k.toString(16).padStart(2, "0")).join(" ")}` }
      ],
      [{ start: 0, end: n - 1, role: "ciphertext" }],
      { period: xor.period, key: [...xor.key], printable, actionable: "apply-xor" }));
  }

  /**
   * Text is frequently periodic without being a record format. Log lines,
   * repeated sentences and pretty-printed JSON all produce a strong stride, and
   * calling that "107-byte record structure" at 97% confidence on an English
   * report is a confident wrong answer. Naming it line structure and capping
   * the confidence keeps the finding, which is real, without the false framing.
   */
  const textLike = classification && [ "text", "base64-encoded", "hex-encoded", "utf-16 text" ].includes(classification.label);

  /* -- 7. record structure ------------------------------------------------- */
  if (stride && stride.candidates && stride.candidates.length){
    for (const c of stride.candidates.slice(0, 3)){
      const cols = columns && columns.stride === c.lag ? columns : null;
      let conf = c.score;
      const ev = c.evidence.map(e => ({ text: e.text, estimator: e.estimator, value: e.value }));
      const named = [];
      if (cols && cols.fields.length){
        const strong = cols.fields.filter(f => f.type !== "random" && f.type !== "varying");
        if (strong.length){
          conf = Math.min(0.97, conf * (1 + 0.35 * Math.min(1, cols.structuredRatio * 2)));
          for (const f of strong.slice(0, 8)){
            named.push(f);
            ev.push({ text: `+0x${f.start.toString(16).padStart(2, "0")} is ${f.type}: ${f.detail}`, field: f.start });
          }
        }
      }
      const typed = cols && cols.fields.some(f => ["counter","timestamp","float","enum","length prefix","monotonic integer"].includes(f.type));
      if (textLike && !typed) conf = Math.min(conf, 0.45);
      const label = textLike && !typed
        ? `${c.lag}-byte repeating line structure in text`
        : `${c.lag}-byte record structure${decodeNote ? " " + decodeNote : ""}`;
      out.push(_hyp(HYP.RECORD, label, conf, ev,
        [0, 1, 2, 3].map(i => ({ start: i * c.lag, end: Math.min(n - 1, (i + 1) * c.lag - 1), role: `record ${i}` })),
        { stride: c.lag, records: c.records, remainder: c.remainder, fields: named,
          struct: cols ? cols.structKey : null, drillable: true, actionable: "open-columns" }));
    }
  }

  /* -- 8. individual high-value fields ------------------------------------- */
  if (columns && columns.fields){
    for (const f of columns.fields){
      if (f.type !== "timestamp" && f.type !== "counter") continue;
      out.push(_hyp(HYP.FIELD, `${f.type === "timestamp" ? "Timestamp" : "Sequence counter"} at record offset +0x${f.start.toString(16).padStart(2, "0")}`,
        f.confidence * 0.95,
        f.evidence.map(t => ({ text: t })),
        [0, 1, 2].map(i => ({ start: i * columns.stride + f.start, end: i * columns.stride + f.start + f.len - 1, role: `record ${i} field` })),
        { field: f, stride: columns.stride }));
    }
  }

  /* -- 9. regions ---------------------------------------------------------- */
  if (segments && segments.length > 1){
    for (const s of segments){
      if (s.length < Math.max(256, n * 0.02)) continue;
      out.push(_hyp(HYP.REGION, `${_cap(s.label)} region, 0x${s.start.toString(16).toUpperCase()}-0x${s.end.toString(16).toUpperCase()} (${s.length.toLocaleString()} bytes)`,
        s.confidence * 0.9,
        (s.reasons || []).map(t => ({ text: t })),
        [{ start: s.start, end: s.end, role: s.label }],
        { label: s.label, entropy: s.entropy }));
    }
  } else if (classification){
    out.push(_hyp(HYP.CLASS, `Whole buffer is ${classification.label}`, classification.confidence,
      (classification.reasons || []).map(t => ({ text: t })),
      [{ start: 0, end: n - 1, role: classification.label }],
      { label: classification.label }));
  }

  /* -- 10. repetition ------------------------------------------------------ */
  if (repeats && repeats.rows && repeats.rows.length){
    const r = repeats.rows[0];
    if (r.len >= 16 || r.count >= 4){
      out.push(_hyp(HYP.REPEAT, `Repeated ${r.len}-byte sequence, ${r.count + 1} occurrence${r.count === 0 ? "" : "s"}`,
        Math.min(0.85, 0.35 + r.len / 64),
        [
          { text: `${r.len} identical bytes recur at a distance of ${r.distance}` },
          { text: `first occurrence 0x${(r.positions[0] - r.distance >= 0 ? r.positions[0] - r.distance : r.positions[0]).toString(16).toUpperCase()}` }
        ],
        r.positions.slice(0, 32).map(p => ({ start: p, end: p + r.len - 1, role: "repeat" })),
        { len: r.len, distance: r.distance }));
    }
  }

  /* -- 11. strings --------------------------------------------------------- */
  if (strings && strings.notable && strings.notable.length >= 3){
    out.push(_hyp(HYP.STRING, `${strings.count.toLocaleString()} strings, ${strings.notable.length} notable`, 0.7,
      strings.notable.slice(0, 8).map(s => ({ text: `0x${s.start.toString(16).toUpperCase()} ${s.enc}: ${s.text.slice(0, 72)}`, ref: { start: s.start, end: s.end } })),
      strings.notable.slice(0, 64).map(s => ({ start: s.start, end: s.end, role: "string" })),
      { count: strings.count }));
  }

  /**
   * Structure claimed about a buffer we believe is encrypted is noise. Field
   * typing on repeating-XOR ciphertext produced a "timestamp at +0x18" that is
   * an artefact of the keystream, not of the record format, and pointed the
   * reader at the wrong bytes. Once encryption is asserted with confidence, the
   * honest move is to withdraw the structural claims and say that structure
   * should be re-derived from the plaintext after decrypting.
   */
  const encrypted = out.find(h => h.kind === HYP.CRYPTO && h.confidence >= 0.7 &&
                                  (h.extra.actionable === "apply-xor" || h.extra.blockSize));
  if (encrypted){
    for (let i = out.length - 1; i >= 0; i--){
      const h = out[i];
      if (h.kind === HYP.FIELD){ out.splice(i, 1); continue; }
      if (h.kind === HYP.RECORD){
        h.confidence = Math.min(h.confidence, 0.35);
        h.title = h.title.replace(/record structure/, "periodicity in ciphertext");
        h.evidence = h.evidence.concat([{ text: `structure measured on ciphertext reflects the keystream as much as the plaintext; re-run after decrypting` }]);
      }
    }
  }

  /* -- rank ---------------------------------------------------------------- */
  const KIND_WEIGHT = { [HYP.ENCODING]: 1.18, [HYP.RECORD]: 1.15, [HYP.CRYPTO]: 1.12,
                        [HYP.FORMAT]: 1.08, [HYP.FIELD]: 0.95, [HYP.REGION]: 0.8,
                        [HYP.REPEAT]: 0.75, [HYP.CLASS]: 0.7, [HYP.STRING]: 0.6 };
  for (const h of out) h.rank = h.confidence * (KIND_WEIGHT[h.kind] || 1);
  out.sort((a, b) => b.rank - a.rank);

  return { hypotheses: out, summary: summarise(out, n, decodeNote) };
}

function _cap(s){ return s.charAt(0).toUpperCase() + s.slice(1); }

/** One sentence a person can read before deciding whether to look further. */
function summarise(hyps, n, decodeNote){
  if (!hyps.length) return `${n.toLocaleString()} bytes with no structure detected.`;
  const top = hyps.filter(h => h.confidence >= 0.6).slice(0, 3);
  if (!top.length) return `${n.toLocaleString()} bytes. Nothing detected above 60% confidence; strongest guess is ${hyps[0].title.toLowerCase()}.`;
  const bits = top.map(h => h.title.toLowerCase());
  return `${n.toLocaleString()} bytes${decodeNote ? ", " + decodeNote : ""}: ${bits.join("; ")}.`;
}

/** Flatten every hypothesis range into highlightable atoms for the resolver. */
function hypothesisRanges(h){
  return (h.ranges || []).map(r => ({ t: "byteRange", start: r.start, end: r.end }));
}
//#endregion

module.exports = { HYP, buildHypotheses, summarise, hypothesisRanges, resetHypothesisIds };
