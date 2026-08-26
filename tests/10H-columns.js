//#region 10H COLUMN TYPING
/* Knowing the stride is half the answer. This is the other half: given a stride,
   what is each column FOR? Output is a field layout with a named type, a width,
   an endianness where one applies, and the evidence for each call.

   Deliberately conservative. A wrong "u32 little-endian timestamp" is worse
   than an honest "constant 0x01", because the first sends you looking for a
   date and the second sends you looking at the next column. Every classifier
   here refuses rather than guesses when its own test is marginal. */

const COLUMN_LIMITS = Object.freeze({
  maxStride: 4096,
  maxRecords: 65536,
  minRecords: 6
});

/** Slice the buffer into records at `stride`, capped for cost. */
function sliceRecords(bytes, stride, opts = {}){
  const max = opts.maxRecords || COLUMN_LIMITS.maxRecords;
  const skip = opts.skip || 0;
  const usable = bytes.length - skip;
  const count = Math.min(max, Math.floor(usable / stride));
  return { count, stride, skip, remainder: usable - count * stride };
}

function _colStats(bytes, stride, col, count, skip){
  const counts = new Uint32Array(256);
  let min = 255, max = 0, sum = 0;
  for (let r = 0; r < count; r++){
    const v = bytes[skip + r * stride + col];
    counts[v]++; sum += v;
    if (v < min) min = v;
    if (v > max) max = v;
  }
  let distinct = 0, h = 0;
  for (let v = 0; v < 256; v++) if (counts[v]){ distinct++; const p = counts[v] / count; h -= p * Math.log2(p); }
  return { counts, distinct, min, max, mean: sum / count, entropy: h };
}

function _readUint(bytes, off, width, little){
  let v = 0;
  if (little){ for (let i = width - 1; i >= 0; i--) v = v * 256 + bytes[off + i]; }
  else { for (let i = 0; i < width; i++) v = v * 256 + bytes[off + i]; }
  return v;
}

/**
 * Read a width-8 integer as an exact (hi, lo) pair. Number loses precision
 * above 2^53, so a u64 column read into a double compares wrongly and either
 * invents or destroys monotonicity depending on which bits fell off.
 */
function _readU64(bytes, off, little){
  if (little) return { hi: _readUint(bytes, off + 4, 4, true), lo: _readUint(bytes, off, 4, true) };
  return { hi: _readUint(bytes, off, 4, false), lo: _readUint(bytes, off + 4, 4, false) };
}
function _cmp64(a, b){ return a.hi !== b.hi ? (a.hi < b.hi ? -1 : 1) : (a.lo === b.lo ? 0 : a.lo < b.lo ? -1 : 1); }

/** Monotone integer test across records at a given width and endianness. */
function _monotone(bytes, stride, col, width, little, count, skip){
  if (col + width > stride) return null;
  let up = 0, down = 0, same = 0, prev = null;
  const deltas = [];
  const wide = width === 8;
  for (let r = 0; r < count; r++){
    const off = skip + r * stride + col;
    const v = wide ? _readU64(bytes, off, little) : _readUint(bytes, off, width, little);
    if (prev !== null){
      if (wide){
        const c = _cmp64(prev, v);
        if (c < 0) up++; else if (c > 0) down++; else same++;
        if (deltas.length < 4096) deltas.push(prev.hi === v.hi ? v.lo - prev.lo : NaN);
      } else {
        const d = v - prev;
        if (d > 0) up++; else if (d < 0) down++; else same++;
        if (deltas.length < 4096) deltas.push(d);
      }
    }
    prev = v;
  }
  const n = up + down + same;
  if (!n) return null;
  const dir = up >= down ? "increasing" : "decreasing";
  const agree = Math.max(up, down) / n;
  let constDelta = null;
  if (deltas.length){
    const first = deltas[0];
    constDelta = (Number.isFinite(first) && deltas.every(d => d === first)) ? first : null;
  }
  return { dir, agree, up, down, same, constDelta, width, little };
}

const _NOW = 1767225600;                      // 2026-01-01, used only as a range anchor
const TS_LO = 631152000;                      // 1990-01-01
const TS_HI = 2145916800;                     // 2038-01-01

function _timestampFit(bytes, stride, col, count, skip){
  const out = [];
  for (const [width, little, scale, label] of [
    [4, true,  1,    "unix seconds (u32 LE)"],
    [4, false, 1,    "unix seconds (u32 BE)"],
    [8, true,  1000, "unix milliseconds (u64 LE)"],
    [8, false, 1000, "unix milliseconds (u64 BE)"]
  ]){
    if (col + width > stride) continue;
    let inRange = 0, spread = 0, min = Infinity, max = -Infinity;
    for (let r = 0; r < count; r++){
      const raw = _readUint(bytes, skip + r * stride + col, width, little);
      const t = raw / scale;
      if (t >= TS_LO && t <= TS_HI){ inRange++; if (t < min) min = t; if (t > max) max = t; }
    }
    const ratio = inRange / count;
    if (ratio > 0.95 && Number.isFinite(min)){
      spread = max - min;
      // a real timestamp column varies; a constant that happens to sit in range is not one
      if (spread > 0) out.push({ label, width, little, scale, ratio, min, max, spread });
    }
  }
  out.sort((a, b) => b.ratio - a.ratio || a.spread - b.spread);
  return out[0] || null;
}

/**
 * Float detection needs a discriminator sharper than "is finite and not absurd",
 * because a run of unrelated bytes clears that bar embarrassingly often. The
 * exponent field is the discriminator: real measurements from one source cluster
 * into a handful of binary exponents, while arbitrary bytes scatter across the
 * whole exponent range. Without this the f64 column in the reference layout lost
 * to a proposal describing its four constant low mantissa bytes.
 */
function _floatFit(bytes, stride, col, count, skip, width, little){
  if (col + width > stride) return null;
  const buf = new ArrayBuffer(8), dv = new DataView(buf), u8 = new Uint8Array(buf);
  let finite = 0, sane = 0, zeros = 0;
  const exps = new Set();
  for (let r = 0; r < count; r++){
    const off = skip + r * stride + col;
    for (let i = 0; i < width; i++) u8[i] = bytes[off + i];
    const v = width === 4 ? dv.getFloat32(0, little) : dv.getFloat64(0, little);
    if (!Number.isFinite(v)) continue;
    finite++;
    const a = Math.abs(v);
    if (a === 0){ zeros++; sane++; exps.add(-999); continue; }
    if (a > 1e-6 && a < 1e12){ sane++; if (exps.size <= 64) exps.add(Math.floor(Math.log2(a))); }
  }
  const ratio = sane / count;
  if (ratio <= 0.97 || finite !== count || zeros >= count * 0.9) return null;
  const coherent = exps.size <= Math.max(4, Math.min(16, count / 32));
  return { width, little, ratio, exponents: exps.size, coherent };
}

function _asciiness(counts, count){
  let printable = 0, alnum = 0, space = 0, zero = 0;
  for (let v = 0; v < 256; v++){
    const c = counts[v];
    if (!c) continue;
    if (v === 0) zero += c;
    if (v === 32) space += c;
    if (v === 9 || v === 10 || v === 13 || (v >= 32 && v <= 126)) printable += c;
    if ((v >= 48 && v <= 57) || (v >= 65 && v <= 90) || (v >= 97 && v <= 122)) alnum += c;
  }
  return { printable: printable / count, alnum: alnum / count, space: space / count, zero: zero / count };
}

/**
 * Classify every column at a stride, then merge adjacent columns that belong to
 * the same multi-byte field. Merging is the step that turns four "counter-ish"
 * byte columns into one u32; without it the output is a per-byte readout that
 * nobody can act on.
 */
function analyseColumns(bytes, stride, opts = {}){
  if (!Number.isInteger(stride) || stride < 1 || stride > COLUMN_LIMITS.maxStride) throw new Error("bad stride");
  const { count, skip, remainder } = sliceRecords(bytes, stride, opts);
  if (count < COLUMN_LIMITS.minRecords) return { stride, count, columns: [], fields: [], insufficient: true };

  const cols = [];
  for (let c = 0; c < stride; c++){
    const st = _colStats(bytes, stride, c, count, skip);
    const asc = _asciiness(st.counts, count);
    cols.push({ col: c, ...st, ascii: asc, counts: undefined, hist: st.counts });
  }

  // --- byte-level classification -----------------------------------------
  for (const c of cols){
    if (c.distinct === 1){
      c.type = "constant";
      c.detail = `0x${c.min.toString(16).toUpperCase().padStart(2, "0")}`;
      c.confidence = 1;
      c.evidence = [`all ${count} records hold the same value`];
    } else if (c.distinct <= 8 && count >= 20){
      const vals = [];
      for (let v = 0; v < 256; v++) if (c.hist[v]) vals.push(v);
      c.type = "enum";
      c.detail = vals.map(v => "0x" + v.toString(16).toUpperCase().padStart(2, "0")).join(" ");
      c.confidence = 0.85;
      c.evidence = [`only ${c.distinct} distinct values across ${count} records`];
    } else if (c.ascii.printable > 0.97){
      c.type = "text";
      c.detail = c.ascii.alnum > 0.8 ? "alphanumeric" : "printable";
      c.confidence = 0.8;
      c.evidence = [`${(c.ascii.printable * 100).toFixed(1)}% printable ASCII`];
    } else if (c.entropy > 7.4) {
      c.type = "random";
      c.detail = `entropy ${c.entropy.toFixed(2)}/8`;
      c.confidence = 0.7;
      c.evidence = [`per-column entropy ${c.entropy.toFixed(2)} of 8 bits`];
    } else {
      c.type = "varying";
      c.detail = `${c.distinct} distinct`;
      c.confidence = 0.3;
      c.evidence = [`${c.distinct} distinct values, entropy ${c.entropy.toFixed(2)}`];
    }
  }

  // --- field proposals, scored, then resolved by competition --------------
  /**
   * Detectors used to claim their bytes in a fixed order, first come first
   * served. That is wrong twice over. It is order-dependent, so whichever
   * detector happened to run first won regardless of how weak its evidence was;
   * and it had no notion of alignment, so a u32 read at +0x03 whose four bytes
   * straddle a counter and a timestamp passed the "looks like a unix date"
   * range test and claimed bytes 3..6, destroying both real fields behind it.
   * On the reference 40-byte layout this misidentified seven of ten fields.
   *
   * Proposals now compete. Each carries a score combining how specific the
   * claim is, how strong its own evidence is, how many bytes it explains, and
   * whether it sits on a natural boundary. Non-overlapping winners are taken in
   * score order, which is weighted interval scheduling and is why an aligned
   * u32 counter at +0x00 now beats a misaligned u32 timestamp at +0x03.
   */
  const SPECIFICITY = { constant: 1.0, counter: 0.96, text: 0.86, enum: 0.82,
                        "monotonic integer": 0.7, timestamp: 0.68, float: 0.5,
                        "length prefix": 0.42, random: 0.55, varying: 0.2 };
  /**
   * The least significant byte of a genuinely varying integer must itself vary.
   * Without this rule a u32 read across a constant 0x01, a 4-valued enum and two
   * bytes of the ASCII tag "EV" produced values inside the 1990-2038 window for
   * every single record and claimed a 100%-confidence timestamp at +0x08,
   * flattening three real fields. Checking the low byte costs nothing and kills
   * the entire class of false numeric fields built out of constant material.
   */
  function lsbVaries(start, width, little){
    const lsb = little ? start : start + width - 1;
    return cols[lsb] && cols[lsb].distinct > 2;
  }

  /**
   * Natural alignment is a property of machine word widths, not of any length
   * that happens to divide its own offset. Awarding the full bonus whenever
   * start % len === 0 handed +0.28 to a ten-byte constant run at offset 10 and
   * let it outrank the f64 it was partly made of.
   */
  const _alignBonus = (start, len) => {
    if (len < 2) return 0;
    if (len === 2 || len === 4 || len === 8) return start % len === 0 ? 0.28 : start % 2 === 0 ? -0.06 : -0.32;
    return start % 4 === 0 ? 0.12 : start % 2 === 0 ? -0.06 : -0.32;
  };

  const props = [];
  function propose(p){
    const align = _alignBonus(p.start, p.len);
    p.score = (SPECIFICITY[p.type] || 0.3) * 0.6 + p.confidence * 0.4 + align
            + Math.min(0.16, p.len * 0.02) + (p.bonus || 0);
    props.push(p);
  }

  for (let c = 0; c < stride; c++){
    /**
     * Printable ASCII read as a big-endian-ish u32 spans 0x20202020 to
     * 0x7E7E7E7E, which is 1994 to 2038 in unix seconds. The plausible-date
     * window and the printable-character window are very nearly the same
     * interval, so ANY four bytes of text pass the timestamp range test: plain
     * English prose reported four separate timestamp fields at 93% confidence.
     * A timestamp whose every byte is printable is text.
     */
    const ts = _timestampFit(bytes, stride, c, count, skip);
    const allPrintable = ts && cols.slice(c, c + ts.width).every(x => x.ascii && x.ascii.printable > 0.95);
    if (ts && !allPrintable && lsbVaries(c, ts.width, ts.little)) propose({
      start: c, len: ts.width, type: "timestamp", detail: ts.label, confidence: ts.ratio,
      evidence: [
        `${(ts.ratio * 100).toFixed(1)}% of values fall in 1990-2038 when read as ${ts.label}`,
        `range spans ${Math.round(ts.spread)} seconds across ${count} records`
      ],
      extra: { min: ts.min, max: ts.max, little: ts.little, width: ts.width }
    });
  }

  for (const width of [8, 4, 2]){
    for (let c = 0; c + width <= stride; c++){
      let best = null;
      for (const little of [true, false]){
        if (!lsbVaries(c, width, little)) continue;
        const m = _monotone(bytes, stride, c, width, little, count, skip);
        if (!m || m.agree < 0.97 || m.same > count * 0.5) continue;
        const sc = m.agree + (m.constDelta !== null ? 0.5 : 0);
        if (!best || sc > best.sc) best = { m, little, sc };
      }
      if (best){
        const m = best.m;
        propose({
          start: c, len: width,
          type: m.constDelta !== null ? "counter" : "monotonic integer",
          detail: `u${width * 8} ${best.little ? "little" : "big"}-endian${m.constDelta !== null ? `, step ${m.constDelta}` : `, ${m.dir}`}`,
          confidence: m.constDelta !== null ? 0.95 : 0.72,
          evidence: [
            `${(m.agree * 100).toFixed(1)}% of consecutive records move ${m.dir}`,
            m.constDelta !== null ? `every step is exactly ${m.constDelta}` : `${m.up} up, ${m.down} down, ${m.same} unchanged`
          ],
          extra: { width, little: best.little, constDelta: m.constDelta }
        });
      }

      if (width <= 4){
        for (const little of [true, false]){
          if (!lsbVaries(c, width, little)) continue;
          let hits = 0;
          for (let r = 0; r < count; r++){
            const v = _readUint(bytes, skip + r * stride + c, width, little);
            if (v > 0 && v <= stride - c - width) hits++;
          }
          if (hits / count > 0.97 && cols.slice(c, c + width).some(x => x.distinct > 2)){
            propose({
              start: c, len: width, type: "length prefix",
              detail: `u${width * 8} ${little ? "little" : "big"}-endian, always within the record`,
              confidence: 0.55,
              evidence: [`${(hits / count * 100).toFixed(1)}% of values are a valid in-record length`],
              extra: { width, little }
            });
            break;
          }
        }
      }

      /**
       * A float is not made out of a text tag. Once absorption freed the bytes
       * around the timestamp, an f32 read across the constant 0x02, the 5-value
       * enum and the letters "LO" of "LOGREC" passed every numeric test and
       * swallowed two real fields. Two or more invariant printable bytes in the
       * span means the span is text that happens to decode, not a float.
       */
      const constPrintable = cols.slice(c, c + width).filter(x => x.distinct === 1 && x.min >= 32 && x.min <= 126).length;
      if (width >= 4 && constPrintable < 2 && cols.slice(c, c + width).some(x => x.distinct > 1)){
        // A field that is byte-for-byte identical in every record is a constant,
        // whatever it decodes to. Four bytes of the ASCII tag "ENT:" reinterpret
        // as a perfectly finite, perfectly exponent-coherent f32 and outscored
        // the six-byte text field they were carved out of.
        const f = _floatFit(bytes, stride, c, count, skip, width, true) || _floatFit(bytes, stride, c, count, skip, width, false);
        if (f) propose({
          start: c, len: width, type: "float",
          detail: `f${width * 8} ${f.little ? "little" : "big"}-endian`,
          confidence: f.coherent ? 0.5 + 0.45 * f.ratio : 0.35 * f.ratio,
          bonus: f.coherent ? 0.25 : 0,
          evidence: [
            `${(f.ratio * 100).toFixed(1)}% of values decode to finite floats in a plausible magnitude range`,
            f.coherent ? `values occupy only ${f.exponents} distinct binary exponents, consistent with one measurement source`
                       : `values scatter across ${f.exponents} binary exponents, weak evidence`
          ],
          extra: { width, little: f.little, exponents: f.exponents, coherent: f.coherent }
        });
      }
    }
  }

  /**
   * Byte-level runs compete on the same footing. A byte that is literally
   * identical in every record is the strongest statement available about that
   * offset, and it must be able to outrank a probabilistic float fit.
   *
   * Factored into a helper because remainders produced later by absorption need
   * exactly the same treatment. When they did not get it, the leftover span
   * 10..19 of a straddling run was proposed as one 10-byte constant and buried
   * the 6-byte tag "EVENT:" that the split had already recovered once.
   */
  function proposeRun(i, j, mk){
    const run = cols.slice(i, j), len = j - i;
    const allConst = run.every(x => x.distinct === 1);
    if (allConst){
      const printable = run.every(x => x.min >= 32 && x.min <= 126);
      const txt = printable ? run.map(x => String.fromCharCode(x.min)).join("") : null;
      mk({
        start: i, len, type: printable && len >= 2 ? "text" : "constant",
        detail: printable && len >= 2 ? `constant "${txt}"` : run.map(x => x.detail).join(" "),
        confidence: 1,
        evidence: [`${len} byte${len === 1 ? "" : "s"} identical across all ${count} records`],
        extra: printable ? { text: txt, constant: true } : { constant: true }
      });
      // A constant run is not necessarily one field: an ASCII tag sitting
      // against the invariant low mantissa bytes of an f64 is two.
      if (!printable){
        let k = i;
        while (k < j){
          if (!(cols[k].min >= 32 && cols[k].min <= 126)){ k++; continue; }
          let m = k;
          while (m < j && cols[m].min >= 32 && cols[m].min <= 126) m++;
          if (m - k >= 2){
            const sub = cols.slice(k, m).map(x => String.fromCharCode(x.min)).join("");
            mk({ start: k, len: m - k, type: "text", detail: `constant "${sub}"`, confidence: 1,
                 evidence: [`${m - k} printable bytes identical across all ${count} records`],
                 extra: { text: sub, constant: true } });
          }
          k = m;
        }
      }
    } else {
      mk({
        start: i, len, type: run[0].type,
        detail: run[0].type === "text" ? `${len}-byte ${run[0].detail} field` : run[0].detail,
        confidence: run[0].confidence,
        evidence: run[0].evidence,
        extra: { meanEntropy: run.reduce((a, x) => a + x.entropy, 0) / len }
      });
    }
  }
  {
    let i = 0;
    while (i < stride){
      const t = cols[i].type;
      let j = i;
      while (j < stride && cols[j].type === t) j++;
      proposeRun(i, j, propose);
      i = j;
    }
  }

  /**
   * Resolution. Weighted interval scheduling with one extra rule: a proposal
   * that is strictly inside a comparably strong longer proposal is a fragment
   * of it, not a rival, and must stand aside so the longer field can claim the
   * whole span. Two constant high bytes of a u32 counter scored fractionally
   * above the counter and split it in half without this.
   *
   * The rule cannot be applied as a pre-filter, which was the first attempt.
   * Suppressing every fragment whose container merely EXISTS discards fields
   * whose container is later blocked by something stronger elsewhere: the
   * 6-byte tag "EVENT:" was dropped in favour of an f64 spanning 10..17 that
   * then lost bytes 16..17 to the real f64 and never claimed anything, leaving
   * the tag shredded. Deferral is therefore conditional on the container still
   * being able to claim its full span at the moment the fragment is considered.
   */
  props.sort((a, b) => b.score - a.score || b.len - a.len || a.start - b.start);
  const byStart = new Map();
  for (const p of props){
    let arr = byStart.get(p.start);
    if (!arr) byStart.set(p.start, arr = []);
    arr.push(p);
  }
  const taken = new Uint8Array(stride);
  const fields = [];
  const free = p => { for (let i = 0; i < p.len; i++) if (taken[p.start + i]) return false; return true; };
  const claim = p => { for (let i = 0; i < p.len; i++) taken[p.start + i] = 1; fields.push(p); };
  const containerFor = p => {
    // a container cannot begin more than 7 bytes to the left: 8 is the widest field
    for (let s0 = Math.max(0, p.start - 7); s0 <= p.start; s0++){
      const arr = byStart.get(s0);
      if (!arr) continue;
      for (const q of arr){
        if (q === p || q.len <= p.len) continue;
        if (q.start + q.len < p.start + p.len) continue;
        if (q.score < p.score - 0.15) continue;
        if (free(q)) return q;
      }
    }
    return null;
  };
  /**
   * Absorption. A wide integer whose high bytes never change looks, to the byte
   * classifier, like a narrow integer sitting next to a constant run. A u32
   * timestamp of 1710000000+11i over 900 records only ever moves its low two
   * bytes, so a u16 counter at +0x04 plus a 3-byte constant at +0x06 scored
   * above the u32 that spans both and split a real field in half. Containment
   * does not catch this: the constant run is BESIDE the narrow read, not inside
   * it. The rule that does catch it is that a numeric proposal covering a
   * strict superset of another numeric proposal's bytes, whose remaining bytes
   * are all constant, explains strictly more of the record and wins.
   */
  const NUMERIC = new Set(["counter", "monotonic integer", "timestamp", "float", "length prefix"]);
  const isConstantByte = i => cols[i] && cols[i].distinct === 1;
  const absorbs = (wide, narrow) => {
    if (!NUMERIC.has(wide.type) || !NUMERIC.has(narrow.type)) return false;
    if (wide.len <= narrow.len) return false;
    if (wide.start > narrow.start || wide.start + wide.len < narrow.start + narrow.len) return false;
    for (let i = wide.start; i < wide.start + wide.len; i++){
      if (i >= narrow.start && i < narrow.start + narrow.len) continue;
      if (!isConstantByte(i)) return false;
    }
    return true;
  };
  const extra = [];
  for (const wide of props){
    if (!NUMERIC.has(wide.type)) continue;
    let absorbedAny = false;
    for (const narrow of props){
      if (narrow === wide) continue;
      if (absorbs(wide, narrow)){
        absorbedAny = true;
        wide.score = Math.max(wide.score, narrow.score + 0.02);
        wide.evidence = wide.evidence.concat([
          `bytes +0x${(narrow.start + narrow.len).toString(16)}..+0x${(wide.start + wide.len - 1).toString(16)} never change, consistent with the high bytes of a u${wide.len * 8}`
        ]);
      }
    }
    if (!absorbedAny) continue;
    wide.absorbed = true;
    /**
     * The constant run does not sit inside the wide field, it STRADDLES its
     * edge: bytes +0x06..+0x08 are the timestamp's two invariant high bytes
     * plus one genuinely separate constant field, and as a single 3-byte run
     * they outscored the u32 by 0.024 and split it. Marking the straddling run
     * for deferral, and proposing the part of it that lies outside the numeric
     * field in its own right, lets both fields be recovered intact.
     */
    for (const run of props){
      if (run === wide || NUMERIC.has(run.type)) continue;
      const oS = Math.max(run.start, wide.start), oE = Math.min(run.start + run.len, wide.start + wide.len);
      if (oE <= oS) continue;                                   // no overlap
      if (run.start >= wide.start && run.start + run.len <= wide.start + wide.len) continue;  // wholly inside: containment handles it
      run.deferTo = wide;
      for (const [rs, re] of [[run.start, oS], [oE, run.start + run.len]]){
        if (re - rs < 1) continue;
        proposeRun(rs, re, q => extra.push(Object.assign({ score: 0 }, q)));
      }
    }
  }
  for (const e of extra){
    e.score = (SPECIFICITY[e.type] || 0.3) * 0.6 + e.confidence * 0.4
            + _alignBonus(e.start, e.len) + Math.min(0.16, e.len * 0.02);
    props.push(e);
  }
  props.sort((a, b) => b.score - a.score || b.len - a.len || a.start - b.start);

  const deferred = [];
  for (const p of props){
    if (!free(p)) continue;
    if (p.deferTo && free(p.deferTo)){ deferred.push(p); continue; }
    if (containerFor(p)){ deferred.push(p); continue; }
    claim(p);
  }
  for (const p of deferred) if (free(p)) claim(p);

  // Anything no proposal covered falls back to its byte classification.
  {
    let i = 0;
    while (i < stride){
      if (taken[i]){ i++; continue; }
      const t = cols[i].type;
      let j = i;
      while (j < stride && !taken[j] && cols[j].type === t) j++;
      fields.push({ start: i, len: j - i, type: t, detail: cols[i].detail,
                    confidence: cols[i].confidence, evidence: cols[i].evidence, extra: {} });
      for (let k = i; k < j; k++) taken[k] = 1;
      i = j;
    }
  }

  /**
   * A monotone u32 stepping by a constant that also lands inside the plausible
   * unix window is both a counter and a timestamp, and saying only one of those
   * throws away the more actionable half. The step and the date both survive.
   */
  for (const f of fields){
    if (f.type !== "counter" && f.type !== "monotonic integer") continue;
    const ts = props.find(p => p.type === "timestamp" && p.start === f.start && p.len === f.len);
    if (!ts) continue;
    f.type = "timestamp";
    f.detail = `${ts.detail}, ${f.detail}`;
    f.confidence = Math.max(f.confidence, ts.confidence) * 0.98;
    f.evidence = f.evidence.concat(ts.evidence);
    f.extra = Object.assign({}, f.extra, ts.extra);
  }

  fields.sort((a, b) => a.start - b.start);

  const structured = fields.filter(f => f.type !== "random" && f.type !== "varying")
                           .reduce((a, f) => a + f.len, 0);
  return {
    stride, count, skip, remainder,
    columns: cols.map(c => ({ col: c.col, distinct: c.distinct, entropy: c.entropy, min: c.min, max: c.max, mean: c.mean, type: c.type, printable: c.ascii.printable })),
    fields,
    structuredBytes: structured,
    structuredRatio: structured / stride
  };
}

/** Compact one-line struct rendering, C-ish, for the inspector and the report. */
function fieldsToStruct(res, name = "record"){
  const lines = [`struct ${name} {           // stride ${res.stride}, ${res.count} records`];
  for (const f of res.fields){
    const ty = f.type === "counter" || f.type === "monotonic integer" || f.type === "length prefix"
      ? `uint${(f.extra && f.extra.width ? f.extra.width : f.len) * 8}_t`
      : f.type === "timestamp" ? `uint${(f.extra.width) * 8}_t`
      : f.type === "float" ? (f.extra.width === 8 ? "double" : "float")
      : f.type === "text" ? `char[${f.len}]`
      : `uint8_t[${f.len}]`;
    const nm = f.type.replace(/[^a-z]+/gi, "_").toLowerCase() + "_" + f.start.toString(16);
    lines.push(`  ${ty.padEnd(12)} ${nm.padEnd(22)} // +0x${f.start.toString(16).padStart(2, "0")}  ${f.detail}`);
  }
  lines.push("};");
  return lines.join("\n");
}
//#endregion

module.exports = { COLUMN_LIMITS, sliceRecords, analyseColumns, fieldsToStruct };
