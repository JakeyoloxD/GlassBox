//#region 10I CLASSIFICATION / SEGMENTATION
/* Entropy alone cannot answer the question people actually ask, which is
   "is this compressed or is this encrypted". Both sit near 8 bits per byte.
   The separation comes from what else is true: compressed streams carry
   headers, keep small residual structure, and are rarely a whole multiple of
   16 bytes; encrypted blobs are uniform to the chi-square test, block-aligned,
   and structureless. Neither is guessed from one statistic. */

function byteHistogram(bytes, start = 0, end = bytes.length){
  const c = new Uint32Array(256);
  for (let i = start; i < end; i++) c[bytes[i]]++;
  return c;
}
function entropyFromHist(c, n){
  if (!n) return 0;
  let h = 0;
  for (let i = 0; i < 256; i++) if (c[i]){ const p = c[i] / n; h -= p * Math.log2(p); }
  return h;
}
/**
 * Bias-corrected entropy. The plug-in estimator undershoots by about
 * (K-1)/(2n ln2), which is negligible on a megabyte and decisive on a short
 * buffer: 480 bytes of genuine AES output measure around 7.6 bits rather than
 * 8, slipping under a fixed 7.5 threshold and getting classified as structured
 * binary. Correcting the estimate is more honest than lowering the threshold,
 * which would misclassify real low-entropy data instead.
 */
function entropyCorrected(c, n){
  if (!n) return 0;
  let h = 0, K = 0;
  for (let i = 0; i < 256; i++) if (c[i]){ K++; const p = c[i] / n; h -= p * Math.log2(p); }
  return Math.min(8, h + (K - 1) / (2 * n * Math.LN2));
}
/** Chi-square against a uniform byte distribution. ~255 for true uniform. */
function chiSquareUniform(c, n){
  if (!n) return 0;
  const e = n / 256;
  let x = 0;
  for (let i = 0; i < 256; i++){ const d = c[i] - e; x += d * d / e; }
  return x;
}
/** Monobit and byte-run tests: cheap randomness sanity checks. */
function bitBalance(bytes, start = 0, end = bytes.length){
  let ones = 0;
  for (let i = start; i < end; i++){
    let v = bytes[i];
    v = v - ((v >> 1) & 0x55);
    v = (v & 0x33) + ((v >> 2) & 0x33);
    ones += (v + (v >> 4)) & 0x0F;
  }
  const total = (end - start) * 8;
  return total ? ones / total : 0;
}

const CLASSES = Object.freeze({
  EMPTY: "empty", TEXT: "text", UTF16: "utf-16 text", BASE64: "base64-encoded",
  HEX: "hex-encoded", CODE: "machine code or structured binary", SPARSE: "sparse or padded",
  COMPRESSED: "compressed", ENCRYPTED: "encrypted or high-quality random", UNKNOWN: "unclassified"
});

/**
 * Classify a byte range. Returns a label, a confidence, and the reasons, so a
 * disagreement can be argued with rather than merely disbelieved.
 */
function classifyRange(bytes, start = 0, end = bytes.length, ctx = {}){
  const n = end - start;
  if (n <= 0) return { label: CLASSES.EMPTY, confidence: 1, entropy: 0, chi: 0, reasons: ["zero-length range"] };
  const c = byteHistogram(bytes, start, end);
  const h = entropyCorrected(c, n);
  const chi = chiSquareUniform(c, n);
  const bal = bitBalance(bytes, start, end);
  let distinct = 0, printable = 0, zero = c[0], nulEven = 0, ascii7 = 0;
  for (let v = 0; v < 256; v++){
    if (c[v]) distinct++;
    if (v === 9 || v === 10 || v === 13 || (v >= 32 && v <= 126)) printable += c[v];
    if (v < 128) ascii7 += c[v];
  }
  for (let i = start + 1; i < end; i += 2) if (bytes[i] === 0) nulEven++;
  const pr = printable / n, zr = zero / n, nulRatio = n > 1 ? nulEven / Math.floor(n / 2) : 0;
  const reasons = [];
  const say = t => reasons.push(t);

  if (zr > 0.9){ say(`${(zr * 100).toFixed(1)}% zero bytes`); return { label: CLASSES.SPARSE, confidence: 0.95, entropy: h, chi, reasons }; }

  // UTF-16LE is half NUL by construction, so printability has to be measured
  // over the bytes that are supposed to be printable. Measuring it over all of
  // them caps the ratio at 0.5 and the branch could never fire.
  const nonNul = n - zero;
  const prNonNul = nonNul > 0 ? printable / nonNul : 0;
  if (prNonNul > 0.85 && nulRatio > 0.85 && ascii7 / n > 0.9){
    say(`every second byte is NUL, ${(prNonNul * 100).toFixed(1)}% of the rest printable ASCII`);
    return { label: CLASSES.UTF16, confidence: 0.9, entropy: h, chi, reasons };
  }

  if (pr > 0.95){
    // narrow the text case
    let b64 = 0, hex = 0;
    for (let v = 0; v < 256; v++){
      if (!c[v]) continue;
      const ch = String.fromCharCode(v);
      if (/[A-Za-z0-9+/=\r\n]/.test(ch)) b64 += c[v];
      if (/[0-9a-fA-F\r\n ]/.test(ch)) hex += c[v];
    }
    if (hex / n > 0.995 && distinct <= 24){ say(`${distinct} distinct characters, all hexadecimal`); return { label: CLASSES.HEX, confidence: 0.9, entropy: h, chi, reasons }; }
    if (b64 / n > 0.995 && distinct >= 40){ say(`${distinct} distinct characters, all within the base64 alphabet`); return { label: CLASSES.BASE64, confidence: 0.85, entropy: h, chi, reasons }; }
    say(`${(pr * 100).toFixed(1)}% printable ASCII, entropy ${h.toFixed(2)}`);
    return { label: CLASSES.TEXT, confidence: 0.9, entropy: h, chi, reasons };
  }

  // A recognised container header settles the question outright and must be
  // consulted before any statistical branch. Behind the entropy gate it was
  // unreachable for exactly the streams it was written for: a gzip of highly
  // repetitive text is short, and a short stream plus its 10-byte header
  // measures well under 7.5 bits per byte.
  if (ctx.format && (ctx.format.kind === "compressed" || ctx.format.kind === "archive")){
    say(`range begins with a ${ctx.format.label} header`);
    say(`entropy ${h.toFixed(3)} of 8 bits`);
    return { label: CLASSES.COMPRESSED, confidence: 0.95, entropy: h, chi, reasons };
  }

  // High-entropy fork, sized against what a uniform source of this length could
  // actually achieve. A fixed 7.5 threshold cannot classify short buffers: 480
  // bytes of real AES output peak near 7.6 before correction and land under it,
  // so genuine ciphertext was being reported as structured binary.
  const expectedUniform = 8 - 255 / (2 * n * Math.LN2);
  if (h > Math.min(7.5, expectedUniform - 0.35)){
    const df = 255;
    // for uniform data chi ~ df with sd ~ sqrt(2*df); 3 sd is a generous window
    const uniform = Math.abs(chi - df) < 3 * Math.sqrt(2 * df) * Math.max(1, Math.sqrt(4096 / Math.min(n, 4096)));
    const balanced = Math.abs(bal - 0.5) < 0.01;
    const aligned = n % 16 === 0;
    say(`entropy ${h.toFixed(3)} of 8 bits`);
    say(`chi-square ${chi.toFixed(1)} against 255 expected for uniform bytes`);
    say(`bit balance ${(bal * 100).toFixed(2)}% ones`);
    if (uniform && balanced){
      if (aligned) say(`length ${n} is a whole number of 16-byte blocks`);
      return { label: CLASSES.ENCRYPTED, confidence: aligned ? 0.75 : 0.62, entropy: h, chi, reasons };
    }
    say("byte distribution deviates measurably from uniform, which encryption output does not");
    return { label: CLASSES.COMPRESSED, confidence: 0.6, entropy: h, chi, reasons };
  }

  if (h > 5.5){ say(`entropy ${h.toFixed(2)}, ${distinct} distinct byte values, ${(pr * 100).toFixed(0)}% printable`); return { label: CLASSES.CODE, confidence: 0.5, entropy: h, chi, reasons }; }
  say(`entropy ${h.toFixed(2)} with ${distinct} distinct byte values`);
  return { label: CLASSES.UNKNOWN, confidence: 0.3, entropy: h, chi, reasons };
}

/**
 * Segment the buffer where its character changes.
 *
 * Sliding-window entropy with a threshold produces a boundary every time the
 * curve wobbles. Instead: bin the buffer, then merge adjacent bins whose
 * entropy and printability are close, which is agglomerative and yields
 * boundaries only where the data genuinely changes regime.
 */
function segmentBuffer(bytes, opts = {}){
  const bins = Math.min(opts.bins || 512, Math.max(1, Math.floor(bytes.length / 64)));
  // The empty and very-short cases must still return the full row shape, or a
  // renderer reading .entropy crashes on the boot state before any input.
  if (bins < 2){
    const cls = classifyRange(bytes, 0, bytes.length);
    return [{ start: 0, end: Math.max(0, bytes.length - 1), length: bytes.length,
              entropy: cls.entropy || 0, printable: 0, label: cls.label,
              confidence: cls.confidence, reasons: cls.reasons, chi: cls.chi || 0 }];
  }
  const span = Math.ceil(bytes.length / bins);
  const cells = [];
  for (let b = 0; b < bins; b++){
    const s = b * span, e = Math.min(bytes.length, s + span);
    if (s >= e) break;
    const c = byteHistogram(bytes, s, e);
    const n = e - s;
    let printable = 0;
    for (let v = 0; v < 256; v++) if (v === 9 || v === 10 || v === 13 || (v >= 32 && v <= 126)) printable += c[v];
    cells.push({ start: s, end: e, h: entropyFromHist(c, n), pr: printable / n });
  }
  const hTol = opts.hTol == null ? 0.85 : opts.hTol;
  const pTol = opts.pTol == null ? 0.25 : opts.pTol;
  const merged = [];
  let cur = null;
  for (const cell of cells){
    if (cur && Math.abs(cell.h - cur.h) <= hTol && Math.abs(cell.pr - cur.pr) <= pTol){
      cur.end = cell.end;
      cur.n++;
      cur.h = cur.h + (cell.h - cur.h) / cur.n;
      cur.pr = cur.pr + (cell.pr - cur.pr) / cur.n;
    } else {
      if (cur) merged.push(cur);
      cur = { start: cell.start, end: cell.end, h: cell.h, pr: cell.pr, n: 1 };
    }
  }
  if (cur) merged.push(cur);

  /**
   * Absorb slivers into whichever neighbour they most resemble.
   *
   * A bin that straddles a regime boundary matches neither side and survives as
   * its own segment: the reference fixture produced a spurious 65-byte
   * "unclassified" band at every single transition, three of them, each one an
   * artefact of binning rather than a feature of the data. Folding a short
   * segment into the closer neighbour in (entropy, printability) removes them
   * without inventing a threshold.
   */
  const minLen = opts.minLen == null ? Math.max(128, span * 3) : opts.minLen;
  let out = merged;
  for (let guard = 0; guard < 64; guard++){
    let worst = -1, worstLen = Infinity;
    for (let i = 0; i < out.length; i++){
      const len = out[i].end - out[i].start;
      if (len < minLen && len < worstLen && out.length > 1){ worst = i; worstLen = len; }
    }
    if (worst < 0) break;
    const prev = out[worst - 1], next = out[worst + 1], m = out[worst];
    const dist = o => o ? Math.abs(o.h - m.h) + Math.abs(o.pr - m.pr) * 4 : Infinity;
    const target = dist(prev) <= dist(next) ? prev : next;
    target.start = Math.min(target.start, m.start);
    target.end = Math.max(target.end, m.end);
    out = out.filter((_, i) => i !== worst);
  }
  return out.map(m => {
    const cls = classifyRange(bytes, m.start, m.end);
    return { start: m.start, end: m.end - 1, length: m.end - m.start, entropy: m.h, printable: m.pr,
             label: cls.label, confidence: cls.confidence, reasons: cls.reasons, chi: cls.chi };
  });
}
//#endregion

//#region 10J STRINGS
/* Offsets are the whole point. A string list without positions is grep; a
   string list with positions cross-highlights into every other view. */
function extractStrings(bytes, opts = {}){
  const min = opts.min == null ? 6 : opts.min;
  const limit = opts.limit == null ? 4096 : opts.limit;
  const out = [];
  const n = bytes.length;

  // ASCII
  let s = -1;
  for (let i = 0; i <= n; i++){
    const v = i < n ? bytes[i] : 0;
    const ok = i < n && (v === 9 || (v >= 32 && v <= 126));
    if (ok){ if (s < 0) s = i; continue; }
    if (s >= 0 && i - s >= min){
      out.push({ start: s, end: i - 1, len: i - s, enc: "ascii", text: _str(bytes, s, i, 1) });
      if (out.length >= limit) return _finish(out, opts);
    }
    s = -1;
  }

  // UTF-16LE
  s = -1;
  for (let i = 0; i + 1 <= n; i += 2){
    const v = bytes[i], hi = bytes[i + 1];
    const ok = hi === 0 && (v === 9 || (v >= 32 && v <= 126));
    if (ok){ if (s < 0) s = i; continue; }
    if (s >= 0 && (i - s) / 2 >= min){
      out.push({ start: s, end: i - 1, len: (i - s) / 2, enc: "utf-16le", text: _str(bytes, s, i, 2) });
      if (out.length >= limit) return _finish(out, opts);
    }
    s = -1;
  }
  return _finish(out, opts);
}
function _str(bytes, a, b, step){
  let s = "";
  for (let i = a; i < b; i += step) s += String.fromCharCode(bytes[i]);
  return s.length > 512 ? s.slice(0, 512) + "\u2026" : s;
}
function _finish(out, opts){
  out.sort((a, b) => a.start - b.start);
  // interesting strings first for display, positions retained for highlighting
  // Random bytes throw off short accidental ASCII runs by the thousand. A
  // notable string is one that looks authored: a URL, a path, an address, or a
  // long run containing real word separators.
  const notable = out.filter(x =>
    /^(https?:|ftp:|\/[a-z]|[A-Za-z]:\\|[\w.-]+@[\w.-]+\.\w+|\d+\.\d+\.\d+\.\d+)/.test(x.text) ||
    (x.len >= 16 && /[ ._-]/.test(x.text) && /[aeiouAEIOU]/.test(x.text)));
  return { strings: out, count: out.length, notable: notable.slice(0, 128), truncated: out.length >= (opts.limit || 4096) };
}
//#endregion

//#region 10K DIGRAPH / SPACE-FILLING
/**
 * Byte-pair scatter. The single highest information-per-pixel view of an
 * unknown buffer: text collapses into a few dense bands, base64 into a tight
 * lattice, x86 into a distinctive smear along the low rows, compressed data
 * into uniform fog with visible structure, and encrypted data into featureless
 * uniform fog. Shape is recognisable long before any statistic is convincing.
 */
function digraphMatrix(bytes, opts = {}){
  const m = new Uint32Array(65536);
  const cap = opts.sample || 4194304;
  const n = Math.min(bytes.length, cap);
  for (let i = 0; i + 1 < n; i++) m[(bytes[i] << 8) | bytes[i + 1]]++;
  let max = 0, occupied = 0;
  for (let i = 0; i < 65536; i++){ const v = m[i]; if (v){ occupied++; if (v > max) max = v; } }
  return { m, max, occupied, coverage: occupied / 65536, n };
}

/** Hilbert d -> (x,y). Locality-preserving, so a contiguous region of the file
 *  renders as a compact blob rather than a set of unrelated scanlines. */
function hilbertXY(d, order){
  const nSide = 1 << order;
  let rx, ry, t = d, x = 0, y = 0;
  for (let s = 1; s < nSide; s <<= 1){
    rx = 1 & (t >> 1);
    ry = 1 & (t ^ rx);
    if (ry === 0){
      if (rx === 1){ x = s - 1 - x; y = s - 1 - y; }
      const tmp = x; x = y; y = tmp;
    }
    x += s * rx; y += s * ry;
    t >>= 2;
  }
  return { x, y };
}

/** Build a Hilbert-ordered class map: each cell is a byte span, coloured by
 *  what that span IS rather than by its mean value. */
function hilbertMap(bytes, opts = {}){
  const order = opts.order == null ? 7 : Math.max(3, Math.min(9, opts.order));  // 2^order per side
  const side = 1 << order, cells = side * side;
  const span = Math.max(1, Math.ceil(bytes.length / cells));
  const used = Math.min(cells, Math.ceil(bytes.length / span));
  const cellEntropy = new Float32Array(used);
  const cellPrint = new Float32Array(used);
  const cellMean = new Uint8Array(used);
  const xs = new Uint16Array(used), ys = new Uint16Array(used);
  const c = new Uint32Array(256);
  const touch = new Uint16Array(256);
  for (let i = 0; i < used; i++){
    const s = i * span, e = Math.min(bytes.length, s + span);
    let tn = 0, sum = 0, pr = 0;
    for (let k = s; k < e; k++){
      const v = bytes[k];
      if (c[v] === 0) touch[tn++] = v;
      c[v]++; sum += v;
      if (v === 9 || v === 10 || v === 13 || (v >= 32 && v <= 126)) pr++;
    }
    const m = e - s;
    let h = 0;
    for (let t = 0; t < tn; t++){ const p = c[touch[t]] / m; h -= p * Math.log2(p); c[touch[t]] = 0; }
    cellEntropy[i] = m > 1 ? h / Math.log2(Math.min(m, 256)) * 8 : 0;
    cellPrint[i] = pr / m;
    cellMean[i] = Math.round(sum / m);
    const p = hilbertXY(i, order);
    xs[i] = p.x; ys[i] = p.y;
  }
  return { order, side, span, used, xs, ys, cellEntropy, cellPrint, cellMean, length: bytes.length };
}
//#endregion

module.exports = { CLASSES, byteHistogram, entropyFromHist, entropyCorrected, chiSquareUniform, bitBalance,
  classifyRange, segmentBuffer, extractStrings, digraphMatrix, hilbertXY, hilbertMap };
