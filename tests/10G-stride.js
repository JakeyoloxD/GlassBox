//#region 10G PERIOD / STRIDE
/* The central question of structure discovery: does this buffer repeat, and at
   what interval? Three independent estimators, deliberately not averaged - they
   detect different things and disagreeing is informative.

     equality autocorrelation  record layout, struct stride, image row pitch
     index of coincidence      repeating-key XOR, classical periodicity
     column dispersion         fixed fields, the estimator that survives noise

   All three run on a sampled window so cost is bounded regardless of input. */

const STRIDE_DEFAULTS = Object.freeze({
  minLag: 2,
  maxLag: 1024,
  sampleBytes: 262144,     // window used to REFINE a candidate lag
  coarseBytes: 32768,      // window used to SWEEP every lag
  refineTop: 48,           // how many swept peaks get the full window
  topK: 12
});

/** Sampling window. Skips a leading header if one was identified upstream. */
function strideWindow(bytes, opts = {}){
  const cap = opts.sampleBytes || STRIDE_DEFAULTS.sampleBytes;
  const skip = opts.skip || 0;
  const start = Math.min(skip, Math.max(0, bytes.length - 1));
  const end = Math.min(bytes.length, start + cap);
  return bytes.subarray(start, end);
}

/**
 * Equality autocorrelation.
 *
 * r(L) = P(b[i] == b[i+L]) normalised against the buffer's own coincidence
 * floor. Using byte-equality rather than the numeric product matters: numeric
 * autocorrelation on byte VALUES is dominated by the DC term and by any slow
 * ramp in the data, and reports lag 1 for almost everything. Equality is
 * scale-free and reports the interval at which the same symbol recurs, which
 * is what a record boundary actually is.
 */
function equalityAutocorrelation(bytes, opts = {}){
  const o = Object.assign({}, STRIDE_DEFAULTS, opts);
  const w = strideWindow(bytes, o);
  const n = w.length;
  const maxLag = Math.min(o.maxLag, Math.floor(n / 4));
  if (n < 16 || maxLag < o.minLag) return { n, lags: new Float32Array(0), minLag: o.minLag, floor: 0 };

  // coincidence floor: probability two random positions share a value
  const counts = new Uint32Array(256);
  for (let i = 0; i < n; i++) counts[w[i]]++;
  let sq = 0;
  for (let v = 0; v < 256; v++) sq += counts[v] * counts[v];
  const floor = sq / (n * n);

  const lags = new Float32Array(maxLag + 1);
  for (let L = o.minLag; L <= maxLag; L++){
    let eq = 0;
    const lim = n - L;
    for (let i = 0; i < lim; i++) if (w[i] === w[i + L]) eq++;
    const p = eq / lim;
    // excess coincidence over chance, normalised so 1.0 means perfectly periodic
    lags[L] = floor >= 1 ? 0 : (p - floor) / (1 - floor);
  }
  return { n, lags, minLag: o.minLag, maxLag, floor };
}

/**
 * Index of coincidence per stride. Classical Friedman: split into `s` columns
 * and average the per-column IoC. A repeating-key XOR of English text spikes
 * hard at the true key length and its multiples.
 */
function iocByStride(bytes, opts = {}){
  const o = Object.assign({}, STRIDE_DEFAULTS, opts);
  const w = strideWindow(bytes, o);
  const n = w.length;
  const maxLag = Math.min(o.maxLag, Math.floor(n / 8));
  const out = new Float32Array(maxLag + 1);
  if (n < 32) return { ioc: out, maxLag: 0, n };
  // Sparse histogram reset. Clearing all 256 slots per column costs
  // 256*s operations per stride, which dominates the whole sweep at high
  // strides where a column holds only a few dozen samples. Touch-list reset
  // makes the clear proportional to the data, not to the alphabet.
  const counts = new Uint32Array(256);
  const touched = new Uint8Array(256);
  const touchList = new Uint16Array(256);
  for (let s = o.minLag; s <= maxLag; s++){
    let acc = 0, cols = 0;
    for (let c = 0; c < s; c++){
      let m = 0, tn = 0;
      for (let i = c; i < n; i += s){
        const v = w[i];
        if (!touched[v]){ touched[v] = 1; touchList[tn++] = v; }
        counts[v]++; m++;
      }
      if (m >= 2){
        let sum = 0;
        for (let t = 0; t < tn; t++){ const cnt = counts[touchList[t]]; if (cnt > 1) sum += cnt * (cnt - 1); }
        acc += sum / (m * (m - 1));
        cols++;
      }
      for (let t = 0; t < tn; t++){ counts[touchList[t]] = 0; touched[touchList[t]] = 0; }
    }
    out[s] = cols ? acc / cols : 0;
  }
  return { ioc: out, maxLag, n };
}

/**
 * Column dispersion. At stride s, how much lower is the mean per-column entropy
 * than the whole-buffer entropy? Constant and enum fields collapse their
 * column's entropy to near zero; payload columns do not. This is the estimator
 * that finds record structure in data where autocorrelation is flat, e.g. a log
 * of 64-byte records whose payloads are all different.
 *
 * BIAS CORRECTION IS NOT OPTIONAL HERE. A column at stride s holds only n/s
 * samples, and the plug-in entropy estimator is biased downward by roughly
 * (K-1)/(2m ln2) for m samples over K observed symbols. That bias grows with
 * the stride, so the uncorrected estimator reported a smooth upward ramp of
 * "dispersion" against lag and confidently identified a 64-byte record format
 * as an 800-byte one, purely because 800 leaves fewer samples per column.
 * Miller-Madow removes the ramp and leaves only real field structure.
 */
function columnDispersion(bytes, opts = {}){
  const o = Object.assign({}, STRIDE_DEFAULTS, opts);
  const w = strideWindow(bytes, o);
  const n = w.length;
  const maxLag = Math.min(o.maxLag, Math.floor(n / 8));
  const out = new Float32Array(maxLag + 1);
  if (n < 64) return { disp: out, maxLag: 0, n, whole: 0 };
  const whole = _entropyCorrected(w, 0, n, 1);
  if (whole <= 0.01) return { disp: out, maxLag, n, whole };
  const counts = new Uint32Array(256);
  const touched = new Uint8Array(256);
  const touchList = new Uint16Array(256);
  const LN2 = Math.LN2;
  for (let s = o.minLag; s <= maxLag; s++){
    if (Math.floor(n / s) < 8){ out[s] = 0; continue; }
    let acc = 0;
    for (let c = 0; c < s; c++){
      let m = 0, tn = 0;
      for (let i = c; i < n; i += s){
        const v = w[i];
        if (!touched[v]){ touched[v] = 1; touchList[tn++] = v; }
        counts[v]++; m++;
      }
      let h = 0;
      for (let t = 0; t < tn; t++){ const p = counts[touchList[t]] / m; h -= p * Math.log2(p); }
      acc += h + (tn - 1) / (2 * m * LN2);
      for (let t = 0; t < tn; t++){ counts[touchList[t]] = 0; touched[touchList[t]] = 0; }
    }
    const mean = acc / s;
    out[s] = Math.max(0, (whole - mean) / whole);
  }
  return { disp: out, maxLag, n, whole };
}

function _entropyCorrected(b, start, end, step){
  const c = new Uint32Array(256);
  let m = 0;
  for (let i = start; i < end; i += step){ c[b[i]]++; m++; }
  if (!m) return 0;
  let h = 0, K = 0;
  for (let v = 0; v < 256; v++) if (c[v]){ K++; const p = c[v] / m; h -= p * Math.log2(p); }
  return h + (K - 1) / (2 * m * Math.LN2);
}

function _entropy(b, start, end, step){
  const c = new Uint32Array(256);
  let m = 0;
  for (let i = start; i < end; i += step){ c[b[i]]++; m++; }
  if (!m) return 0;
  let h = 0;
  for (let v = 0; v < 256; v++) if (c[v]){ const p = c[v] / m; h -= p * Math.log2(p); }
  return h;
}

/** Local maxima that stand clear of their neighbourhood, not every bump. */
function _peaks(arr, minLag, maxLag, minValue){
  const out = [];
  for (let L = Math.max(minLag, 1) + 1; L < maxLag; L++){
    const v = arr[L];
    if (v < minValue) continue;
    if (v <= arr[L - 1] || v < arr[L + 1]) continue;
    out.push({ lag: L, value: v });
  }
  return out.sort((a, b) => b.value - a.value);
}

/**
 * Prefer the fundamental over its harmonics.
 *
 * A buffer of 48-byte records is equally periodic at 96, 480 and 768, and the
 * harmonics routinely score identically because every estimator here saturates
 * on strongly periodic data. The first implementation walked the score-sorted
 * list and only compared against already-kept entries, which made the result
 * depend on insertion order and reported lag 768 for a 48-byte record format.
 * Divisibility is a property of the candidate set, not of the iteration, so the
 * test must run against every candidate: a lag is a harmonic if ANY strictly
 * smaller candidate divides it and retains most of its strength.
 */
function _fundamental(cands){
  const kept = [];
  for (const c of cands){
    let harmonicOf = null;
    for (const k of cands){
      if (k.lag >= c.lag) continue;
      if (c.lag % k.lag !== 0) continue;
      if (k.score >= c.score * 0.6){ harmonicOf = k.lag; break; }
    }
    if (harmonicOf){ c.harmonicOf = harmonicOf; continue; }
    kept.push(c);
  }
  return kept;
}

/**
 * Combined stride analysis. Returns ranked candidates with the evidence that
 * produced each one, never a bare number: a stride with no attribution cannot
 * be argued with, and arguing with it is the entire point of the tool.
 */
function analyseStride(bytes, opts = {}){
  const o = Object.assign({}, STRIDE_DEFAULTS, opts);
  // Stage 1: sweep every lag on a small window. Sweeping the full window costs
  // O(window * maxLag) three times over and put a 2 MB input at 3.4 seconds,
  // which is not an interactive tool. Peak POSITIONS are stable at a fraction
  // of the samples; only peak VALUES need the long window, and only at the few
  // dozen lags that survive the sweep.
  const coarse = { sampleBytes: Math.min(o.sampleBytes, o.coarseBytes) };
  const ac = equalityAutocorrelation(bytes, Object.assign({}, o, coarse));
  const io = iocByStride(bytes, Object.assign({}, o, coarse));
  const cd = columnDispersion(bytes, Object.assign({}, o, coarse));
  const maxLag = Math.min(ac.maxLag || 0, cd.maxLag || Infinity, io.maxLag || Infinity);
  if (!maxLag || maxLag < o.minLag) {
    return { candidates: [], ac, ioc: io, disp: cd, n: ac.n, maxLag: 0 };
  }

  const acPeaks = _peaks(ac.lags, o.minLag, maxLag, 0.02);
  const iocBase = _median(io.ioc, o.minLag, maxLag);
  const iocPeaks = _peaks(io.ioc, o.minLag, maxLag, iocBase * 1.35);
  const dispPeaks = _peaks(cd.disp, o.minLag, maxLag, 0.05);

  const byLag = new Map();
  const bump = (lag, key, value) => {
    let e = byLag.get(lag);
    if (!e) byLag.set(lag, e = { lag, ac: 0, ioc: 0, disp: 0, evidence: [] });
    e[key] = value;
  };
  acPeaks.slice(0, 40).forEach(p => bump(p.lag, "ac", p.value));
  iocPeaks.slice(0, 40).forEach(p => bump(p.lag, "ioc", p.value));
  dispPeaks.slice(0, 40).forEach(p => bump(p.lag, "disp", p.value));

  // Stage 2: re-measure the survivors on the full window.
  const survivors = [...byLag.values()].sort((a, b) => (b.ac + b.disp) - (a.ac + a.disp)).slice(0, o.refineTop);
  if (bytes.length > (coarse.sampleBytes || 0)){
    for (const e of survivors){
      const r = refineLag(bytes, e.lag, o);
      if (e.ac > 0) e.ac = r.ac;
      if (e.disp > 0) e.disp = r.disp;
      if (e.ioc > 0) e.ioc = r.ioc;
      e.refined = true;
    }
  }

  const total = bytes.length;
  const cands = [];
  for (const e of survivors){
    const records = Math.floor(ac.n / e.lag);
    if (records < 4) continue;
    const remainder = total % e.lag;
    const iocLift = iocBase > 0 ? (e.ioc / iocBase - 1) : 0;
    // weights: autocorrelation is the strongest single signal, dispersion the
    // most robust to high-entropy payloads, IoC the most specific to key reuse
    let score = 0.55 * Math.min(1, e.ac / 0.35)
              + 0.30 * Math.min(1, e.disp / 0.30)
              + 0.15 * Math.min(1, iocLift / 1.5);
    const agree = (e.ac > 0 ? 1 : 0) + (e.disp > 0 ? 1 : 0) + (e.ioc > 0 ? 1 : 0);
    if (agree >= 2) score *= 1.25;                   // independent estimators concur
    const hs = _harmonicSupport(ac.lags, e.lag, maxLag);
    const hsRel = e.ac > 0 ? Math.min(1, hs / e.ac) : 0;
    score *= 0.72 + 0.42 * hsRel;                    // isolated peaks are demoted
    if (remainder === 0 && total >= e.lag * 4) score *= 1.12;   // divides the buffer exactly
    if (e.lag % 4 === 0) score *= 1.04;              // machine structures tend to align
    score = Math.min(1, score);
    if (score < 0.08) continue;
    const evidence = [];
    if (e.ac > 0)  evidence.push({ estimator: "equality autocorrelation", value: e.ac, text: `coincidence at lag ${e.lag} exceeds chance by ${(e.ac * 100).toFixed(1)}%` });
    if (e.disp > 0) evidence.push({ estimator: "column dispersion", value: e.disp, text: `per-column entropy ${(e.disp * 100).toFixed(1)}% below whole-buffer entropy` });
    if (e.ioc > 0) evidence.push({ estimator: "index of coincidence", value: e.ioc, text: `IoC ${e.ioc.toFixed(4)} against baseline ${iocBase.toFixed(4)}` });
    if (hs > 0) evidence.push({ estimator: "harmonic support", value: hsRel, text: `response also present at ${e.lag * 2} and ${e.lag * 3}, ${(hsRel * 100).toFixed(0)}% of the fundamental` });
    evidence.push({ estimator: "coverage", value: records, text: `${records} whole spans in the analysed window, remainder ${remainder} byte${remainder === 1 ? "" : "s"}` });
    cands.push({ lag: e.lag, score, records, remainder, ac: e.ac, disp: e.disp, ioc: e.ioc, agree, harmonicSupport: hsRel, evidence });
  }
  cands.sort((a, b) => (b.score - a.score) || (a.lag - b.lag));
  const fundamental = _fundamental(cands);
  return { candidates: fundamental.slice(0, o.topK), all: cands.slice(0, 64), ac, ioc: io, disp: cd, iocBase, n: ac.n, maxLag };
}

/**
 * Harmonic support. A real fundamental stride L leaves a response at 2L, 3L and
 * 4L as well; an isolated spurious peak does not. Borrowed from pitch detection,
 * where the identical problem is called octave error.
 */
function _harmonicSupport(arr, lag, maxLag){
  let sum = 0, k = 0;
  for (let h = 2; h <= 4; h++){
    const L = lag * h;
    if (L > maxLag) break;
    sum += Math.max(0, arr[L]); k++;
  }
  return k ? sum / k : 0;
}

/** Exact measurement of one lag on the full analysis window. */
function refineLag(bytes, lag, opts = {}){
  const o = Object.assign({}, STRIDE_DEFAULTS, opts);
  const w = strideWindow(bytes, o);
  const n = w.length;
  if (n < lag * 4) return { ac: 0, ioc: 0, disp: 0 };

  const counts = new Uint32Array(256);
  for (let i = 0; i < n; i++) counts[w[i]]++;
  let sq = 0;
  for (let v = 0; v < 256; v++) sq += counts[v] * counts[v];
  const floor = sq / (n * n);
  let eq = 0;
  const lim = n - lag;
  for (let i = 0; i < lim; i++) if (w[i] === w[i + lag]) eq++;
  const ac = floor >= 1 ? 0 : ((eq / lim) - floor) / (1 - floor);

  const whole = _entropyCorrected(w, 0, n, 1);
  const touched = new Uint8Array(256), touchList = new Uint16Array(256);
  const c2 = new Uint32Array(256);
  let hAcc = 0, iocAcc = 0, cols = 0;
  for (let c = 0; c < lag; c++){
    let m = 0, tn = 0;
    for (let i = c; i < n; i += lag){
      const v = w[i];
      if (!touched[v]){ touched[v] = 1; touchList[tn++] = v; }
      c2[v]++; m++;
    }
    if (m >= 2){
      let h = 0, sum = 0;
      for (let t = 0; t < tn; t++){
        const cnt = c2[touchList[t]], p = cnt / m;
        h -= p * Math.log2(p);
        if (cnt > 1) sum += cnt * (cnt - 1);
      }
      hAcc += h + (tn - 1) / (2 * m * Math.LN2);
      iocAcc += sum / (m * (m - 1));
      cols++;
    }
    for (let t = 0; t < tn; t++){ c2[touchList[t]] = 0; touched[touchList[t]] = 0; }
  }
  const disp = whole > 0.01 && cols ? Math.max(0, (whole - hAcc / cols) / whole) : 0;
  return { ac, ioc: cols ? iocAcc / cols : 0, disp, n };
}

function _median(arr, lo, hi){
  const v = [];
  for (let i = lo; i <= hi; i++) v.push(arr[i]);
  if (!v.length) return 0;
  v.sort((a, b) => a - b);
  return v[v.length >> 1];
}

/**
 * Repeating-XOR key recovery for a known period.
 * Chi-squared against an expected byte distribution, per column.
 */
const ENGLISH_FREQ = (() => {
  const f = new Float64Array(256).fill(0.00005);
  const letters = { e:12.02,t:9.10,a:8.12,o:7.68,i:7.31,n:6.95,s:6.28,r:6.02,h:5.92,d:4.32,l:3.98,u:2.88,c:2.71,m:2.61,f:2.30,y:2.11,w:2.09,g:2.03,p:1.82,b:1.49,v:1.11,k:0.69,x:0.17,q:0.11,j:0.10,z:0.07 };
  let total = 0;
  for (const k in letters) total += letters[k];
  for (const k in letters){
    const p = letters[k] / total * 0.78;
    f[k.charCodeAt(0)] = p;
    f[k.toUpperCase().charCodeAt(0)] = p * 0.08;
  }
  f[32] = 0.17; f[10] = 0.01; f[13] = 0.004; f[46] = 0.008; f[44] = 0.008;
  let s = 0;
  for (let i = 0; i < 256; i++) s += f[i];
  for (let i = 0; i < 256; i++) f[i] /= s;
  return f;
})();

function recoverXorKey(bytes, period, expected = ENGLISH_FREQ){
  if (period < 1 || period > 512 || bytes.length < period * 4) return null;
  const key = new Uint8Array(period);
  const conf = new Float64Array(period);
  const counts = new Uint32Array(256);
  for (let c = 0; c < period; c++){
    counts.fill(0);
    let m = 0;
    for (let i = c; i < bytes.length; i += period){ counts[bytes[i]]++; m++; }
    let bestK = 0, bestChi = Infinity, secondChi = Infinity;
    for (let k = 0; k < 256; k++){
      let chi = 0;
      for (let v = 0; v < 256; v++){
        const e = expected[v ^ k] * m;
        const d = counts[v] - e;
        chi += d * d / (e + 1e-9);
      }
      if (chi < bestChi){ secondChi = bestChi; bestChi = chi; bestK = k; }
      else if (chi < secondChi) secondChi = chi;
    }
    key[c] = bestK;
    conf[c] = secondChi > 0 && Number.isFinite(secondChi) ? Math.min(1, 1 - bestChi / secondChi) : 0;
  }
  let mean = 0;
  for (let i = 0; i < period; i++) mean += conf[i];
  return { key, confidence: mean / period, period };
}

/**
 * Repeating-XOR search that validates itself.
 *
 * Taking the period from the top overall stride candidate does not work: on
 * XOR-encrypted English the strongest periodicity is the plaintext's own
 * sentence length beaten against the key, not the key length, so the real
 * 8-byte key was never even tried. This searches short periods on their own
 * terms via index-of-coincidence lift, then accepts a period ONLY if the
 * recovered key actually decrypts the buffer to something readable. A key that
 * does not produce plaintext is not a key.
 */
function searchXor(bytes, opts = {}){
  const maxPeriod = Math.min(opts.maxPeriod || 64, Math.floor(bytes.length / 16));
  if (maxPeriod < 2) return null;
  const io = iocByStride(bytes, { minLag: 1, maxLag: maxPeriod, sampleBytes: opts.sampleBytes || 131072 });
  const base = _median(io.ioc, 2, maxPeriod);
  const ranked = [];
  for (let s = 1; s <= maxPeriod; s++) if (io.ioc[s] > base * 1.25) ranked.push({ period: s, ioc: io.ioc[s] });
  ranked.sort((a, b) => b.ioc - a.ioc);

  /**
   * Acceptance needs a test that plaintext passes and ciphertext fails, and
   * "is it printable" is not that test. XOR of English against a word-shaped
   * key is largely printable already, so a printability gate upstream skipped
   * the search entirely and the 8-byte key was never tried. Word-separator
   * frequency is the discriminator: natural language runs 8-25% spaces, and
   * XOR against anything scrambles that ratio out of the band. A candidate is
   * accepted only if decryption moves the buffer INTO the band, which also
   * refuses the degenerate all-zero key on input that was plaintext already.
   */
  const spaceBand = buf => {
    let sp = 0, pr = 0;
    for (let i = 0; i < buf.length; i++){
      const v = buf[i];
      if (v === 32) sp++;
      if (v === 9 || v === 10 || v === 13 || (v >= 32 && v <= 126)) pr++;
    }
    const ratio = buf.length ? sp / buf.length : 0;
    return { ok: ratio >= 0.08 && ratio <= 0.25 && pr / buf.length > 0.95, ratio, printable: pr / buf.length };
  };
  const head = bytes.subarray(0, Math.min(bytes.length, 8192));
  if (spaceBand(head).ok) return null;                 // already plaintext

  // Prefer the smallest period that works: a key of length k also explains 2k.
  const tried = ranked.slice(0, 12).map(r => r.period).filter(p => p >= 2).sort((a, b) => a - b);
  for (const period of tried){
    const rec = recoverXorKey(bytes, period);
    if (!rec) continue;
    if ([...rec.key].every(k => k === 0)) continue;
    const test = applyXor(head, rec.key);
    const sb = spaceBand(test);
    if (sb.ok){
      return { key: rec.key, period, confidence: Math.min(0.95, 0.5 + sb.printable * 0.45),
               printableAfter: sb.printable, spaceRatio: sb.ratio,
               iocLift: base > 0 ? io.ioc[period] / base : 0 };
    }
  }
  return null;
}

function applyXor(bytes, key){
  const out = new Uint8Array(bytes.length);
  const k = key.length;
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % k];
  return out;
}

/**
 * Block-cipher ECB detection. Duplicate aligned blocks in otherwise
 * high-entropy data is the single cleanest crypto tell there is.
 */
function detectEcb(bytes, blockSize = 16, opts = {}){
  const n = bytes.length;
  const blocks = Math.floor(n / blockSize);
  if (blocks < 4) return null;
  /**
   * Duplicate aligned blocks only mean ECB if the block CONTENT could be
   * ciphertext. English prose, JSON and source code are full of repeated
   * 16-byte runs, and ungated this detector announced "electronic codebook
   * mode" at 93% confidence on a plain-text assessment report.
   *
   * The gate cannot be a fixed entropy floor, which was the first attempt: the
   * duplication that defines ECB is itself what drags the measured entropy
   * down, so a genuine 192-byte ECB sample with eight identical blocks scored
   * 5.9 bits and was rejected by the very property it was detecting. Two
   * corrections make the test sound. Entropy is measured over the DISTINCT
   * blocks, removing the self-inflicted penalty, and it is compared against the
   * entropy a uniform source of that same size would actually produce rather
   * than against 8, which no short sample can reach.
   */
  const bs = blockSize;
  const distinctBlocks = new Map();
  for (let b = 0; b < blocks; b++){
    const p0 = b * bs;
    let sig = "";
    for (let j = 0; j < bs; j++) sig += bytes[p0 + j].toString(16).padStart(2, "0");
    if (!distinctBlocks.has(sig)) distinctBlocks.set(sig, p0);
  }
  const uniq = [...distinctBlocks.values()];
  const un = uniq.length * bs;
  const c = new Uint32Array(256);
  for (const p0 of uniq) for (let j = 0; j < bs; j++) c[bytes[p0 + j]]++;
  let h = 0, K = 0;
  for (let v = 0; v < 256; v++) if (c[v]){ K++; const pr = c[v] / un; h -= pr * Math.log2(pr); }
  h += (K - 1) / (2 * un * Math.LN2);
  const expectedUniform = 8 - 255 / (2 * un * Math.LN2);
  const margin = opts.margin == null ? 0.6 : opts.margin;
  if (h < expectedUniform - margin) return null;

  const seen = new Map();
  let dupes = 0, maxRun = 0;
  for (let b = 0; b < blocks; b++){
    const p = b * blockSize;
    let sig = "";
    for (let j = 0; j < blockSize; j++) sig += bytes[p + j].toString(16).padStart(2, "0");
    let e = seen.get(sig);
    if (!e) seen.set(sig, e = { count: 0, first: p, positions: [] });
    e.count++;
    if (e.positions.length < 32) e.positions.push(p);
    if (e.count > 1){ dupes++; if (e.count > maxRun) maxRun = e.count; }
  }
  if (!dupes) return null;
  const repeated = [...seen.values()].filter(e => e.count > 1).sort((a, b) => b.count - a.count);
  return {
    blockSize,
    entropy: h,
    blocks,
    duplicateBlocks: dupes,
    distinctRepeated: repeated.length,
    ratio: dupes / blocks,
    maxRepeat: maxRun,
    positions: repeated.slice(0, 12).map(e => ({ count: e.count, positions: e.positions }))
  };
}

/**
 * Unaligned longest repeated substrings via rolling-hash seeding then
 * extension. A suffix array would be exact; this is O(n) with a bounded table
 * and finds every repeat above the seed length, which is what matters when the
 * question is "does anything in here repeat at all".
 */
function findRepeats(bytes, opts = {}){
  const seed = opts.seed == null ? 8 : opts.seed;
  const limit = opts.limit == null ? 64 : opts.limit;
  const maxCells = opts.maxCells == null ? 1 << 20 : opts.maxCells;
  const n = bytes.length;
  if (n < seed * 2) return { rows: [], seed, sampled: false };
  const step = Math.max(1, Math.ceil((n - seed) / maxCells));
  const table = new Map();
  const MOD = 0x7FFFFFFF, BASE = 257;
  let pow = 1;
  for (let i = 1; i < seed; i++) pow = (pow * BASE) % MOD;
  let h = 0;
  for (let i = 0; i < seed; i++) h = (h * BASE + bytes[i]) % MOD;
  const rows = [];
  const claimed = new Uint8Array(n);
  const push = (a, b) => {
    // extend the match both ways
    let s = 0;
    while (a + seed + s < n && b + seed + s < n && bytes[a + seed + s] === bytes[b + seed + s]) s++;
    let p = 0;
    while (a - p - 1 >= 0 && b - p - 1 >= 0 && bytes[a - p - 1] === bytes[b - p - 1] && b - p - 1 > a) p++;
    const start = a - p, len = seed + s + p;
    if (b - start < len) return;                    // overlapping self-match
    return { start, other: b - p, len };
  };
  for (let i = 0; i + seed <= n; i++){
    if (i){
      h = (h - bytes[i - 1] * pow % MOD + MOD * BASE) % MOD;
      h = (h * BASE + bytes[i + seed - 1]) % MOD;
    }
    if (i % step) continue;
    const prev = table.get(h);
    if (prev === undefined){ table.set(h, i); continue; }
    if (claimed[i]) continue;
    // verify: rolling hashes collide
    let equal = true;
    for (let j = 0; j < seed; j++) if (bytes[prev + j] !== bytes[i + j]){ equal = false; break; }
    if (!equal) continue;
    const m = push(prev, i);
    if (!m) continue;
    for (let j = 0; j < m.len && m.other + j < n; j++) claimed[m.other + j] = 1;
    rows.push({ start: m.start, at: m.other, len: m.len, distance: m.other - m.start });
    if (rows.length >= limit * 4) break;
  }
  // group by (len, distance) so a periodic buffer reports one finding not 10000
  const groups = new Map();
  for (const r of rows){
    const k = r.len + ":" + r.distance;
    let g = groups.get(k);
    if (!g) groups.set(k, g = { len: r.len, distance: r.distance, count: 0, positions: [] });
    g.count++;
    if (g.positions.length < 32) g.positions.push(r.at);
  }
  const out = [...groups.values()].sort((a, b) => (b.len * b.count) - (a.len * a.count));
  return { rows: out.slice(0, limit), total: out.length, seed, sampled: step > 1, step };
}
//#endregion

module.exports = { STRIDE_DEFAULTS, refineLag, searchXor, equalityAutocorrelation, iocByStride, columnDispersion,
  analyseStride, recoverXorKey, applyXor, detectEcb, findRepeats, ENGLISH_FREQ };
