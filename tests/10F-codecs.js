//#region 10F CODECS / DECODE LADDER
/* Pure, synchronous, allocation-conscious. No network, no async, no streams.
   Every decoder returns null on refusal rather than throwing, so the ladder can
   score candidates cheaply without try/catch in the hot path. */

const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32_RFC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function _revTable(alpha){
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < alpha.length; i++) t[alpha.charCodeAt(i)] = i;
  return t;
}
const RT_B64 = _revTable(B64_STD), RT_B64U = _revTable(B64_URL), RT_B32 = _revTable(B32_RFC), RT_B58 = _revTable(B58_BTC);

function isWs(c){ return c === 9 || c === 10 || c === 13 || c === 32; }

/** Strip whitespace in place-ish. Returns a compacted copy only if needed. */
function stripWs(bytes){
  let n = 0;
  for (let i = 0; i < bytes.length; i++) if (isWs(bytes[i])) n++;
  if (!n) return bytes;
  const out = new Uint8Array(bytes.length - n);
  let j = 0;
  for (let i = 0; i < bytes.length; i++) if (!isWs(bytes[i])) out[j++] = bytes[i];
  return out;
}

/* ---------- base64 / base64url ------------------------------------------- */
function decodeBase64(bytes, rt = RT_B64){
  const s = stripWs(bytes);
  let len = s.length;
  while (len > 0 && s[len - 1] === 61) len--;          // '='
  if (len < 4) return null;
  const rem = len & 3;
  if (rem === 1) return null;
  const out = new Uint8Array(((len * 3) >> 2));
  let acc = 0, bits = 0, o = 0;
  for (let i = 0; i < len; i++){
    const v = rt[s[i]];
    if (v < 0) return null;
    acc = (acc << 6) | v; bits += 6;
    if (bits >= 8){ bits -= 8; out[o++] = (acc >> bits) & 255; }
  }
  return out.subarray(0, o);
}

/* ---------- base32 -------------------------------------------------------- */
function decodeBase32(bytes){
  const s = stripWs(bytes);
  let len = s.length;
  while (len > 0 && s[len - 1] === 61) len--;
  if (len < 8) return null;
  const out = new Uint8Array(Math.floor(len * 5 / 8));
  let acc = 0, bits = 0, o = 0;
  for (let i = 0; i < len; i++){
    let c = s[i];
    if (c >= 97 && c <= 122) c -= 32;                   // accept lowercase
    const v = RT_B32[c];
    if (v < 0) return null;
    acc = (acc << 5) | v; bits += 5;
    if (bits >= 8){ bits -= 8; out[o++] = (acc >> bits) & 255; }
  }
  return out.subarray(0, o);
}

/* ---------- base58 (bitcoin alphabet, big-integer style) ------------------ */
function decodeBase58(bytes){
  const s = stripWs(bytes);
  if (!s.length || s.length > 4096) return null;
  const size = Math.ceil(s.length * 733 / 1000) + 1;    // log(58)/log(256)
  const buf = new Uint8Array(size);
  let length = 0, zeros = 0;
  while (zeros < s.length && s[zeros] === 49) zeros++;   // leading '1'
  for (let i = zeros; i < s.length; i++){
    const v = RT_B58[s[i]];
    if (v < 0) return null;
    let carry = v, j = 0;
    for (let k = size - 1; k >= 0 && (carry !== 0 || j < length); k--, j++){
      carry += 58 * buf[k];
      buf[k] = carry & 255;
      carry >>= 8;
    }
    length = j;
  }
  const out = new Uint8Array(zeros + length);
  out.set(buf.subarray(size - length), zeros);
  return out;
}

/* ---------- hex ----------------------------------------------------------- */
function decodeHex(bytes){
  const s = stripWs(bytes);
  // tolerate 0x prefix and separators already removed by stripWs
  let start = 0;
  if (s.length > 2 && s[0] === 48 && (s[1] === 120 || s[1] === 88)) start = 2;
  const n = s.length - start;
  if (n < 4 || (n & 1)) return null;
  const out = new Uint8Array(n >> 1);
  for (let i = 0; i < n; i += 2){
    const hi = _hexVal(s[start + i]), lo = _hexVal(s[start + i + 1]);
    if (hi < 0 || lo < 0) return null;
    out[i >> 1] = (hi << 4) | lo;
  }
  return out;
}
function _hexVal(c){
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 97 && c <= 102) return c - 87;
  if (c >= 65 && c <= 70) return c - 55;
  return -1;
}

/* ---------- ascii85 (btoa/Adobe) ----------------------------------------- */
function decodeAscii85(bytes){
  const s = stripWs(bytes);
  let i = 0, end = s.length;
  if (s[0] === 60 && s[1] === 126){ i = 2; }             // <~
  if (end >= 2 && s[end - 2] === 126 && s[end - 1] === 62) end -= 2;
  const out = [];
  let tuple = 0, count = 0;
  for (; i < end; i++){
    const c = s[i];
    if (c === 122 && count === 0){ out.push(0, 0, 0, 0); continue; }  // 'z'
    if (c < 33 || c > 117) return null;
    tuple = tuple * 85 + (c - 33); count++;
    if (count === 5){
      out.push((tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255);
      tuple = 0; count = 0;
    }
  }
  if (count === 1) return null;
  if (count > 1){
    for (let k = count; k < 5; k++) tuple = tuple * 85 + 84;
    const b = [(tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255];
    for (let k = 0; k < count - 1; k++) out.push(b[k]);
  }
  return Uint8Array.from(out);
}

/* ---------- percent-encoding & quoted-printable --------------------------- */
function decodeUrl(bytes){
  const out = new Uint8Array(bytes.length);
  let o = 0, saw = 0;
  for (let i = 0; i < bytes.length; i++){
    const c = bytes[i];
    if (c === 37 && i + 2 < bytes.length){
      const hi = _hexVal(bytes[i + 1]), lo = _hexVal(bytes[i + 2]);
      if (hi < 0 || lo < 0) return null;
      out[o++] = (hi << 4) | lo; i += 2; saw++;
    } else if (c === 43){ out[o++] = 32; saw++; }
    else out[o++] = c;
  }
  return saw ? out.subarray(0, o) : null;
}
function decodeQuotedPrintable(bytes){
  const out = new Uint8Array(bytes.length);
  let o = 0, saw = 0;
  for (let i = 0; i < bytes.length; i++){
    const c = bytes[i];
    if (c === 61){
      if (bytes[i + 1] === 13 && bytes[i + 2] === 10){ i += 2; saw++; continue; }
      if (bytes[i + 1] === 10){ i += 1; saw++; continue; }
      const hi = _hexVal(bytes[i + 1]), lo = _hexVal(bytes[i + 2]);
      if (hi < 0 || lo < 0) return null;
      out[o++] = (hi << 4) | lo; i += 2; saw++;
    } else out[o++] = c;
  }
  return saw ? out.subarray(0, o) : null;
}

/* ---------- PEM / JWT ----------------------------------------------------- */
function decodePem(bytes){
  const txt = latin1(bytes);
  const m = /-----BEGIN [^-]{1,64}-----([\s\S]*?)-----END [^-]{1,64}-----/.exec(txt);
  if (!m) return null;
  return decodeBase64(asciiBytes(m[1]));
}
function decodeJwtPayload(bytes){
  const txt = latin1(bytes).trim();
  const parts = txt.split(".");
  if (parts.length < 2 || parts.length > 3) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
  const h = decodeBase64(asciiBytes(parts[0]), RT_B64U);
  const p = decodeBase64(asciiBytes(parts[1]), RT_B64U);
  if (!h || !p) return null;
  const ht = latin1(h);
  if (ht[0] !== "{" || !/"alg"/.test(ht)) return null;
  const out = new Uint8Array(h.length + 1 + p.length);
  out.set(h, 0); out[h.length] = 10; out.set(p, h.length + 1);
  return out;
}

function latin1(bytes){
  let s = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(bytes.length, i + step)));
  return s;
}
function asciiBytes(str){
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 255;
  return out;
}

/* ---------- DEFLATE / zlib / gzip ----------------------------------------
   Written out rather than pulled in so the ladder stays synchronous. The
   browser's DecompressionStream is async, which would force every downstream
   compute() to become a promise and break the topological recompute in
   region 06. A 150-line inflate is the cheaper price.
--------------------------------------------------------------------------- */
const _LEN_BASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
const _LEN_EXTRA = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const _DIST_BASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
const _DIST_EXTRA = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
const _CLC_ORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

function _buildHuff(lengths){
  let maxBits = 0;
  for (const l of lengths) if (l > maxBits) maxBits = l;
  if (!maxBits) return null;
  const blCount = new Int32Array(maxBits + 1);
  for (const l of lengths) if (l) blCount[l]++;
  const nextCode = new Int32Array(maxBits + 2);
  let code = 0;
  for (let b = 1; b <= maxBits; b++){ code = (code + blCount[b - 1]) << 1; nextCode[b] = code; }
  const counts = blCount, symbols = new Int32Array(lengths.length);
  const offs = new Int32Array(maxBits + 2);
  for (let b = 1; b <= maxBits; b++) offs[b + 1] = offs[b] + counts[b];
  for (let s = 0; s < lengths.length; s++) if (lengths[s]) symbols[offs[lengths[s]]++] = s;
  return { counts, symbols, maxBits };
}

class _BitReader {
  constructor(bytes, pos){ this.b = bytes; this.p = pos; this.val = 0; this.n = 0; }
  bits(need){
    while (this.n < need){
      if (this.p >= this.b.length) throw new Error("deflate: truncated");
      this.val |= this.b[this.p++] << this.n; this.n += 8;
    }
    const r = this.val & ((1 << need) - 1);
    this.val >>>= need; this.n -= need;
    return r;
  }
  align(){ this.val = 0; this.n = 0; }
  decode(h){
    let code = 0, first = 0, index = 0;
    for (let len = 1; len <= h.maxBits; len++){
      code |= this.bits(1);
      const count = h.counts[len];
      if (code - first < count) return h.symbols[index + (code - first)];
      index += count; first = (first + count) << 1; code <<= 1;
    }
    throw new Error("deflate: bad code");
  }
}

/** Raw DEFLATE. maxOut bounds the decompression bomb surface. */
function inflateRaw(bytes, pos = 0, maxOut = 64 * 1024 * 1024){
  const br = new _BitReader(bytes, pos);
  let out = new Uint8Array(Math.max(4096, Math.min(maxOut, bytes.length * 6)));
  let o = 0;
  const grow = need => {
    if (o + need <= out.length) return;
    if (o + need > maxOut) throw new Error("deflate: output limit");
    let cap = out.length;
    while (cap < o + need) cap = Math.min(maxOut, cap * 2);
    const n = new Uint8Array(cap); n.set(out.subarray(0, o)); out = n;
  };
  let fixedLit = null, fixedDist = null;
  for (;;){
    const last = br.bits(1), type = br.bits(2);
    if (type === 0){
      br.align();
      if (br.p + 4 > bytes.length) throw new Error("deflate: truncated stored");
      const len = bytes[br.p] | (bytes[br.p + 1] << 8);
      const nlen = bytes[br.p + 2] | (bytes[br.p + 3] << 8);
      if ((len ^ 0xFFFF) !== nlen) throw new Error("deflate: stored length mismatch");
      br.p += 4;
      if (br.p + len > bytes.length) throw new Error("deflate: truncated stored data");
      grow(len); out.set(bytes.subarray(br.p, br.p + len), o); o += len; br.p += len;
    } else {
      let lit, dist;
      if (type === 1){
        if (!fixedLit){
          const l = new Uint8Array(288);
          for (let i = 0; i < 144; i++) l[i] = 8;
          for (let i = 144; i < 256; i++) l[i] = 9;
          for (let i = 256; i < 280; i++) l[i] = 7;
          for (let i = 280; i < 288; i++) l[i] = 8;
          fixedLit = _buildHuff(l);
          fixedDist = _buildHuff(new Uint8Array(30).fill(5));
        }
        lit = fixedLit; dist = fixedDist;
      } else if (type === 2){
        const hlit = br.bits(5) + 257, hdist = br.bits(5) + 1, hclen = br.bits(4) + 4;
        const clc = new Uint8Array(19);
        for (let i = 0; i < hclen; i++) clc[_CLC_ORDER[i]] = br.bits(3);
        const clh = _buildHuff(clc);
        if (!clh) throw new Error("deflate: empty code-length tree");
        const lens = new Uint8Array(hlit + hdist);
        for (let i = 0; i < lens.length;){
          const sym = br.decode(clh);
          if (sym < 16) lens[i++] = sym;
          else if (sym === 16){ const prev = i ? lens[i - 1] : 0; let r = 3 + br.bits(2); while (r-- && i < lens.length) lens[i++] = prev; }
          else if (sym === 17){ let r = 3 + br.bits(3); while (r-- && i < lens.length) lens[i++] = 0; }
          else { let r = 11 + br.bits(7); while (r-- && i < lens.length) lens[i++] = 0; }
        }
        lit = _buildHuff(lens.subarray(0, hlit));
        dist = _buildHuff(lens.subarray(hlit));
        if (!lit) throw new Error("deflate: empty literal tree");
      } else throw new Error("deflate: reserved block type");

      for (;;){
        const sym = br.decode(lit);
        if (sym < 256){ grow(1); out[o++] = sym; }
        else if (sym === 256) break;
        else {
          const li = sym - 257;
          if (li >= _LEN_BASE.length) throw new Error("deflate: bad length symbol");
          const len = _LEN_BASE[li] + br.bits(_LEN_EXTRA[li]);
          if (!dist) throw new Error("deflate: no distance tree");
          const ds = br.decode(dist);
          if (ds >= _DIST_BASE.length) throw new Error("deflate: bad distance symbol");
          const d = _DIST_BASE[ds] + br.bits(_DIST_EXTRA[ds]);
          if (d > o) throw new Error("deflate: distance before start");
          grow(len);
          let src = o - d;
          for (let k = 0; k < len; k++) out[o++] = out[src++];
        }
      }
    }
    if (last) break;
  }
  return out.subarray(0, o);
}

function decodeZlib(bytes){
  if (bytes.length < 6) return null;
  const cmf = bytes[0], flg = bytes[1];
  if ((cmf & 0x0F) !== 8) return null;
  if (((cmf << 8) | flg) % 31 !== 0) return null;
  if (flg & 0x20) return null;                     // preset dictionary unsupported
  try { return inflateRaw(bytes, 2); } catch { return null; }
}
function decodeGzip(bytes){
  if (bytes.length < 18 || bytes[0] !== 0x1F || bytes[1] !== 0x8B || bytes[2] !== 8) return null;
  const flg = bytes[3];
  let p = 10;
  if (flg & 4){ if (p + 2 > bytes.length) return null; p += 2 + (bytes[p] | (bytes[p + 1] << 8)); }
  if (flg & 8){ while (p < bytes.length && bytes[p]) p++; p++; }
  if (flg & 16){ while (p < bytes.length && bytes[p]) p++; p++; }
  if (flg & 2) p += 2;
  if (p >= bytes.length) return null;
  try { return inflateRaw(bytes, p); } catch { return null; }
}
function decodeDeflateRaw(bytes){
  try { const r = inflateRaw(bytes, 0); return r.length ? r : null; } catch { return null; }
}

/* ---------- candidate scoring --------------------------------------------
   A decoder that runs is not a decoder that is right. base64 will happily
   "decode" an English sentence into noise. Score the SHAPE of the input
   before decoding, and the plausibility of the output after.
--------------------------------------------------------------------------- */
function alphabetRatio(bytes, rt, extra){
  let hit = 0, tot = 0;
  const n = Math.min(bytes.length, 65536);
  for (let i = 0; i < n; i++){
    const c = bytes[i];
    if (isWs(c)) continue;
    tot++;
    if (rt[c] >= 0 || (extra && extra.includes(c))) hit++;
  }
  return tot ? { ratio: hit / tot, tot } : { ratio: 0, tot: 0 };
}
function printableRatio(bytes){
  let p = 0;
  const n = Math.min(bytes.length, 65536);
  if (!n) return 0;
  for (let i = 0; i < n; i++){ const v = bytes[i]; if (v === 9 || v === 10 || v === 13 || (v >= 32 && v <= 126)) p++; }
  return p / n;
}
function entropyOf(bytes){
  const n = Math.min(bytes.length, 1 << 20);
  if (!n) return 0;
  const c = new Uint32Array(256);
  for (let i = 0; i < n; i++) c[bytes[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) if (c[i]){ const p = c[i] / n; h -= p * Math.log2(p); }
  return h;
}

/** Decoders, ordered. Each declares a gate (cheap shape test) and a decode. */
const CODECS = [
  { id: "pem",      label: "PEM envelope",     gate: b => b.length > 60 && latin1(b.subarray(0, 200)).includes("-----BEGIN "), fn: decodePem, confidence: 0.98 },
  { id: "jwt",      label: "JWT",              gate: b => b.length > 40 && b.length < 1 << 20 && latin1(b.subarray(0, 12)).startsWith("ey"), fn: decodeJwtPayload, confidence: 0.97 },
  { id: "gzip",     label: "gzip",             gate: b => b.length > 18 && b[0] === 0x1F && b[1] === 0x8B, fn: decodeGzip, confidence: 0.99 },
  { id: "zlib",     label: "zlib",             gate: b => b.length > 6 && (b[0] & 0x0F) === 8 && ((b[0] << 8 | b[1]) % 31 === 0), fn: decodeZlib, confidence: 0.95 },
  { id: "hex",      label: "hexadecimal",      gate: b => { const r = alphabetRatio(b, _RT_HEX); return r.tot >= 8 && r.ratio > 0.995 && !(r.tot & 1); }, fn: decodeHex, confidence: 0.9 },
  { id: "base64",   label: "base64",           gate: b => { const r = alphabetRatio(b, RT_B64, [61]); return r.tot >= 16 && r.ratio > 0.995; }, fn: b => decodeBase64(b, RT_B64), confidence: 0.85 },
  { id: "base64url",label: "base64url",        gate: b => { const r = alphabetRatio(b, RT_B64U, [61]); const s = alphabetRatio(b, RT_B64, [61]); return r.tot >= 16 && r.ratio > 0.995 && s.ratio < r.ratio; }, fn: b => decodeBase64(b, RT_B64U), confidence: 0.85 },
  { id: "base32",   label: "base32",           gate: b => { const r = alphabetRatio(b, RT_B32, [61,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122]); return r.tot >= 16 && r.ratio > 0.995; }, fn: decodeBase32, confidence: 0.75 },
  { id: "base58",   label: "base58",           gate: b => { const r = alphabetRatio(b, RT_B58); return r.tot >= 16 && r.tot <= 4096 && r.ratio > 0.999; }, fn: decodeBase58, confidence: 0.6 },
  { id: "ascii85",  label: "ascii85",          gate: b => b.length > 20 && b[0] === 60 && b[1] === 126, fn: decodeAscii85, confidence: 0.9 },
  { id: "url",      label: "percent-encoding", gate: b => { let pc = 0; const n = Math.min(b.length, 8192); for (let i = 0; i < n; i++) if (b[i] === 37) pc++; return pc >= 2 && printableRatio(b) > 0.97; }, fn: decodeUrl, confidence: 0.7 },
  { id: "qp",       label: "quoted-printable", gate: b => { let eq = 0; const n = Math.min(b.length, 8192); for (let i = 0; i < n; i++) if (b[i] === 61) eq++; return eq >= 2 && printableRatio(b) > 0.97; }, fn: decodeQuotedPrintable, confidence: 0.55 },
  { id: "deflate",  label: "raw deflate",      gate: b => b.length > 32 && printableRatio(b) < 0.6, fn: decodeDeflateRaw, confidence: 0.4 }
];
const _RT_HEX = (() => { const t = new Int16Array(256).fill(-1); for (const ch of "0123456789abcdefABCDEF") t[ch.charCodeAt(0)] = 1; return t; })();

/**
 * How plausible is a decode output as real data rather than noise?
 *
 * The first version scored only the extremes: readable text, or entropy above
 * 7.4. Everything in between scored ~0.1, which is exactly where the common
 * case lives - base64 of a small gzip stream is neither printable nor maximally
 * random, so the ladder scored 0.35, fell below its own floor, and refused to
 * unwrap the single most common nesting in the wild. The fix is to stop asking
 * "is this noise" and start asking "does this look like something", with a
 * recognised magic number as the strongest possible yes.
 */
function outputPlausibility(bytes){
  if (!bytes || bytes.length < 4) return 0;
  const pr = printableRatio(bytes), h = entropyOf(bytes);
  let s = 0.2;                                   // floor: it decoded at all
  const fmt = identifyFormat(bytes);
  if (fmt) s += fmt.score >= 4 ? 0.6 : 0.35;     // a known header is decisive
  if (pr > 0.92) s += 0.4;                       // decoded to text
  else if (pr > 0.65) s += 0.18;
  if (h > 7.2) s += 0.2;                         // compressed or encrypted
  else if (h < 4.5) s += 0.15;                   // structured or sparse
  if (bytes.length >= 16) s += 0.08;
  if (bytes.length < 8) s -= 0.25;
  return Math.max(0, Math.min(1, s));
}

/**
 * Try every gated codec once. Returns scored candidates, best first.
 * Never mutates input. Never recurses; recursion is the ladder's job.
 */
function decodeCandidates(bytes){
  const out = [];
  for (const c of CODECS){
    let ok = false;
    try { ok = c.gate(bytes); } catch { ok = false; }
    if (!ok) continue;
    let res = null;
    try { res = c.fn(bytes); } catch { res = null; }
    if (!res || !res.length) continue;
    if (res.length === bytes.length && _sameBytes(res, bytes)) continue;   // identity, not a decode
    const plaus = outputPlausibility(res);
    out.push({ id: c.id, label: c.label, bytes: res, score: c.confidence * (0.35 + 0.65 * plaus), plausibility: plaus, inLen: bytes.length, outLen: res.length });
  }
  out.sort((a, b) => b.score - a.score);
  return out;
}
function _sameBytes(a, b){
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Recursive unwrap. Stops on no candidate, on score floor, on depth, or when
 * the output stops shrinking meaningfully in a way that suggests a loop.
 */
function decodeLadder(bytes, opts = {}){
  const maxDepth = opts.maxDepth == null ? 6 : opts.maxDepth;
  const floor = opts.floor == null ? 0.45 : opts.floor;
  const chain = [{ step: 0, id: "raw", label: "raw input", bytes, score: 1, outLen: bytes.length }];
  const seen = new Set();
  let cur = bytes;
  for (let d = 1; d <= maxDepth; d++){
    const cands = decodeCandidates(cur);
    if (!cands.length || cands[0].score < floor) break;
    const best = cands[0];
    const sig = best.id + ":" + best.outLen;
    if (seen.has(sig)) break;
    seen.add(sig);
    chain.push({ step: d, id: best.id, label: best.label, bytes: best.bytes, score: best.score, outLen: best.outLen, alternatives: cands.slice(1, 4).map(c => ({ id: c.id, label: c.label, outLen: c.outLen, score: c.score })) });
    cur = best.bytes;
  }
  return chain;
}
//#endregion

const { identifyFormat } = require('./10E-signatures.js');
module.exports = { outputPlausibility, decodeBase64, decodeBase32, decodeBase58, decodeHex, decodeAscii85, decodeUrl,
  decodeQuotedPrintable, decodePem, decodeJwtPayload, inflateRaw, decodeZlib, decodeGzip,
  decodeDeflateRaw, decodeCandidates, decodeLadder, entropyOf, printableRatio, latin1, asciiBytes,
  RT_B64, RT_B64U, CODECS };
