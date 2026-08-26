//#region 10E SIGNATURES / CONSTANTS
/* Two different questions, deliberately kept apart:
     what IS this          -> magic at offset 0
     what is INSIDE this   -> carved signatures at every offset, binwalk style
   plus a third that nothing else in this class does:
     what CRYPTO is in here -> exact match against known algorithm tables.       */

/** Magic entries: bytes may contain null for a wildcard byte. */
function _mk(hexOrStr){
  if (typeof hexOrStr !== "string") return hexOrStr;
  const out = [];
  for (let i = 0; i < hexOrStr.length; i++) out.push(hexOrStr.charCodeAt(i) & 255);
  return out;
}
function _hx(h){
  const out = [];
  for (let i = 0; i < h.length; i += 2) out.push(h.slice(i, i + 2) === "??" ? null : parseInt(h.slice(i, i + 2), 16));
  return out;
}

const MAGIC = [
  { id: "gzip",    label: "gzip stream",            sig: _hx("1f8b08"),        kind: "compressed", carve: true },
  { id: "zlib",    label: "zlib stream",            sig: _hx("789c"),          kind: "compressed", carve: true, weak: true },
  { id: "zlib1",   label: "zlib stream (level 1)",  sig: _hx("7801"),          kind: "compressed", carve: true, weak: true },
  { id: "zlib9",   label: "zlib stream (level 9)",  sig: _hx("78da"),          kind: "compressed", carve: true, weak: true },
  { id: "zip",     label: "ZIP local file header",  sig: _hx("504b0304"),      kind: "archive",    carve: true },
  { id: "zipcd",   label: "ZIP central directory",  sig: _hx("504b0102"),      kind: "archive",    carve: true },
  { id: "zipeocd", label: "ZIP end of central dir", sig: _hx("504b0506"),      kind: "archive",    carve: true },
  { id: "xz",      label: "XZ stream",              sig: _hx("fd377a585a00"),  kind: "compressed", carve: true },
  { id: "bzip2",   label: "bzip2",                  sig: _hx("425a68"),        kind: "compressed", carve: true },
  { id: "zstd",    label: "Zstandard",              sig: _hx("28b52ffd"),      kind: "compressed", carve: true },
  { id: "lz4",     label: "LZ4 frame",              sig: _hx("04224d18"),      kind: "compressed", carve: true },
  { id: "7z",      label: "7-Zip",                  sig: _hx("377abcaf271c"),  kind: "archive",    carve: true },
  { id: "rar",     label: "RAR archive",            sig: _hx("526172211a07"),  kind: "archive",    carve: true },
  { id: "tar",     label: "POSIX tar (ustar)",      sig: _mk("ustar"),         kind: "archive",    carve: true, offset: 257 },
  { id: "elf",     label: "ELF executable",         sig: _hx("7f454c46"),      kind: "executable", carve: true },
  { id: "pe",      label: "DOS/PE executable",      sig: _hx("4d5a"),          kind: "executable", carve: false },
  { id: "macho64", label: "Mach-O 64-bit",          sig: _hx("cffaedfe"),      kind: "executable", carve: true },
  { id: "macho32", label: "Mach-O 32-bit",          sig: _hx("cefaedfe"),      kind: "executable", carve: true },
  { id: "class",   label: "Java class",             sig: _hx("cafebabe"),      kind: "executable", carve: true },
  { id: "dex",     label: "Android DEX",            sig: _mk("dex\n"),         kind: "executable", carve: true },
  { id: "wasm",    label: "WebAssembly",            sig: _hx("0061736d"),      kind: "executable", carve: true },
  { id: "png",     label: "PNG image",              sig: _hx("89504e470d0a1a0a"), kind: "image",   carve: true },
  { id: "jpeg",    label: "JPEG image",             sig: _hx("ffd8ff"),        kind: "image",      carve: true },
  { id: "gif",     label: "GIF image",              sig: _mk("GIF8"),          kind: "image",      carve: true },
  { id: "bmp",     label: "BMP image",              sig: _mk("BM"),            kind: "image",      carve: false },
  { id: "webp",    label: "WebP (RIFF)",            sig: _hx("52494646????????57454250"), kind: "image", carve: true },
  { id: "tiff_le", label: "TIFF (little-endian)",   sig: _hx("49492a00"),      kind: "image",      carve: true },
  { id: "tiff_be", label: "TIFF (big-endian)",      sig: _hx("4d4d002a"),      kind: "image",      carve: true },
  { id: "ico",     label: "Windows icon",           sig: _hx("00000100"),      kind: "image",      carve: false, weak: true },
  { id: "pdf",     label: "PDF document",           sig: _mk("%PDF-"),         kind: "document",   carve: true },
  { id: "ole2",    label: "OLE2 / legacy Office",   sig: _hx("d0cf11e0a1b11ae1"), kind: "document", carve: true },
  { id: "rtf",     label: "RTF document",           sig: _mk("{\\rtf"),        kind: "document",   carve: true },
  { id: "sqlite",  label: "SQLite database",        sig: _mk("SQLite format 3"), kind: "database", carve: true },
  { id: "pcap",    label: "pcap capture",           sig: _hx("d4c3b2a1"),      kind: "capture",    carve: true },
  { id: "pcapng",  label: "pcapng capture",         sig: _hx("0a0d0d0a"),      kind: "capture",    carve: true, weak: true },
  { id: "pem",     label: "PEM block",              sig: _mk("-----BEGIN "),   kind: "crypto",     carve: true },
  { id: "sshrsa",  label: "OpenSSH public key",     sig: _mk("ssh-rsa "),      kind: "crypto",     carve: true },
  { id: "openssl", label: "OpenSSL salted blob",    sig: _mk("Salted__"),      kind: "crypto",     carve: true },
  { id: "gpg",     label: "GPG/PGP packet",         sig: _hx("8502"),          kind: "crypto",     carve: false, weak: true },
  { id: "der_seq", label: "DER SEQUENCE",           sig: _hx("3082"),          kind: "structured", carve: false, weak: true },
  { id: "cab",     label: "Microsoft Cabinet",      sig: _mk("MSCF"),          kind: "archive",    carve: true },
  { id: "uboot",   label: "U-Boot uImage",          sig: _hx("27051956"),      kind: "firmware",   carve: true },
  { id: "squashfs",label: "SquashFS (LE)",          sig: _mk("hsqs"),          kind: "firmware",   carve: true },
  { id: "squashbe",label: "SquashFS (BE)",          sig: _mk("sqsh"),          kind: "firmware",   carve: true },
  { id: "cramfs",  label: "CramFS",                 sig: _hx("453dcd28"),      kind: "firmware",   carve: true },
  { id: "jffs2",   label: "JFFS2",                  sig: _hx("1985"),          kind: "firmware",   carve: false, weak: true },
  { id: "dtb",     label: "Device tree blob",       sig: _hx("d00dfeed"),      kind: "firmware",   carve: true },
  { id: "mp3id3",  label: "MP3 with ID3",           sig: _mk("ID3"),           kind: "media",      carve: true },
  { id: "ogg",     label: "Ogg container",          sig: _mk("OggS"),          kind: "media",      carve: true },
  { id: "riffwav", label: "RIFF/WAV audio",         sig: _hx("52494646????????57415645"), kind: "media", carve: true },
  { id: "mp4",     label: "ISO base media (MP4)",   sig: _mk("ftyp"),          kind: "media",      carve: true, offset: 4 }
];

function matchSigAt(bytes, pos, sig){
  if (pos + sig.length > bytes.length) return false;
  for (let i = 0; i < sig.length; i++){
    const s = sig[i];
    if (s !== null && bytes[pos + i] !== s) return false;
  }
  return true;
}

/** Format identity at the head of the buffer. Longest match wins. */
function identifyFormat(bytes){
  let best = null;
  for (const m of MAGIC){
    const at = m.offset || 0;
    if (!matchSigAt(bytes, at, m.sig)) continue;
    const score = m.sig.reduce((a, s) => a + (s === null ? 0 : 1), 0) - (m.weak ? 1.5 : 0);
    if (!best || score > best.score) best = { id: m.id, label: m.label, kind: m.kind, offset: at, score };
  }
  return best;
}

/**
 * Carve embedded signatures. First-byte bucketed so the scan is one pass with
 * a tiny inner loop rather than |MAGIC| passes over the buffer.
 */
function carveSignatures(bytes, opts = {}){
  const limit = opts.limit == null ? 512 : opts.limit;
  const includeWeak = !!opts.includeWeak;
  const buckets = new Array(256);
  for (const m of MAGIC){
    if (!m.carve) continue;
    if (m.weak && !includeWeak) continue;
    if (m.offset) continue;                        // offset-anchored formats are not carvable
    const f = m.sig[0];
    if (f === null) continue;
    (buckets[f] || (buckets[f] = [])).push(m);
  }
  const hits = [];
  const n = bytes.length;
  for (let i = 0; i < n && hits.length < limit; i++){
    const b = buckets[bytes[i]];
    if (!b) continue;
    for (const m of b){
      if (matchSigAt(bytes, i, m.sig)){
        hits.push({ offset: i, id: m.id, label: m.label, kind: m.kind, len: m.sig.length });
        break;
      }
    }
  }
  return { hits, truncated: hits.length >= limit };
}

/* ---------- cryptographic constant tables --------------------------------
   These are the fingerprints of an implementation, not of a file format.
   Finding the AES forward S-box at 0x3F20 in a firmware image tells you where
   the crypto lives, which no entropy plot ever will.
--------------------------------------------------------------------------- */

function _aesSbox(){
  const p = new Uint8Array(256), q = new Uint8Array(256);
  let x = 1, y = 1;
  do {
    x = x ^ (x << 1) ^ (x & 0x80 ? 0x11B : 0);        // multiply by 3
    x &= 0xFF;
    y ^= y << 1; y ^= y << 2; y ^= y << 4; y &= 0xFF;
    if (y & 0x80) y ^= 0x09;
    p[x] = y; q[y] = x;
  } while (x !== 1);
  // p is the generator walk; build the sbox from the affine transform
  const inv = new Uint8Array(256);
  for (let i = 1; i < 256; i++){
    // brute-force inverse in GF(2^8)/0x11B: 256 ops per element is fine, once
    for (let j = 1; j < 256; j++) if (_gmul(i, j) === 1){ inv[i] = j; break; }
  }
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++){
    const b = inv[i];
    s[i] = (b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63) & 0xFF;
  }
  return s;
}
function _gmul(a, b){
  let r = 0;
  while (b){
    if (b & 1) r ^= a;
    a = (a << 1) ^ (a & 0x80 ? 0x11B : 0);
    a &= 0xFF; b >>= 1;
  }
  return r;
}
function _rotl8(v, n){ return ((v << n) | (v >>> (8 - n))) & 0xFF; }

function _bytesFromU32(arr, little){
  const out = new Uint8Array(arr.length * 4);
  for (let i = 0; i < arr.length; i++){
    const v = arr[i] >>> 0;
    if (little){ out[i*4] = v & 255; out[i*4+1] = (v >>> 8) & 255; out[i*4+2] = (v >>> 16) & 255; out[i*4+3] = (v >>> 24) & 255; }
    else { out[i*4] = (v >>> 24) & 255; out[i*4+1] = (v >>> 16) & 255; out[i*4+2] = (v >>> 8) & 255; out[i*4+3] = v & 255; }
  }
  return out;
}

const SHA256_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
];
const SHA256_H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
const SHA512_H_HI = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
const SHA1_H = [0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0];
const MD5_H = [0x67452301,0xefcdab89,0x98badcfe,0x10325476];
const MD5_T = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501];
const BLAKE2B_IV_HI = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

function _crc32Table(poly){
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++){
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? ((c >>> 1) ^ poly) : (c >>> 1);
    t[i] = c >>> 0;
  }
  return t;
}

let _CONSTS = null;
function cryptoConstants(){
  if (_CONSTS) return _CONSTS;
  const sbox = _aesSbox();
  const inv = new Uint8Array(256);
  for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
  const te0 = new Uint32Array(256);
  for (let i = 0; i < 256; i++){
    const s = sbox[i], s2 = _gmul(s, 2), s3 = _gmul(s, 3);
    te0[i] = ((s2 << 24) | (s << 16) | (s << 8) | s3) >>> 0;
  }
  const crc32 = _crc32Table(0xEDB88320);
  const crc32c = _crc32Table(0x82F63B78);

  const list = [
    { id: "aes_sbox",     label: "AES forward S-box",        bytes: sbox,                       algo: "AES", weight: 1.0 },
    { id: "aes_sbox_inv", label: "AES inverse S-box",        bytes: inv,                        algo: "AES", weight: 1.0 },
    { id: "aes_te0_le",   label: "AES T-table Te0 (LE)",     bytes: _bytesFromU32(te0, true),   algo: "AES", weight: 1.0 },
    { id: "aes_te0_be",   label: "AES T-table Te0 (BE)",     bytes: _bytesFromU32(te0, false),  algo: "AES", weight: 1.0 },
    { id: "sha256_k_be",  label: "SHA-256 round constants",  bytes: _bytesFromU32(SHA256_K, false), algo: "SHA-256", weight: 1.0 },
    { id: "sha256_k_le",  label: "SHA-256 round constants (LE)", bytes: _bytesFromU32(SHA256_K, true), algo: "SHA-256", weight: 1.0 },
    { id: "sha256_h_be",  label: "SHA-256 initial state",    bytes: _bytesFromU32(SHA256_H, false), algo: "SHA-256", weight: 0.9 },
    { id: "sha256_h_le",  label: "SHA-256 initial state (LE)", bytes: _bytesFromU32(SHA256_H, true), algo: "SHA-256", weight: 0.9 },
    { id: "sha1_h_be",    label: "SHA-1 initial state",      bytes: _bytesFromU32(SHA1_H, false), algo: "SHA-1", weight: 0.9 },
    { id: "sha1_h_le",    label: "SHA-1 initial state (LE)", bytes: _bytesFromU32(SHA1_H, true), algo: "SHA-1", weight: 0.9 },
    { id: "md5_t_le",     label: "MD5 sine table head (LE)", bytes: _bytesFromU32(MD5_T, true), algo: "MD5", weight: 0.95 },
    { id: "md5_t_be",     label: "MD5 sine table head",      bytes: _bytesFromU32(MD5_T, false), algo: "MD5", weight: 0.95 },
    { id: "md5_h_le",     label: "MD5/SHA-1 initial state (LE)", bytes: _bytesFromU32(MD5_H, true), algo: "MD5", weight: 0.8 },
    { id: "crc32_le",     label: "CRC-32 table (IEEE)",      bytes: _bytesFromU32(Array.from(crc32.subarray(0, 32)), true), algo: "CRC-32", weight: 0.85 },
    { id: "crc32c_le",    label: "CRC-32C table (Castagnoli)", bytes: _bytesFromU32(Array.from(crc32c.subarray(0, 32)), true), algo: "CRC-32C", weight: 0.85 },
    { id: "b64_std",      label: "base64 standard alphabet", bytes: asciiOf("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), algo: "base64", weight: 0.7 },
    { id: "b64_url",      label: "base64url alphabet",       bytes: asciiOf("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"), algo: "base64url", weight: 0.7 },
    { id: "b32_rfc",      label: "base32 alphabet",          bytes: asciiOf("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), algo: "base32", weight: 0.6 },
    { id: "b58_btc",      label: "base58 alphabet",          bytes: asciiOf("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"), algo: "base58", weight: 0.7 },
    { id: "hex_lower",    label: "lowercase hex alphabet",   bytes: asciiOf("0123456789abcdef"), algo: "hex", weight: 0.35 },
    { id: "blake2b_iv",   label: "BLAKE2b IV (high words)",  bytes: _bytesFromU32(BLAKE2B_IV_HI, false), algo: "BLAKE2b", weight: 0.6 }
  ];
  for (const c of list){ c.len = c.bytes.length; }
  _CONSTS = list;
  return list;
}
function asciiOf(s){
  const o = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i);
  return o;
}

/**
 * Exact-match scan for every known constant, in one pass.
 *
 * Naive approach is |constants| passes over the buffer. Instead: index every
 * constant by its first 4 bytes into a hash map, then walk the buffer once
 * and only memcmp where a 4-byte key hits. Cost is O(n) with a Map lookup per
 * byte, which stays interactive to several megabytes.
 */
function scanCryptoConstants(bytes, opts = {}){
  const consts = cryptoConstants();
  const limit = opts.limit == null ? 256 : opts.limit;
  const index = new Map();
  for (const c of consts){
    if (c.len < 4) continue;
    const key = (c.bytes[0] << 24 | c.bytes[1] << 16 | c.bytes[2] << 8 | c.bytes[3]) >>> 0;
    let arr = index.get(key);
    if (!arr) index.set(key, arr = []);
    arr.push(c);
  }
  const hits = [];
  const n = bytes.length;
  if (n < 4) return { hits, algos: [] };
  let k = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  for (let i = 0; i + 4 <= n; i++){
    if (i) k = (((k << 8) >>> 0) | bytes[i + 3]) >>> 0;
    const cands = index.get(k);
    if (cands){
      for (const c of cands){
        if (i + c.len > n) continue;
        let ok = true;
        for (let j = 4; j < c.len; j++) if (bytes[i + j] !== c.bytes[j]){ ok = false; break; }
        if (ok){
          hits.push({ offset: i, id: c.id, label: c.label, algo: c.algo, len: c.len, weight: c.weight });
          if (hits.length >= limit) return { hits, algos: _algoSummary(hits), truncated: true };
        }
      }
    }
  }
  return { hits, algos: _algoSummary(hits), truncated: false };
}
function _algoSummary(hits){
  const m = new Map();
  for (const h of hits){
    let a = m.get(h.algo);
    if (!a) m.set(h.algo, a = { algo: h.algo, count: 0, weight: 0, offsets: [] });
    a.count++; a.weight = Math.max(a.weight, h.weight);
    if (a.offsets.length < 16) a.offsets.push(h.offset);
  }
  return [...m.values()].sort((a, b) => b.weight - a.weight || b.count - a.count);
}

/**
 * A permutation table of 256 distinct bytes is an S-box whether or not it is
 * a known one. This finds candidate S-boxes the constant table cannot.
 */
function findPermutationTables(bytes, opts = {}){
  const size = opts.size == null ? 256 : opts.size;
  const limit = opts.limit == null ? 32 : opts.limit;
  const n = bytes.length;
  if (n < size) return [];
  const out = [];
  const count = new Int32Array(256);
  let distinct = 0;
  for (let i = 0; i < size; i++){ if (count[bytes[i]]++ === 0) distinct++; }
  const step = opts.step == null ? 1 : opts.step;
  for (let start = 0; start + size <= n; start += step){
    if (start){
      const outB = bytes[start - 1], inB = bytes[start + size - 1];
      if (--count[outB] === 0) distinct--;
      if (count[inB]++ === 0) distinct++;
    }
    if (distinct === size && size === 256){
      const identity = _isIdentity(bytes, start, size);
      out.push({ offset: start, size, identity });
      if (out.length >= limit) break;
      // skip past this table; overlapping permutations are noise
      for (let s = 0; s < size - 1 && start + step < n; s++){}
    }
  }
  return out;
}
function _isIdentity(bytes, start, size){
  for (let i = 0; i < size; i++) if (bytes[start + i] !== i) return false;
  return true;
}
//#endregion

module.exports = { MAGIC, matchSigAt, identifyFormat, carveSignatures, cryptoConstants,
  scanCryptoConstants, findPermutationTables, _aesSbox, _gmul };
