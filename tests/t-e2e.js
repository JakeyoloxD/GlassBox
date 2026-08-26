const crypto = require("crypto"), zlib = require("zlib");
const SIG = require("./10E-signatures.js");
const COD = require("./10F-codecs.js");
const STR = require("./10G-stride.js");
const COL = require("./10H-columns.js");
const CLS = require("./10I-classify.js");
const HYP = require("./10L-hypotheses.js");
let pass = 0, fail = 0;
const ok = (n, c, x) => c ? pass++ : (fail++, console.log("  FAIL", n, x === undefined ? "" : x));

/** The pipeline exactly as the app will run it. */
function analyse(raw){
  HYP.resetHypothesisIds();
  const chain = COD.decodeLadder(raw);
  const bytes = chain[chain.length - 1].bytes;
  const format = SIG.identifyFormat(bytes);
  const carved = SIG.carveSignatures(bytes);
  const constants = SIG.scanCryptoConstants(bytes);
  const permutations = SIG.findPermutationTables(bytes);
  const classification = CLS.classifyRange(bytes, 0, bytes.length, { format });
  const segments = CLS.segmentBuffer(bytes);
  const strings = CLS.extractStrings(bytes);
  const stride = STR.analyseStride(bytes);
  const best = stride.candidates[0];
  const columns = best && best.score > 0.25 && best.lag <= COL.COLUMN_LIMITS.maxStride
    ? COL.analyseColumns(bytes, best.lag) : null;
  const repeats = STR.findRepeats(bytes);
  const ecb = STR.detectEcb(bytes, 16);
  const xor = STR.searchXor(bytes);
  return HYP.buildHypotheses({ bytes, format, carved, constants, permutations, stride, columns,
    classification, segments, strings, repeats, ecb, xor, chain });
}
const titles = r => r.hypotheses.map(h => h.title);
const has = (r, re) => r.hypotheses.some(h => re.test(h.title));
function show(name, r){
  console.log(`\n== ${name}`);
  console.log("   " + r.summary);
  for (const h of r.hypotheses.slice(0, 5))
    console.log(`   [${(h.confidence*100).toFixed(0).padStart(3)}%] ${h.kind.padEnd(16)} ${h.title}`);
}

/* ---- fixture 1: base64 of gzip of a JSON log ----------------------------- */
{
  const log = JSON.stringify(Array.from({length: 300}, (_,i) => ({ ts: 1700000000+i*7, host: `10.0.0.${i%251}`, sev: ["low","med","high"][i%3] })));
  const raw = new Uint8Array(Buffer.from(zlib.gzipSync(Buffer.from(log)).toString("base64")));
  const r = analyse(raw); show("base64(gzip(json))", r);
  ok("f1 decodes", has(r, /base64/i) && has(r, /gzip/i), titles(r).join(" | "));
  ok("f1 sees text after unwrap", r.hypotheses.some(h => /text/i.test(h.title)), titles(r).join(" | "));
  ok("f1 every hypothesis has evidence", r.hypotheses.every(h => h.evidence.length > 0));
}

/* ---- fixture 2: binary log, 48-byte records ------------------------------ */
{
  const N = 900, SZ = 48, b = Buffer.alloc(N*SZ);
  for (let i = 0; i < N; i++){
    const o = i*SZ;
    b.writeUInt32LE(i, o);
    b.writeUInt32LE(1710000000 + i*11, o+4);
    b[o+8] = 0x02; b[o+9] = i % 5;
    b.write("LOGREC", o+10);
    crypto.randomFillSync(b, o+16, 32);
  }
  const r = analyse(new Uint8Array(b)); show("48-byte binary records", r);
  ok("f2 finds 48-byte records", has(r, /^48-byte record structure/), titles(r).join(" | "));
  const rec = r.hypotheses.find(h => /^48-byte record/.test(h.title));
  ok("f2 record is top hypothesis", r.hypotheses[0] === rec, r.hypotheses[0].title);
  ok("f2 names the counter", rec.evidence.some(e => /\+0x00 is (counter|timestamp)/.test(e.text)), JSON.stringify(rec.evidence.map(e=>e.text)));
  ok("f2 names the tag", rec.evidence.some(e => /LOGREC/.test(e.text)), JSON.stringify(rec.evidence.map(e=>e.text)));
  ok("f2 surfaces a timestamp field", has(r, /Timestamp at record offset/), titles(r).join(" | "));
  ok("f2 ranges point at records", rec.ranges[0].start === 0 && rec.ranges[1].start === 48);
}

/* ---- fixture 3: AES-ECB ciphertext with repeated plaintext --------------- */
{
  const k = crypto.randomBytes(16);
  const pt = Buffer.concat([Buffer.alloc(160, 0x41), crypto.randomBytes(160), Buffer.alloc(160, 0x41)]);
  const c = crypto.createCipheriv("aes-128-ecb", k, null); c.setAutoPadding(false);
  const r = analyse(new Uint8Array(Buffer.concat([c.update(pt), c.final()])));
  show("AES-128-ECB ciphertext", r);
  ok("f3 detects ECB", has(r, /electronic codebook/i), titles(r).join(" | "));
  ok("f3 calls it encrypted", r.hypotheses.some(h => /encrypted/i.test(h.title)), titles(r).join(" | "));
}

/* ---- fixture 4: firmware-like blob with embedded crypto and files -------- */
{
  const fw = Buffer.alloc(300000);
  crypto.randomFillSync(fw);
  fw.fill(0x00, 0, 4096);
  fw.write("U-Boot 2021.01 (build securus)", 64);
  Buffer.from(SIG._aesSbox()).copy(fw, 0x8000);
  zlib.gzipSync(Buffer.from("payload ".repeat(400))).copy(fw, 0x14000);
  Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]).copy(fw, 0x20000);
  fw.write("https://update.example.internal/fw", 0x2A000);
  fw.write("/etc/config/network.conf", 0x2A100);
  fw.write("admin@example.internal", 0x2A200);
  fw.write("Firmware build 4.2.1 release candidate", 0x2A300);
  const r = analyse(new Uint8Array(fw)); show("firmware-like blob", r);
  ok("f4 finds AES", has(r, /AES implementation/), titles(r).join(" | "));
  ok("f4 finds embedded gzip", has(r, /Embedded gzip/), titles(r).join(" | "));
  ok("f4 finds embedded png", has(r, /Embedded PNG/i), titles(r).join(" | "));
  ok("f4 finds strings", has(r, /strings/), titles(r).join(" | "));
  const aes = r.hypotheses.find(h => /AES implementation/.test(h.title));
  ok("f4 AES cites the exact offset", aes.ranges.some(x => x.start === 0x8000), JSON.stringify(aes.ranges.slice(0,2)));
  ok("f4 AES is drillable", aes.extra.drillable === true);
}

/* ---- fixture 5: repeating-key XOR over English --------------------------- */
{
  const pt = Buffer.from(("Penetration test report. The host exposed an unauthenticated management interface " +
    "permitting configuration retrieval without credentials. ").repeat(60));
  const key = Buffer.from("CANBERRA");
  const ct = Buffer.alloc(pt.length);
  for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ key[i % key.length];
  const r = analyse(new Uint8Array(ct)); show("repeating-key XOR", r);
  ok("f5 finds xor", has(r, /Repeating-key XOR/), titles(r).join(" | "));
  const x = r.hypotheses.find(h => /Repeating-key XOR/.test(h.title));
  ok("f5 recovers the key", x && x.extra.key && Buffer.from(x.extra.key).toString() === "CANBERRA",
     x && Buffer.from(x.extra.key || []).toString());
  ok("f5 offers an action", x && x.extra.actionable === "apply-xor");
  ok("f5 no timestamp fields in ciphertext", !has(r, /Timestamp at record offset/), titles(r).join(" | "));
}

/* ---- fixture 6: pure random must stay quiet ------------------------------ */
{
  const r = analyse(new Uint8Array(crypto.randomBytes(200000))); show("pure CSPRNG output", r);
  ok("f6 no record structure claimed", !has(r, /record structure/), titles(r).join(" | "));
  ok("f6 no crypto constants claimed", !has(r, /implementation present/), titles(r).join(" | "));
  ok("f6 says encrypted/random", r.hypotheses.some(h => /encrypted|random/i.test(h.title)), titles(r).join(" | "));
  ok("f6 few hypotheses", r.hypotheses.length <= 4, r.hypotheses.length + ": " + titles(r).join(" | "));
}

/* ---- fixture 7: plain english must stay quiet ---------------------------- */
{
  let t = "";
  for (let i = 0; i < 700; i++) t += `Section ${i}. The control was assessed as effective during the period under review, with evidence retained. `;
  const r = analyse(new Uint8Array(Buffer.from(t))); show("plain english prose", r);
  ok("f7 classified as text", r.hypotheses.some(h => /text/i.test(h.title)), titles(r).join(" | "));
  ok("f7 no crypto claims", !has(r, /XOR|codebook|implementation present/), titles(r).join(" | "));
  ok("f7 no timestamp fields in prose", !has(r, /Timestamp at record offset/), titles(r).join(" | "));
  ok("f7 record structure framed as text", !r.hypotheses.some(h => /^\d+-byte record structure/.test(h.title)), titles(r).join(" | "));
}

/* ---- determinism ---------------------------------------------------------- */
{
  const b = new Uint8Array(crypto.randomBytes(50000));
  const a1 = JSON.stringify(analyse(b).hypotheses.map(h => [h.kind, h.title, h.confidence.toFixed(6)]));
  const a2 = JSON.stringify(analyse(b).hypotheses.map(h => [h.kind, h.title, h.confidence.toFixed(6)]));
  ok("deterministic", a1 === a2);
}

/* ---- performance ---------------------------------------------------------- */
{
  const big = new Uint8Array(crypto.randomBytes(4 * 1024 * 1024));
  const t = Date.now(); analyse(big); const dt = Date.now() - t;
  ok("4MB full pipeline < 6000ms", dt < 6000, dt + "ms");
  console.log(`\n   4MB full pipeline: ${dt}ms`);
}

console.log(`\ne2e: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
