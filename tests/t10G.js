const crypto = require("crypto");
const G = require("./10G-stride.js");
let pass = 0, fail = 0;
const ok = (n, c, x) => c ? pass++ : (fail++, console.log("FAIL", n, x === undefined ? "" : x));

/* fixture: 48-byte records. u32 LE counter, constant 0x01, ascii tag, random payload */
function records(count, size, payloadLen){
  const b = Buffer.alloc(count * size);
  for (let i = 0; i < count; i++){
    const o = i * size;
    b.writeUInt32LE(1000 + i, o);
    b[o + 4] = 0x01;
    b[o + 5] = 0x00;
    b.write("EVT", o + 6);
    b.writeUInt16LE(i % 7, o + 9);
    crypto.randomFillSync(b, o + 11, payloadLen);
  }
  return new Uint8Array(b);
}

const r48 = records(400, 48, 37);
let a = G.analyseStride(r48);
ok("48B records -> lag 48", a.candidates[0] && a.candidates[0].lag === 48,
   a.candidates.slice(0,4).map(c=>`${c.lag}@${c.score.toFixed(2)}`).join(" "));
ok("48B has evidence", a.candidates[0] && a.candidates[0].evidence.length >= 2);
ok("48B no harmonic at top", !a.candidates.slice(0,3).some(c => c.lag === 96),
   a.candidates.slice(0,5).map(c=>c.lag).join(","));

const r64 = records(300, 64, 50);
a = G.analyseStride(r64);
ok("64B records -> lag 64", a.candidates[0] && a.candidates[0].lag === 64,
   a.candidates.slice(0,4).map(c=>`${c.lag}@${c.score.toFixed(2)}`).join(" "));

const r13 = records(500, 13, 2);
a = G.analyseStride(r13);
ok("13B records -> lag 13", a.candidates[0] && a.candidates[0].lag === 13,
   a.candidates.slice(0,4).map(c=>`${c.lag}@${c.score.toFixed(2)}`).join(" "));

/* pure noise must produce no confident stride */
a = G.analyseStride(new Uint8Array(crypto.randomBytes(200000)));
ok("noise -> no strong stride", !a.candidates.length || a.candidates[0].score < 0.25,
   a.candidates.slice(0,3).map(c=>`${c.lag}@${c.score.toFixed(2)}`).join(" "));

/* english prose must not produce a confident stride */
let proseSrc = "";
for (let i = 0; i < 900; i++) proseSrc += `Finding ${i}: the host at 10.0.${i%251}.${(i*7)%251} exposed service ${i%13} with severity ${["low","medium","high"][i%3]} and required remediation within ${i%30} days. `;
const prose = Buffer.from(proseSrc);
a = G.analyseStride(new Uint8Array(prose));
ok("prose -> weak stride", !a.candidates.length || a.candidates[0].score < 0.6,
   a.candidates.slice(0,3).map(c=>`${c.lag}@${c.score.toFixed(2)}`).join(" "));

/* repeating-key XOR: IoC must find the key length and chi-squared the key */
const plain = Buffer.from(("It was the best of times, it was the worst of times, it was the age of wisdom, " +
  "it was the age of foolishness, it was the epoch of belief. ").repeat(60));
const key = Buffer.from("GLASSBOX!");
const ct = Buffer.alloc(plain.length);
for (let i = 0; i < plain.length; i++) ct[i] = plain[i] ^ key[i % key.length];
a = G.analyseStride(new Uint8Array(ct), { maxLag: 64 });
const top = a.candidates.slice(0, 3).map(c => c.lag);
ok("xor key length found", top.includes(9), top.join(","));
const rec = G.recoverXorKey(new Uint8Array(ct), 9);
ok("xor key recovered", Buffer.from(rec.key).toString() === "GLASSBOX!", Buffer.from(rec.key).toString());
const back = G.applyXor(new Uint8Array(ct), rec.key);
ok("xor roundtrip", Buffer.from(back).toString().startsWith("It was the best"));

/* ECB detection */
const aeskey = crypto.randomBytes(16);
const blocky = Buffer.concat([Buffer.from("A".repeat(64)), crypto.randomBytes(64), Buffer.from("A".repeat(64))]);
const c1 = crypto.createCipheriv("aes-128-ecb", aeskey, null); c1.setAutoPadding(false);
const ecb = Buffer.concat([c1.update(blocky), c1.final()]);
const d = G.detectEcb(new Uint8Array(ecb), 16);
ok("ecb detected", d && d.duplicateBlocks >= 4, JSON.stringify(d && {du:d.duplicateBlocks, r:d.ratio}));

const c2 = crypto.createCipheriv("aes-128-cbc", aeskey, crypto.randomBytes(16)); c2.setAutoPadding(false);
const cbc = Buffer.concat([c2.update(blocky), c2.final()]);
ok("cbc not flagged", G.detectEcb(new Uint8Array(cbc), 16) === null);

/* unaligned repeats */
const rep = Buffer.concat([crypto.randomBytes(500), Buffer.from("SIGNATURE_BLOCK_MARKER_XYZ"), crypto.randomBytes(731),
                           Buffer.from("SIGNATURE_BLOCK_MARKER_XYZ"), crypto.randomBytes(400)]);
const fr = G.findRepeats(new Uint8Array(rep), { seed: 8 });
ok("unaligned repeat found", fr.rows.some(r => r.len >= 26), JSON.stringify(fr.rows.slice(0,3)));

/* timings */
const big = new Uint8Array(crypto.randomBytes(2 * 1024 * 1024));
let t = Date.now(); G.analyseStride(big); const ts = Date.now() - t;
ok("stride 2MB < 4000ms", ts < 4000, ts + "ms");
t = Date.now(); G.findRepeats(big); const tr = Date.now() - t;
ok("repeats 2MB < 2500ms", tr < 2500, tr + "ms");
console.log(`  timings: stride ${ts}ms  repeats ${tr}ms`);

console.log(`\n10G: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
