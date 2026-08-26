const crypto = require("crypto");
const H = require("./10H-columns.js");
let pass = 0, fail = 0;
const ok = (n, c, x) => c ? pass++ : (fail++, console.log("FAIL", n, x === undefined ? "" : x));

/* Known layout, 40 bytes:
   +0x00 u32 LE counter, step 1
   +0x04 u32 LE unix timestamp, increasing
   +0x08 u8 constant 0x01
   +0x09 u8 enum {0,1,2,3}
   +0x0A char[6] "EVENT:"
   +0x10 f64 LE value
   +0x18 u8[16] random payload
*/
const N = 800, SZ = 40;
const b = Buffer.alloc(N * SZ);
for (let i = 0; i < N; i++){
  const o = i * SZ;
  b.writeUInt32LE(500000 + i, o);
  b.writeUInt32LE(1700000000 + i * 37, o + 4);
  b[o + 8] = 0x01;
  b[o + 9] = i % 4;
  b.write("EVENT:", o + 10);
  b.writeDoubleLE(12.5 + (i % 97) * 0.25, o + 16);
  crypto.randomFillSync(b, o + 24, 16);
}
const bytes = new Uint8Array(b);
const r = H.analyseColumns(bytes, SZ);
const at = s => r.fields.find(f => f.start === s);

ok("record count", r.count === N, r.count);
ok("+0x00 counter", at(0) && at(0).type === "counter" && at(0).len === 4, JSON.stringify(at(0)));
ok("+0x00 step 1", at(0) && at(0).extra.constDelta === 1, at(0) && at(0).extra.constDelta);
ok("+0x00 little-endian", at(0) && at(0).extra.little === true);
ok("+0x04 timestamp", at(4) && at(4).type === "timestamp", JSON.stringify(at(4)));
ok("+0x08 constant", at(8) && at(8).type === "constant" && at(8).detail.includes("0x01"), JSON.stringify(at(8)));
ok("+0x09 enum", at(9) && at(9).type === "enum", JSON.stringify(at(9)));
ok("+0x0A text", at(10) && at(10).type === "text" && at(10).len === 6, JSON.stringify(at(10)));
ok("+0x10 float", at(16) && at(16).type === "float" && at(16).len === 8, JSON.stringify(at(16)));
ok("+0x18 random", at(24) && at(24).type === "random" && at(24).len === 16, JSON.stringify(at(24)));
ok("fields cover stride", r.fields.reduce((a,f)=>a+f.len,0) === SZ, r.fields.reduce((a,f)=>a+f.len,0));
ok("every field has evidence", r.fields.every(f => f.evidence && f.evidence.length));

/* big-endian variant */
const be = Buffer.alloc(400 * 16);
for (let i = 0; i < 400; i++){ be.writeUInt32BE(i * 3, i * 16); crypto.randomFillSync(be, i*16+4, 12); }
const rbe = H.analyseColumns(new Uint8Array(be), 16);
const f0 = rbe.fields.find(f => f.start === 0);
ok("big-endian counter", f0 && f0.type === "counter" && f0.extra.little === false && f0.extra.constDelta === 3, JSON.stringify(f0));

/* pure noise must yield no confident fields */
const noise = H.analyseColumns(new Uint8Array(crypto.randomBytes(32000)), 32);
ok("noise -> all random", noise.fields.every(f => f.type === "random" || f.type === "varying"),
   JSON.stringify(noise.fields.filter(f=>f.type!=="random"&&f.type!=="varying").slice(0,3)));
ok("noise structuredRatio ~0", noise.structuredRatio < 0.1, noise.structuredRatio);

/* all-zero must not be reported as a float field */
const zeros = H.analyseColumns(new Uint8Array(16000), 16);
ok("zeros -> constant not float", zeros.fields.every(f => f.type === "constant"),
   JSON.stringify(zeros.fields.slice(0,3)));

/* struct rendering */
const st = H.fieldsToStruct(r, "evt");
ok("struct renders", st.includes("struct evt") && st.includes("+0x00") && st.split("\n").length === r.fields.length + 2, st);
console.log("\n" + st + "\n");

/* guard rails */
let threw = false; try { H.analyseColumns(bytes, 0); } catch { threw = true; }
ok("rejects stride 0", threw);
ok("insufficient records flagged", H.analyseColumns(new Uint8Array(30), 16).insufficient === true);

let t = Date.now(); H.analyseColumns(new Uint8Array(crypto.randomBytes(1<<20)), 256); const tt = Date.now()-t;
ok("1MB @ stride 256 < 3000ms", tt < 3000, tt + "ms");
console.log(`  timing: columns ${tt}ms`);

console.log(`\n10H: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
