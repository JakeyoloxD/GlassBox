const crypto = require("crypto"), zlib = require("zlib");
const C = require("./10I-classify.js");
let pass = 0, fail = 0;
const ok = (n, c, x) => c ? pass++ : (fail++, console.log("FAIL", n, x === undefined ? "" : x));
const cls = b => C.classifyRange(new Uint8Array(b)).label;

const prose = Buffer.from("The assessment identified three findings across the perimeter estate. ".repeat(120));
ok("text", cls(prose) === C.CLASSES.TEXT, cls(prose));
ok("base64", cls(Buffer.from(crypto.randomBytes(3000).toString("base64"))) === C.CLASSES.BASE64, cls(Buffer.from(crypto.randomBytes(3000).toString("base64"))));
ok("hex", cls(Buffer.from(crypto.randomBytes(3000).toString("hex"))) === C.CLASSES.HEX, cls(Buffer.from(crypto.randomBytes(3000).toString("hex"))));
ok("sparse", cls(Buffer.alloc(4000)) === C.CLASSES.SPARSE, cls(Buffer.alloc(4000)));
const u16 = Buffer.alloc(2000);
for (let i = 0; i < 1000; i++){ u16[i*2] = 65 + (i % 26); u16[i*2+1] = 0; }
ok("utf-16", cls(u16) === C.CLASSES.UTF16, cls(u16));

const enc = crypto.randomBytes(65536);
ok("encrypted", cls(enc) === C.CLASSES.ENCRYPTED, cls(enc) + " " + JSON.stringify(C.classifyRange(new Uint8Array(enc)).reasons));
const comp = zlib.gzipSync(Buffer.from(prose.toString().repeat(3)));
const compBody = comp.subarray(10);
ok("compressed not called encrypted", cls(compBody) !== C.CLASSES.ENCRYPTED, cls(compBody));
ok("compressed with header ctx", C.classifyRange(new Uint8Array(comp), 0, comp.length, { format: { kind: "compressed", label: "gzip" } }).label === C.CLASSES.COMPRESSED);
ok("reasons present", C.classifyRange(new Uint8Array(enc)).reasons.length >= 3);

// segmentation: text | zeros | random | text
const seg = Buffer.concat([Buffer.from("HEADER ".repeat(600)), Buffer.alloc(4096), crypto.randomBytes(8192), Buffer.from("TRAILER ".repeat(600))]);
const segs = C.segmentBuffer(new Uint8Array(seg));
ok("segments >= 4", segs.length >= 4, segs.map(s => `${s.label}:${s.length}`).join(" | "));
ok("segments cover buffer", segs[0].start === 0 && segs[segs.length-1].end === seg.length - 1);
const labels = segs.map(s => s.label);
ok("segment order", labels[0] === C.CLASSES.TEXT && labels.includes(C.CLASSES.SPARSE) && labels.includes(C.CLASSES.ENCRYPTED),
   labels.join(" | "));
console.log("  segments: " + segs.map(s => `${s.label}@0x${s.start.toString(16)}(${s.length})`).join("  "));

// strings
// NUL-delimited so a stray printable byte in the random filler cannot merge
// with the planted string and shift its start offset.
const withStr = Buffer.concat([crypto.randomBytes(199), Buffer.from("\0"), Buffer.from("https://wiki.securus-cg.com/api\0"),
                               crypto.randomBytes(199), Buffer.from("\0"),
                               Buffer.from("C:\\Windows\\System32\0"), crypto.randomBytes(100)]);
const st = C.extractStrings(new Uint8Array(withStr));
ok("finds url", st.strings.some(x => x.text.startsWith("https://wiki")), JSON.stringify(st.strings.slice(0,5)));
ok("finds path", st.strings.some(x => x.text.startsWith("C:\\Windows")));
ok("offsets correct", st.strings.find(x => x.text.startsWith("https://")).start === 200);
ok("notable picks url", st.notable.some(x => x.text.startsWith("https://")));
const w16 = Buffer.alloc(80);
Buffer.from("SecretConfigKey").split ? 0 : 0;
"SecretConfigKey".split("").forEach((ch,i)=>{ w16[20+i*2]=ch.charCodeAt(0); w16[21+i*2]=0; });
const s16 = C.extractStrings(new Uint8Array(w16));
ok("finds utf-16 string", s16.strings.some(x => x.enc === "utf-16le" && x.text === "SecretConfigKey"), JSON.stringify(s16.strings));

// digraph
const dg = C.digraphMatrix(new Uint8Array(prose));
ok("digraph sparse for text", dg.coverage < 0.05, dg.coverage);
const dge = C.digraphMatrix(new Uint8Array(crypto.randomBytes(300000)));
ok("digraph dense for random", dge.coverage > 0.9, dge.coverage);

// hilbert
ok("hilbert 0", JSON.stringify(C.hilbertXY(0, 4)) === '{"x":0,"y":0}');
const seen = new Set();
for (let d = 0; d < 256; d++){ const p = C.hilbertXY(d, 4); seen.add(p.x + "," + p.y); }
ok("hilbert bijective order 4", seen.size === 256, seen.size);
let adj = true;
for (let d = 1; d < 256; d++){
  const a = C.hilbertXY(d-1,4), b = C.hilbertXY(d,4);
  if (Math.abs(a.x-b.x) + Math.abs(a.y-b.y) !== 1) adj = false;
}
ok("hilbert steps are adjacent", adj);
const hm = C.hilbertMap(new Uint8Array(seg), { order: 6 });
ok("hilbert map sized", hm.used > 0 && hm.xs.length === hm.used && hm.side === 64, `${hm.used} ${hm.side}`);

let t = Date.now(); C.segmentBuffer(new Uint8Array(crypto.randomBytes(4<<20))); const t1 = Date.now()-t;
t = Date.now(); C.extractStrings(new Uint8Array(crypto.randomBytes(4<<20))); const t2 = Date.now()-t;
t = Date.now(); C.hilbertMap(new Uint8Array(crypto.randomBytes(4<<20)), {order:7}); const t3 = Date.now()-t;
ok("segment 4MB < 1500ms", t1 < 1500, t1+"ms");
ok("strings 4MB < 1500ms", t2 < 1500, t2+"ms");
ok("hilbert 4MB < 1500ms", t3 < 1500, t3+"ms");
console.log(`  timings: segment ${t1}ms  strings ${t2}ms  hilbert ${t3}ms`);

console.log(`\n10I-K: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
