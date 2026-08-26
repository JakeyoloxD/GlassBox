const zlib = require("zlib");
const E = require("./10F-codecs.js");
let pass = 0, fail = 0;
function ok(name, cond, extra){ if (cond){ pass++; } else { fail++; console.log("FAIL", name, extra === undefined ? "" : extra); } }
const B = s => new Uint8Array(Buffer.from(s, "utf8"));
const S = u => Buffer.from(u).toString("utf8");

// base64
ok("b64 basic", S(E.decodeBase64(B("SGVsbG8gd29ybGQh"))) === "Hello world!");
ok("b64 pad", S(E.decodeBase64(B("SGVsbG8="))) === "Hello");
ok("b64 ws", S(E.decodeBase64(B("SGVs\nbG8g\td29ybGQh"))) === "Hello world!");
ok("b64url", S(E.decodeBase64(B("-_-_aGk"), E.RT_B64U)).endsWith("hi"));
ok("b64 reject", E.decodeBase64(B("!!!!")) === null);

// hex
ok("hex", S(E.decodeHex(B("48656c6c6f"))) === "Hello");
ok("hex 0x", S(E.decodeHex(B("0x48656c6c6f"))) === "Hello");
ok("hex odd", E.decodeHex(B("48656c6c6")) === null);

// base32
const b32 = Buffer.from("Hello world!").toString("base64"); // not b32; use manual
ok("b32", S(E.decodeBase32(B("JBSWY3DPEBLW64TMMQQQ===="))) === "Hello World!", S(E.decodeBase32(B("JBSWY3DPEBLW64TMMQQQ===="))));

// base58
ok("b58", S(E.decodeBase58(B("StV1DL6CwTryKyV"))) === "hello world", S(E.decodeBase58(B("StV1DL6CwTryKyV"))));

// ascii85
ok("a85", S(E.decodeAscii85(B("<~87cURD]i,\"Ebo80~>"))) === "Hello World!", S(E.decodeAscii85(B("<~87cURD]i,\"Ebo80~>"))));

// url / qp
ok("url", S(E.decodeUrl(B("a%20b%2Bc"))) === "a b+c");
ok("qp", S(E.decodeQuotedPrintable(B("caf=C3=A9"))) === "café");

// inflate: stored, fixed, dynamic
const payloads = [
  Buffer.alloc(0),
  Buffer.from("A"),
  Buffer.from("hello hello hello hello hello"),
  Buffer.from("x".repeat(100000)),
  require("crypto").randomBytes(50000),
  Buffer.from(JSON.stringify({ a: 1, b: "y".repeat(5000), c: [1,2,3] }))
];
for (let i = 0; i < payloads.length; i++){
  const p = payloads[i];
  const gz = new Uint8Array(zlib.gzipSync(p));
  const zl = new Uint8Array(zlib.deflateSync(p));
  const rw = new Uint8Array(zlib.deflateRawSync(p));
  const st = new Uint8Array(zlib.deflateRawSync(p, { level: 0 }));
  const g = E.decodeGzip(gz), z = E.decodeZlib(zl), r = E.decodeDeflateRaw(rw), s0 = E.decodeDeflateRaw(st);
  if (p.length === 0){
    ok("gzip empty ok", g === null || g.length === 0);
  } else {
    ok("gzip #" + i, g && Buffer.compare(Buffer.from(g), p) === 0, g && g.length);
    ok("zlib #" + i, z && Buffer.compare(Buffer.from(z), p) === 0, z && z.length);
    ok("raw  #" + i, r && Buffer.compare(Buffer.from(r), p) === 0, r && r.length);
    ok("stored #" + i, s0 && Buffer.compare(Buffer.from(s0), p) === 0, s0 && s0.length);
  }
}

// PEM
const der = require("crypto").randomBytes(200);
const pem = "-----BEGIN CERTIFICATE-----\n" + der.toString("base64").match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";
ok("pem", Buffer.compare(Buffer.from(E.decodePem(B(pem))), der) === 0);

// JWT
const jwt = [Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url"),
             Buffer.from('{"sub":"1234567890","name":"Jake","iat":1516239022}').toString("base64url"),
             "sig"].join(".");
const jp = E.decodeJwtPayload(B(jwt));
ok("jwt", jp && S(jp).includes('"sub"'), jp && S(jp));

// ladder: base64(gzip(text))
const text = "The quick brown fox jumps over the lazy dog. ".repeat(40);
const nested = Buffer.from(zlib.gzipSync(Buffer.from(text))).toString("base64");
const chain = E.decodeLadder(B(nested));
ok("ladder depth", chain.length === 3, chain.map(c => c.id).join(">"));
ok("ladder ids", chain.map(c => c.id).join(">") === "raw>base64>gzip", chain.map(c => c.id).join(">"));
ok("ladder final", S(chain[chain.length - 1].bytes) === text);

// ladder: triple - hex(base64(zlib(text)))
const trip = Buffer.from(Buffer.from(zlib.deflateSync(Buffer.from(text))).toString("base64")).toString("hex");
const c3 = E.decodeLadder(B(trip));
ok("ladder triple", c3.map(c => c.id).join(">") === "raw>hex>base64>zlib", c3.map(c => c.id).join(">"));

// ladder must NOT chew plain English into noise
const eng = B("Dear Jake, the assessment report is attached. Regards, Ava. ".repeat(10));
const ce = E.decodeLadder(eng);
ok("ladder leaves prose alone", ce.length === 1, ce.map(c => c.id).join(">"));

// ladder must not chew random bytes
const rnd = new Uint8Array(require("crypto").randomBytes(4096));
const cr = E.decodeLadder(rnd);
ok("ladder leaves entropy alone", cr.length === 1, cr.map(c => c.id).join(">"));

// bomb guard
try { E.inflateRaw(new Uint8Array(zlib.deflateRawSync(Buffer.alloc(1<<20))), 0, 1024); ok("bomb guard", false); }
catch(e){ ok("bomb guard", /output limit/.test(e.message), e.message); }

console.log(`\n10E: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
