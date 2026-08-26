const zlib = require("zlib"), crypto = require("crypto");
const G = require("./10E-signatures.js");
let pass = 0, fail = 0;
const ok = (n, c, x) => c ? pass++ : (fail++, console.log("FAIL", n, x === undefined ? "" : x));

// AES S-box must match the published table
const S = G._aesSbox();
ok("aes sbox 0x00", S[0x00] === 0x63, S[0].toString(16));
ok("aes sbox 0x53", S[0x53] === 0xED, S[0x53].toString(16));
ok("aes sbox 0xFF", S[0xFF] === 0x16, S[0xFF].toString(16));
ok("aes sbox 0x01", S[0x01] === 0x7C, S[1].toString(16));
ok("aes sbox is permutation", new Set(S).size === 256);
ok("gmul 0x57*0x83", G._gmul(0x57, 0x83) === 0xC1, G._gmul(0x57,0x83).toString(16));

// identifyFormat
ok("id png", G.identifyFormat(new Uint8Array([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,1,2])).id === "png");
ok("id elf", G.identifyFormat(new Uint8Array([0x7f,0x45,0x4c,0x46,2,1,1,0])).id === "elf");
ok("id gzip", G.identifyFormat(new Uint8Array(zlib.gzipSync(Buffer.from("x")))).id === "gzip");
ok("id none", G.identifyFormat(new Uint8Array([1,2,3,4,5,6,7,8])) === null);
// longest match wins over weak
const webp = Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WEBP")]);
ok("id webp beats riff-wav", G.identifyFormat(new Uint8Array(webp)).id === "webp", G.identifyFormat(new Uint8Array(webp)));

// carve: embed a PNG and a gzip inside random noise
const noise = crypto.randomBytes(20000);
const png = Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]);
const gz = zlib.gzipSync(Buffer.from("hello"));
noise.set(png, 5000);
noise.set(gz.subarray(0, 3), 12345);
const carved = G.carveSignatures(new Uint8Array(noise));
ok("carve finds png", carved.hits.some(h => h.id === "png" && h.offset === 5000), JSON.stringify(carved.hits.slice(0,5)));
ok("carve finds gzip", carved.hits.some(h => h.id === "gzip" && h.offset === 12345));

// crypto constants: plant an AES sbox and SHA-256 K table in a blob
const blob = Buffer.alloc(40000);
crypto.randomFillSync(blob);
blob.set(Buffer.from(S), 8192);
const k = Buffer.alloc(64);
[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174]
 .forEach((v,i)=>k.writeUInt32BE(v>>>0, i*4));
blob.set(k, 20000);
const sc = G.scanCryptoConstants(new Uint8Array(blob));
ok("const finds aes sbox", sc.hits.some(h => h.id === "aes_sbox" && h.offset === 8192), JSON.stringify(sc.hits));
ok("const finds sha256 k", sc.hits.some(h => h.id === "sha256_k_be" && h.offset === 20000));
ok("algo summary has AES", sc.algos.some(a => a.algo === "AES"));
ok("algo summary has SHA-256", sc.algos.some(a => a.algo === "SHA-256"));

// no false positives on pure noise
const clean = G.scanCryptoConstants(new Uint8Array(crypto.randomBytes(200000)));
ok("no const false positives", clean.hits.length === 0, JSON.stringify(clean.hits.slice(0,3)));

// permutation finder
const perm = Buffer.alloc(3000);
crypto.randomFillSync(perm);
perm.set(Buffer.from(S), 1000);
const perms = G.findPermutationTables(new Uint8Array(perm));
ok("perm finds sbox", perms.some(p => p.offset === 1000), JSON.stringify(perms.slice(0,3)));

// identity table detection
const idt = Buffer.alloc(600);
for (let i = 0; i < 256; i++) idt[100 + i] = i;
const p2 = G.findPermutationTables(new Uint8Array(idt));
ok("perm flags identity", p2.some(p => p.offset === 100 && p.identity));

// timing
const big = new Uint8Array(crypto.randomBytes(4 * 1024 * 1024));
let t = Date.now(); G.scanCryptoConstants(big); const tc = Date.now() - t;
t = Date.now(); G.carveSignatures(big); const tv = Date.now() - t;
ok("const scan 4MB < 900ms", tc < 900, tc + "ms");
ok("carve 4MB < 500ms", tv < 500, tv + "ms");
console.log(`  timings: constants ${tc}ms  carve ${tv}ms`);

console.log(`\n10E-sig: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
