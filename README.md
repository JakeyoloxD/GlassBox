# Glassbox

**Give it bytes. It tells you what they are, and shows you why.**

Glassbox is a single-file, fully offline workbench for working out what an unknown
blob of data actually is. You hand it a file or a pasted string; it unwraps any
encoding it recognises, looks for record structure, entropy boundaries, strings,
file signatures and weak cipher behaviour, and then puts a ranked set of claims on
screen — each one carrying the evidence and the byte ranges that produced it.

It is one HTML file. No install, no build step, no network. It runs from a USB
stick on a locked-down assessment box, and nothing you load ever leaves the page.

Version 0.1.0 · document format 1 · `.glass`

---

## Why it exists

Most byte tools show you a measurement and leave the thinking to you. A histogram
tells you there is a peak at lag 48. Glassbox is built to say the next part out
loud: *this is a 48-byte record format, 96 records fit exactly, offset 0x14 is a
big-endian timestamp, here are the bytes, disagree with me.*

The rules the hypothesis engine holds itself to are worth knowing, because they
tell you how much to trust what you are reading:

- No hypothesis without at least one piece of evidence.
- No evidence without a byte range or a measured number.
- Confidence is bounded by the weakest link in the chain that produced it.
- A hypothesis derived from decoded bytes says so, and cites the decode.

Where it touches cryptography it names the metric rather than delivering a bare
"secure" or "broken" — you get *uniformity 4, optimum 4 for 8-bit*, not a badge.

---

## Getting started

Open `Glassbox.html` in a modern browser. Chrome, Edge and Firefox are all fine.
There is no server to run and nothing to configure.

The input dialog opens by itself on first load. You have two ways in:

**Paste or type.** The box reads what you give it and picks an interpretation:

| What you paste | How it is read |
|---|---|
| A run of `0` and `1`, 8 characters or more | Packed bits, MSB first |
| Even-length hex, 4 characters or more, `0x` prefix optional | Bytes |
| Anything else | UTF-8 text |

Whitespace is stripped before the test, so a spaced-out hex dump works. The
interpretation it chose is recorded as the source kind and shown in the status
line, so the provenance stays honest.

**Open a file.** `Open .txt / .bin` on the Input tab. Only those two extensions
are accepted, and the ceiling is 8 MB. A `.txt` file containing raw binary is
fine and common — the extension is a picker constraint, not a claim about
content.

Load something and the whole workspace recomputes. Press `F` at any point to fit
everything back on screen.

---

## Reading the workspace

Fourteen linked panels, laid out left to right. They are chained, not
free-floating: every analysis hangs off the **decoded** bytes rather than the raw
input, so a file that arrives as base64 wrapping a gzip gets measured as its
contents instead of its envelope.

```
  Byte map ──▶ Decode chain ──┬──▶ Hypothesis board   ◀── evidence from all below
                              ├──▶ Signatures
                              ├──▶ Stride ──▶ Columns
                              ├──▶ Segments
                              ├──▶ Strings
                              ├──▶ Digraph · Hilbert
                              └──▶ Bit structure · Byte frequency · Entropy · Repetition
```

**Start at the hypothesis board.** It carries the headline verdict and the ranked
claims. Everything else in the workspace exists to be the evidence behind it.

| Verdict | Meaning |
|---|---|
| `TEXT / PLAINTEXT` | Readable content, no hidden structure worth chasing |
| `ENCODED / WRAPPED DATA` | An envelope was unwrapped; the claims below describe the contents |
| `CRYPTO COMPONENT FOUND` | A cipher table or constant is embedded in the data |
| `REPEATED BLOCK STRUCTURE` | A weakness: ECB-style block repetition, or repeating-key XOR |
| `STRUCTURE DETECTED` | Fixed-width records, segments or repeats |
| `HIGH ENTROPY — NO STRUCTURE FOUND` | Encrypted or compressed, and not leaking anything |

Claims are tagged by kind: format, encoding, record structure, field,
cryptography, region, repetition, strings, content class.

Click a claim and the evidence highlights across every other panel at once. That
cross-highlight is the point of the tool — it is how you check a claim instead of
believing it.

---

## The decode chain

Before anything is measured, Glassbox tries to unwrap the input. It applies up to
six layers, taking the highest-confidence candidate at each step and stopping when
nothing scores above 0.45 or when it detects a loop.

Recognised: PEM, JWT, gzip, zlib, hexadecimal, base64, base64url, base32, base58,
ascii85, percent-encoding, quoted-printable, raw deflate.

The chain panel shows each step with its length and score, and lists the
alternatives it rejected. A config backup that arrives base64-wrapped around a
gzip stream comes out the far side as readable JSON, and every claim downstream
cites the decode it came from.

---

## Drilling into cryptography

When Glassbox finds a 256-byte permutation embedded in the data — an S-box —
you can open it and go deeper. Two routes:

- Click through from a `CRYPTO COMPONENT FOUND` claim on the board.
- Type `sbox`, which scans for a candidate and opens the best one.

You can also nominate bytes yourself. Drag a box on the byte map to select a
range, then press `S` or type `region`. It needs at least 256 bytes.

That opens the crypto cluster: the S-box grid, its **DDT** (differential
distribution table), **LAT** (linear approximation table), **Walsh spectrum** and
**ANF** (algebraic normal form), plus a field microscope for GF(2⁸) arithmetic and
a Walsh butterfly ancestry view. Selecting a cell in one lights the mathematically
related cells in the others.

Each view reports its own metric with a band — differential uniformity against the
optimum for the bit width, nonlinearity against `2^(m/2)`, algebraic degree against
`m-1`. Metrics, not verdicts.

---

## Controls

**Keyboard** (canvas focus, no dialog open)

| Key | Action |
|---|---|
| `F` | Fit everything on screen |
| `S` | Read the selected byte region as an S-box |
| `/` | Jump to the command line |
| `Esc` | Clear selection and highlights |
| `Ctrl+Z` / `Ctrl+Y` | Undo / redo |

**Mouse**

Wheel zooms about the cursor, from 0.15× to 12×. Middle-drag or Alt-drag pans.
Drag on the byte map to mark a region.

**Command line** — press `/`, then:

| Command | Action |
|---|---|
| `input` (or `welcome`) | Open the input dialog |
| `stats` | Byte count, entropy, distinct values |
| `sbox` | Find and open an S-box candidate |
| `region` / `region clear` | Read the selection as an S-box / drop all regions |
| `fit` | Fit everything on screen |
| `clear` | Clear the trace and selection |
| `undo` · `redo` · `save` | As named |
| `help` | List the commands |

Dispatch is allow-listed. There is no `eval` and no `new Function` anywhere in
the app.

---

## Saving your work

`Save snapshot` writes a `.glass` file: JSON holding the document, the loaded
bytes and every object's state. Reopen it with `Open .glass` and you are back
where you were, complete with any S-box clusters you opened.

`Export PNG` on the View tab captures the canvas as an image for a report.

---

## Learning it

Two things on the **Learn** tab if you or a colleague are new to this material:

- **Guided investigation** — an 11-step walkthrough of the evidence-first
  workflow, with no automatic camera movement so you keep your bearings.
- **Glossary** — 29 searchable terms covering the structural and cryptographic
  vocabulary the interface uses.

---

## Limits and constraints

| | |
|---|---|
| Maximum input | 8 MB |
| Accepted file types | `.txt`, `.bin` for data; `.glass` for saved investigations |
| Objects per document | 512 |
| Relations per document | 4,096 |
| Undo history | 24 MB |
| S-box width | up to 8 bits (256 entries) |

The page ships a strict Content-Security-Policy with `default-src 'none'` and
`connect-src 'none'`. It cannot make a network request even if something tried.
All parsing goes through a prototype-pollution-resistant JSON reader.

---

## Verifying the build

The app carries its own test suite — 72 tests including 10 acceptance criteria
that are enforced by scanning the source rather than by trusting discipline. It
checks the crypto kernel against published AES values, verifies all 2,048 Walsh
butterfly equations, and confirms the architectural rules still hold.

Open the browser console and run:

```js
runSelfTests()
```

The report prints pass and fail counts, the acceptance tally, and a line per test.

*Note: the `test` command was removed from the command line in this build, so the
console is currently the only way to run the suite.*

---

## Known gaps

- **Embedded encoded regions are not carved.** The decode ladder only tries to
  decode the buffer as a whole. A base64 artefact sitting in the middle of a
  larger file is found by the strings pass but not unwrapped.
- **Column typing needs a clean stride.** Where record structure is noisy or
  interleaved the field types are best-effort.
