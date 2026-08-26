//#region 12A STRUCTURE RENDERERS
/* Renderer contract unchanged (I3): read COMPUTED, never derive, and translate
   coordinates to facts and atoms to tiers. No mathematics below this line. */

const GB_TIER_FILL = t => t === "primary" ? "#f3c969" : t === "contributing" ? "#d99b4a" : null;

function gbRowList(c, o, env, rows, rowH, paint){
  c.save();
  c.font = "9px " + MONO;
  c.textBaseline = "middle";
  const top = 8, max = Math.floor((o.visual.h - top - 6) / rowH);
  for (let i = 0; i < Math.min(rows.length, max); i++){
    const y = top + i * rowH;
    paint(rows[i], i, y, rowH);
  }
  if (rows.length > max){
    c.fillStyle = "#65717e";
    c.fillText(`+${rows.length - max} more`, 12, top + max * rowH + rowH / 2);
  }
  c.restore();
  return { top, rowH, max };
}
function gbHitRow(o, lp, rows, rowH, top = 8){
  if (!rows || !rows.length) return -1;
  const i = Math.floor((lp.y - top) / rowH);
  return (i >= 0 && i < rows.length) ? i : -1;
}
function gbEllipsis(c, text, maxw){
  let s = String(text);
  if (c.measureText(s).width <= maxw) return s;
  while (s.length > 1 && c.measureText(s + "\u2026").width > maxw) s = s.slice(0, -1);
  return s + "\u2026";
}

/* ---------- the hypothesis board: the primary output surface ------------- */
RENDER["view.hypotheses"] = {
  rowH: 34,
  draw(c, o, d, env){
    c.save();
    if (!d || !d.hypotheses.length){
      c.fillStyle = "#65717e"; c.font = "9px " + MONO;
      c.fillText(d ? "No structure detected." : "Waiting for analysis\u2026", 12, 24);
      c.restore(); return;
    }
    c.font = "9px " + MONO; c.textBaseline = "middle";
    c.fillStyle = "#8fa0b2";
    wrap(c, d.summary, 12, 8, o.visual.w - 24, 12);
    const top = 42, rowH = this.rowH;
    const max = Math.floor((o.visual.h - top - 6) / rowH);
    for (let i = 0; i < Math.min(d.hypotheses.length, max); i++){
      const h = d.hypotheses[i], y = top + i * rowH;
      const t = env.tier({ t: "hypothesis", id: h.id });
      c.globalAlpha = env.hasSemantic && !t ? .3 : 1;
      c.fillStyle = t ? "rgba(243,201,105,.16)" : (i % 2 ? "#151b22" : "#181f27");
      c.fillRect(8, y, o.visual.w - 16, rowH - 2);

      // confidence bar: the number is the claim, so it gets the left gutter
      const cw = 34, conf = h.confidence;
      c.fillStyle = conf >= 0.8 ? "#4f9d6a" : conf >= 0.55 ? "#c2913c" : "#7a6a55";
      c.fillRect(10, y + 3, cw * conf, rowH - 8);
      c.strokeStyle = "#2b3644"; c.lineWidth = .7 / V.z;
      c.strokeRect(10, y + 3, cw, rowH - 8);
      c.fillStyle = "#dce4ec"; c.font = "700 8px " + MONO;
      c.fillText(`${Math.round(conf * 100)}%`, 12, y + rowH / 2 - 1);

      c.font = "600 9px " + MONO;
      c.fillStyle = t ? "#ffe6ab" : "#cfd8e2";
      c.fillText(gbEllipsis(c, h.title, o.visual.w - 60), 52, y + 11);
      c.font = "8px " + MONO;
      c.fillStyle = "#6e7c8b";
      const first = h.evidence[0] ? h.evidence[0].text : h.kind;
      c.fillText(gbEllipsis(c, `${h.kind} \u00b7 ${first}`, o.visual.w - 60), 52, y + 23);
    }
    c.globalAlpha = 1;
    if (d.hypotheses.length > max){
      c.fillStyle = "#65717e"; c.font = "8px " + MONO;
      c.fillText(`+${d.hypotheses.length - max} more`, 12, top + max * rowH + 8);
    }
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d || !d.hypotheses.length) return null;
    const i = gbHitRow(o, lp, d.hypotheses, this.rowH, 42);
    return i < 0 ? null : { kind: "hypothesis", eid: o.eid, index: i };
  }
};

/* ---------- decode chain ------------------------------------------------- */
RENDER["view.decodeChain"] = {
  rowH: 20,
  draw(c, o, d, env){
    c.save(); c.font = "9px " + MONO; c.textBaseline = "middle";
    if (!d || !d.chain){ c.fillStyle = "#65717e"; c.fillText("No input.", 12, 20); c.restore(); return; }
    for (let i = 0; i < d.chain.length && i * this.rowH + 24 < o.visual.h; i++){
      const s = d.chain[i], y = 8 + i * this.rowH;
      c.fillStyle = i ? "#1b232c" : "#141b23";
      c.fillRect(10, y, o.visual.w - 20, this.rowH - 3);
      c.fillStyle = i ? "#7fc2a8" : "#8fa0b2";
      c.fillText(i ? `\u2937 ${s.label}` : s.label, 16, y + this.rowH / 2 - 1);
      c.fillStyle = "#6e7c8b"; c.textAlign = "right";
      c.fillText(`${s.outLen.toLocaleString()} B${i ? `  ${Math.round(s.score * 100)}%` : ""}`, o.visual.w - 16, y + this.rowH / 2 - 1);
      c.textAlign = "left";
    }
    if (!d.decoded){
      c.fillStyle = "#65717e"; c.font = "8px " + MONO;
      c.fillText("no encoding detected; analysis runs on the raw bytes", 16, 8 + d.chain.length * this.rowH + 6);
    }
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d || !d.chain) return null;
    const i = gbHitRow(o, lp, d.chain, this.rowH);
    return i < 0 ? null : { kind: "decode-step", eid: o.eid, index: i };
  }
};

/* ---------- stride: autocorrelation curve with ranked candidates --------- */
RENDER["view.stride"] = {
  geom(o, d){ return { left: 28, bottom: 46, w: o.visual.w - 36, h: o.visual.h - 54 }; },
  draw(c, o, d, env){
    if (!d || !d.ac || !d.ac.lags.length){
      c.save(); c.fillStyle = "#65717e"; c.font = "9px " + MONO;
      c.fillText("Buffer too short for period analysis.", 12, 22); c.restore(); return;
    }
    const g = this.geom(o, d), lags = d.ac.lags, maxLag = d.maxLag || lags.length - 1;
    let peak = 0.001;
    for (let L = 2; L <= maxLag; L++) if (lags[L] > peak) peak = lags[L];
    c.save();
    c.strokeStyle = "#2b3644"; c.lineWidth = .8 / V.z;
    c.strokeRect(g.left, 8, g.w, g.h);
    c.beginPath();
    for (let L = 2; L <= maxLag; L++){
      const x = g.left + (L / maxLag) * g.w;
      const y = 8 + g.h - Math.max(0, lags[L]) / peak * (g.h - 4);
      L === 2 ? c.moveTo(x, y) : c.lineTo(x, y);
    }
    c.strokeStyle = "#4f8fb0"; c.lineWidth = 1 / V.z; c.stroke();

    for (const cand of (d.candidates || []).slice(0, 6)){
      const x = g.left + (cand.lag / maxLag) * g.w;
      const t = env.tier({ t: "stride", n: cand.lag });
      c.strokeStyle = t ? "#f3c969" : "rgba(226,152,64,.5)";
      c.lineWidth = (t ? 1.6 : .8) / V.z;
      c.beginPath(); c.moveTo(x, 8); c.lineTo(x, 8 + g.h); c.stroke();
      c.fillStyle = t ? "#ffe6ab" : "#9aa7b4"; c.font = "8px " + MONO;
      c.fillText(String(cand.lag), x + 2, 16);
    }
    c.fillStyle = "#65717e"; c.font = "8px " + MONO;
    c.fillText("lag \u2192", g.left, 8 + g.h + 11);
    c.fillText(`peak ${peak.toFixed(3)}`, g.left, 20);
    const top = (d.candidates || [])[0];
    if (top){
      c.fillStyle = "#9fb0c0";
      c.fillText(`best ${top.lag} B \u00b7 ${Math.round(top.score * 100)}% \u00b7 ${top.records} spans \u00b7 remainder ${top.remainder}`, g.left, o.visual.h - 22);
      c.fillStyle = "#65717e";
      c.fillText(gbEllipsis(c, top.evidence[0] ? top.evidence[0].text : "", g.w), g.left, o.visual.h - 10);
    }
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d || !d.candidates || !d.candidates.length) return null;
    const g = this.geom(o, d), maxLag = d.maxLag || 1;
    let best = null, bestDx = 9;
    for (const cand of d.candidates.slice(0, 6)){
      const x = g.left + (cand.lag / maxLag) * g.w;
      const dx = Math.abs(lp.x - x);
      if (dx < bestDx){ bestDx = dx; best = cand; }
    }
    return best ? { kind: "stride-lag", eid: o.eid, lag: best.lag } : null;
  }
};

/* ---------- columns: the recovered struct -------------------------------- */
RENDER["view.columns"] = {
  rowH: 16,
  draw(c, o, d, env){
    c.save(); c.font = "9px " + MONO; c.textBaseline = "middle";
    if (!d || d.idle || !d.fields.length){
      c.fillStyle = "#65717e";
      c.fillText(d && d.tooWide ? "Stride too wide to type." : "No record structure to decompose.", 12, 22);
      c.restore(); return;
    }
    c.fillStyle = "#8fa0b2";
    c.fillText(`stride ${d.stride} \u00b7 ${d.count.toLocaleString()} records \u00b7 ${Math.round(d.structuredRatio * 100)}% typed \u00b7 via ${d.chosenBy}`, 12, 14);
    const TYPE_COLOUR = {
      constant: "#5f7f9b", text: "#7fc2a8", enum: "#c2a04a", counter: "#e0912c",
      "monotonic integer": "#c98a4a", timestamp: "#d96f6f", float: "#9a7fc2",
      "length prefix": "#4f9d6a", random: "#41505f", varying: "#4a5866"
    };
    const barY = 26, barH = 12, px = (o.visual.w - 24) / d.stride;
    for (const f of d.fields){
      const t = env.tier({ t: "column", stride: d.stride, col: f.start });
      c.fillStyle = t ? "#f3c969" : (TYPE_COLOUR[f.type] || "#41505f");
      c.fillRect(12 + f.start * px, barY, Math.max(1, f.len * px - .5), barH);
    }
    const top = 46;
    const max = Math.floor((o.visual.h - top - 4) / this.rowH);
    for (let i = 0; i < Math.min(d.fields.length, max); i++){
      const f = d.fields[i], y = top + i * this.rowH;
      const t = env.tier({ t: "column", stride: d.stride, col: f.start });
      c.globalAlpha = env.hasSemantic && !t ? .32 : 1;
      if (t){ c.fillStyle = "rgba(243,201,105,.16)"; c.fillRect(10, y, o.visual.w - 20, this.rowH - 1); }
      c.fillStyle = TYPE_COLOUR[f.type] || "#41505f";
      c.fillRect(12, y + 4, 6, this.rowH - 8);
      c.fillStyle = "#8fa0b2"; c.font = "8px " + MONO;
      c.fillText(`+0x${f.start.toString(16).padStart(2, "0")}`, 24, y + this.rowH / 2);
      c.fillStyle = t ? "#ffe6ab" : "#cfd8e2"; c.font = "9px " + MONO;
      c.fillText(gbEllipsis(c, `${f.type}`, 96), 62, y + this.rowH / 2);
      c.fillStyle = "#6e7c8b"; c.font = "8px " + MONO;
      c.fillText(gbEllipsis(c, f.detail, o.visual.w - 190), 164, y + this.rowH / 2);
    }
    c.globalAlpha = 1;
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d || d.idle || !d.fields.length) return null;
    if (lp.y >= 26 && lp.y <= 38){
      const px = (o.visual.w - 24) / d.stride, col = Math.floor((lp.x - 12) / px);
      const i = d.fields.findIndex(f => col >= f.start && col < f.start + f.len);
      return i < 0 ? null : { kind: "column-field", eid: o.eid, index: i };
    }
    const i = gbHitRow(o, lp, d.fields, this.rowH, 46);
    return i < 0 ? null : { kind: "column-field", eid: o.eid, index: i };
  }
};

/* ---------- signatures --------------------------------------------------- */
RENDER["view.signatures"] = {
  rowH: 15,
  draw(c, o, d, env){
    c.save(); c.font = "9px " + MONO; c.textBaseline = "middle";
    if (!d || !d.rows.length){ c.fillStyle = "#65717e"; c.fillText("No known signatures or constants found.", 12, 22); c.restore(); return; }
    const GROUP = { format: "#4f8fb0", embedded: "#c2a04a", crypto: "#d96f6f" };
    gbRowList(c, o, env, d.rows, this.rowH, (r, i, y, rowH) => {
      const t = env.tier({ t: "signature", off: r.offset });
      c.globalAlpha = env.hasSemantic && !t ? .3 : 1;
      if (t){ c.fillStyle = "rgba(243,201,105,.16)"; c.fillRect(8, y, o.visual.w - 16, rowH - 1); }
      c.fillStyle = GROUP[r.group] || "#41505f";
      c.fillRect(10, y + 3, 5, rowH - 7);
      c.fillStyle = "#8fa0b2"; c.font = "8px " + MONO;
      c.fillText("0x" + r.offset.toString(16).toUpperCase().padStart(6, "0"), 22, y + rowH / 2);
      c.fillStyle = t ? "#ffe6ab" : "#cfd8e2"; c.font = "9px " + MONO;
      c.fillText(gbEllipsis(c, r.label, o.visual.w - 180), 90, y + rowH / 2);
      c.fillStyle = "#6e7c8b"; c.font = "8px " + MONO; c.textAlign = "right";
      c.fillText(r.detail || "", o.visual.w - 12, y + rowH / 2);
      c.textAlign = "left";
      c.globalAlpha = 1;
    });
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d || !d.rows.length) return null;
    const i = gbHitRow(o, lp, d.rows, this.rowH);
    return i < 0 ? null : { kind: "signature-hit", eid: o.eid, index: i };
  }
};

/* ---------- segments: a labelled ribbon over the whole buffer ------------ */
RENDER["view.segments"] = {
  draw(c, o, d, env){
    c.save(); c.font = "8px " + MONO; c.textBaseline = "middle";
    if (!d || !d.rows.length){ c.fillStyle = "#65717e"; c.fillText("No input.", 12, 22); c.restore(); return; }
    const LBL = {
      "text": "#7fc2a8", "utf-16 text": "#6fb0a0", "base64-encoded": "#8fb04f",
      "hex-encoded": "#a0b04f", "sparse or padded": "#41505f",
      "compressed": "#c2a04a", "encrypted or high-quality random": "#d96f6f",
      "machine code or structured binary": "#4f8fb0", "unclassified": "#4a5866", "empty": "#232c36"
    };
    const left = 12, w = o.visual.w - 24, ribbonY = 12, ribbonH = 26;
    for (const s of d.rows){
      const x0 = left + (s.start / d.n) * w, x1 = left + ((s.end + 1) / d.n) * w;
      const rangeAtoms = env.atoms ? env.atoms.ofType("byteRange") : [];
      const t = rangeAtoms.find(a => !(s.end < a.atom.start || s.start > a.atom.end));
      c.globalAlpha = env.hasSemantic && !t ? .3 : 1;
      c.fillStyle = t ? "#f3c969" : (LBL[s.label] || "#4a5866");
      c.fillRect(x0, ribbonY, Math.max(1, x1 - x0 - .5), ribbonH);
    }
    c.globalAlpha = 1;
    const rowH = 13, top = ribbonY + ribbonH + 8;
    const max = Math.floor((o.visual.h - top - 4) / rowH);
    for (let i = 0; i < Math.min(d.rows.length, max); i++){
      const s = d.rows[i], y = top + i * rowH;
      c.fillStyle = LBL[s.label] || "#4a5866";
      c.fillRect(12, y + 3, 5, rowH - 7);
      c.fillStyle = "#8fa0b2";
      c.fillText(`0x${s.start.toString(16).toUpperCase()}\u20130x${s.end.toString(16).toUpperCase()}`, 24, y + rowH / 2);
      c.fillStyle = "#cfd8e2";
      c.fillText(gbEllipsis(c, s.label, o.visual.w - 210), 130, y + rowH / 2);
      c.fillStyle = "#6e7c8b"; c.textAlign = "right";
      c.fillText(`H ${(s.entropy||0).toFixed(2)} \u00b7 ${(s.length||0).toLocaleString()} B`, o.visual.w - 12, y + rowH / 2);
      c.textAlign = "left";
    }
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d || !d.rows.length) return null;
    if (lp.y >= 12 && lp.y <= 38){
      const left = 12, w = o.visual.w - 24;
      const off = Math.round(((lp.x - left) / w) * d.n);
      const s = d.rows.find(r => off >= r.start && off <= r.end);
      return s ? { kind: "segment", eid: o.eid, start: s.start, end: s.end } : null;
    }
    const i = gbHitRow(o, lp, d.rows, 13, 46);
    return i < 0 ? null : { kind: "segment", eid: o.eid, start: d.rows[i].start, end: d.rows[i].end };
  }
};

/* ---------- strings ------------------------------------------------------ */
RENDER["view.strings"] = {
  rowH: 14,
  draw(c, o, d, env){
    c.save(); c.font = "9px " + MONO; c.textBaseline = "middle";
    if (!d || !d.strings.length){ c.fillStyle = "#65717e"; c.fillText("No strings above the minimum length.", 12, 22); c.restore(); return; }
    const list = d.notable.length >= 3 ? d.notable : d.strings;
    c.fillStyle = "#8fa0b2"; c.font = "8px " + MONO;
    c.fillText(`${d.count.toLocaleString()} strings \u00b7 showing ${list === d.notable ? "notable" : "all"}`, 12, 8);
    const top = 18, max = Math.floor((o.visual.h - top - 4) / this.rowH);
    for (let i = 0; i < Math.min(list.length, max); i++){
      const s = list[i], y = top + i * this.rowH;
      const t = env.tier({ t: "stringAt", start: s.start });
      c.globalAlpha = env.hasSemantic && !t ? .3 : 1;
      if (t){ c.fillStyle = "rgba(243,201,105,.16)"; c.fillRect(8, y, o.visual.w - 16, this.rowH - 1); }
      c.fillStyle = "#6e7c8b"; c.font = "8px " + MONO;
      c.fillText("0x" + s.start.toString(16).toUpperCase().padStart(6, "0"), 12, y + this.rowH / 2);
      c.fillStyle = s.enc === "utf-16le" ? "#9a7fc2" : "#7fc2a8";
      c.fillText(s.enc === "utf-16le" ? "w" : "a", 76, y + this.rowH / 2);
      c.fillStyle = t ? "#ffe6ab" : "#cfd8e2"; c.font = "9px " + MONO;
      c.fillText(gbEllipsis(c, s.text, o.visual.w - 104), 88, y + this.rowH / 2);
      c.globalAlpha = 1;
    }
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d || !d.strings.length) return null;
    const list = d.notable.length >= 3 ? d.notable : d.strings;
    const i = gbHitRow(o, lp, list, this.rowH, 18);
    if (i < 0) return null;
    return { kind: "string-hit", eid: o.eid, index: d.strings.indexOf(list[i]) };
  }
};

/* ---------- digraph: byte n against byte n+1 ----------------------------- */
RENDER["view.digraph"] = {
  draw(c, o, d, env){
    if (!d) return;
    const key = rasterKey(o, "digraph|" + d.n);
    let ras = cacheGet(key);
    if (!ras){
      // log scale: the interesting structure lives four orders of magnitude
      // below the peak, and a linear ramp renders every real buffer as one dot
      const lmax = Math.log1p(d.max);
      ras = buildRaster(256, (r, col) => {
        const v = d.m[(r << 8) | col];
        if (!v) return [10, 14, 19];
        const q = Math.log1p(v) / lmax;
        return [20 + 200 * q, 40 + 130 * q, 62 + 60 * (1 - q)];
      });
      cacheSet(key, ras);
    }
    const pad = 18, side = Math.min(o.visual.w, o.visual.h) - pad * 2;
    c.save();
    c.imageSmoothingEnabled = false;
    c.globalAlpha = env.hasSemantic && !env.tier({ t: "object", eid: o.eid }) ? .35 : 1;
    c.drawImage(ras, pad, pad, side, side);
    c.globalAlpha = 1;
    c.strokeStyle = "#2b3644"; c.lineWidth = .8 / V.z;
    c.strokeRect(pad, pad, side, side);
    c.fillStyle = "#65717e"; c.font = "8px " + MONO;
    c.fillText("b[n]\u2192", pad, pad - 6);
    c.fillText(`coverage ${(d.coverage * 100).toFixed(1)}%`, pad, pad + side + 11);
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d) return null;
    const pad = 18, side = Math.min(o.visual.w, o.visual.h) - pad * 2;
    const a = Math.floor(((lp.y - pad) / side) * 256), b = Math.floor(((lp.x - pad) / side) * 256);
    if (a < 0 || b < 0 || a > 255 || b > 255) return null;
    return { kind: "digraph-cell", eid: o.eid, a, b };
  }
};

/* ---------- Hilbert: locality-preserving class map ----------------------- */
RENDER["view.hilbert"] = {
  draw(c, o, d, env){
    if (!d) return;
    const key = rasterKey(o, "hilbert|" + d.used + "|" + d.span);
    let ras = cacheGet(key);
    if (!ras){
      const px = new Uint8Array(d.side * d.side * 3);
      for (let i = 0; i < d.used; i++){
        const h = d.cellEntropy[i] / 8, p = d.cellPrint[i];
        // hue by character, not by mean value: high entropy red, text green,
        // sparse near-black. Mean value tells you nothing about what a span IS.
        const r = h > 0.93 ? 210 : p > 0.9 ? 60 : 40 + 120 * h;
        const g = p > 0.9 ? 180 : 50 + 90 * h;
        const b = h > 0.93 ? 90 : 70 + 80 * (1 - h);
        const q = (d.ys[i] * d.side + d.xs[i]) * 3;
        px[q] = r; px[q + 1] = g; px[q + 2] = b;
      }
      ras = buildRaster(d.side, (row, col) => {
        const q = (row * d.side + col) * 3;
        return [px[q], px[q + 1], px[q + 2]];
      });
      cacheSet(key, ras);
    }
    const pad = 16, side = Math.min(o.visual.w, o.visual.h) - pad * 2;
    c.save();
    c.imageSmoothingEnabled = false;
    c.globalAlpha = env.hasSemantic && !env.tier({ t: "object", eid: o.eid }) ? .35 : 1;
    c.drawImage(ras, pad, pad, side, side);
    c.globalAlpha = 1;
    c.fillStyle = "#65717e"; c.font = "8px " + MONO;
    c.fillText(`${d.span} B/cell \u00b7 Hilbert order ${d.order}`, pad, pad + side + 11);
    c.restore();
  },
  semanticHitTest(o, lp, d){
    if (!d) return null;
    const pad = 16, side = Math.min(o.visual.w, o.visual.h) - pad * 2;
    const x = Math.floor(((lp.x - pad) / side) * d.side), y = Math.floor(((lp.y - pad) / side) * d.side);
    if (x < 0 || y < 0 || x >= d.side || y >= d.side) return null;
    for (let i = 0; i < d.used; i++) if (d.xs[i] === x && d.ys[i] === y)
      return { kind: "segment", eid: o.eid, start: i * d.span, end: Math.min(d.length - 1, (i + 1) * d.span - 1) };
    return null;
  }
};
//#endregion
