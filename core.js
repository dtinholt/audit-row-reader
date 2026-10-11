/* Audit Row Reader, core logic. No DOM in this file.
   Row format: tools/decision-head/docs/audit-log.md. Chain rule: tools/seal.py.
   Loaded as a plain script in the page (global ARR) and usable from node (module.exports). */
"use strict";
(function (root) {
const C = {};

/* ---------- SHA-256, plain JS (works on file:// where crypto.subtle may be absent) ---------- */
const SHA_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const ENC = new TextEncoder();
const W64 = new Uint32Array(64);
function sha256hex(str) {
  const msg = ENC.encode(str);
  const l = msg.length, nBlocks = ((l + 9 + 63) >> 6);
  const buf = new Uint8Array(nBlocks * 64);
  buf.set(msg); buf[l] = 0x80;
  const bits = l * 8, dv = new DataView(buf.buffer);
  dv.setUint32(buf.length - 8, Math.floor(bits / 4294967296)); dv.setUint32(buf.length - 4, bits >>> 0);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = W64;
  for (let off = 0; off < buf.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i-15], b = w[i-2];
      const s0 = ((a>>>7)|(a<<25)) ^ ((a>>>18)|(a<<14)) ^ (a>>>3);
      const s1 = ((b>>>17)|(b<<15)) ^ ((b>>>19)|(b<<13)) ^ (b>>>10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      const t1 = (h + S1 + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
      const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
  }
  return [h0,h1,h2,h3,h4,h5,h6,h7].map(x => (x >>> 0).toString(16).padStart(8, "0")).join("");
}
C.sha256hex = sha256hex;

/* ---------- lines ---------- */
C.splitLines = function (text) {
  const a = text.split("\n");
  if (a.length && a[a.length - 1] === "") a.pop();
  return a.map(l => l.endsWith("\r") ? l.slice(0, -1) : l);
};
/* Streaming splitter with the same rule as splitLines / seal.split_lines.
   push(chunk) returns the complete lines so far; end() returns the last one, if any. */
C.LineSplitter = class {
  constructor() { this.rest = ""; this.bareCR = 0; }
  _fix(l) { if (l.endsWith("\r")) l = l.slice(0, -1); if (l.indexOf("\r") >= 0) this.bareCR++; return l; }
  push(chunk) {
    const s = this.rest + chunk, out = [];
    let start = 0, i;
    while ((i = s.indexOf("\n", start)) >= 0) { out.push(this._fix(s.slice(start, i))); start = i + 1; }
    this.rest = s.slice(start);
    return out;
  }
  end() { const r = this.rest; this.rest = ""; return r === "" ? [] : [this._fix(r)]; }
};

/* ---------- seals ---------- */
const ZERO = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
C.ZERO = ZERO;
C.CHAIN_HEADER = '# audit-row-reader chain v2: h[i] = sha256(h[i-1] + "\\n" + line[i]); h[-1] = the start hash below (64 zeros for a first file)';
C.chainStep = (prev, line) => sha256hex(prev + "\n" + line);
C.chainOf = function (lines, start) {
  let prev = start || ZERO; const out = new Array(lines.length);
  for (let i = 0; i < lines.length; i++) { prev = sha256hex(prev + "\n" + lines[i]); out[i] = prev; }
  return out;
};
/* Line endings (CRLF, bare CR) and hex case are normalised; a seal with no readable hash
   lines and no seal header is marked unreadable, so the page gives no verdict from it. */
C.parseSeal = function (text) {
  let start = ZERO, file = null, bad = 0, header = false; const hashes = [];
  for (const ln of C.splitLines(String(text).replace(/\r\n?/g, "\n"))) {
    let s = ln.trim(); if (!s) continue;
    if (s[0] === "#") {
      if (/^# audit-row-reader chain/.test(s)) header = true;
      let m = /^#\s*start:\s*([0-9a-fA-F]{64})\s*$/.exec(s); if (m) start = m[1].toLowerCase();
      m = /^#\s*file:\s*(.+?)\s*$/.exec(s); if (m) file = m[1];
      continue;
    }
    if (/^[0-9a-fA-F]{64}$/.test(s)) s = s.toLowerCase();
    if (HEX64.test(s)) hashes.push(s); else bad++;
  }
  return { start, file, hashes, bad, header, unreadable: hashes.length === 0 && (bad > 0 || !header) };
};
C.isSealText = function (text) {
  if (/^# audit-row-reader chain/.test(text)) return true;
  const ls = C.splitLines(String(text).replace(/\r\n?/g, "\n")).map(s => s.trim()).filter(Boolean);
  return ls.length > 0 && ls.length <= 5e6 && ls.every(s => /^[0-9a-fA-F]{64}$/.test(s));
};
C.sealText = function (lines, start, name) {
  start = start || ZERO;
  const ch = C.chainOf(lines, start);
  return [C.CHAIN_HEADER, "# start: " + start].concat(name ? ["# file: " + name] : [], ch).join("\n") + "\n";
};
C.sealFinal = seal => seal.hashes.length ? seal.hashes[seal.hashes.length - 1] : seal.start;
/* Compare a computed chain with a seal's hashes. Rows are 1-based within the file. */
C.compareSeal = function (mine, sealed) {
  const m = Math.min(mine.length, sealed.length);
  for (let i = 0; i < m; i++) if (mine[i] !== sealed[i]) return { first: i + 1, kind: "edit" };
  if (mine.length < sealed.length) return { first: mine.length + 1, kind: "truncated", missing: sealed.length - mine.length };
  if (mine.length > sealed.length) return { first: null, kind: "appended", appendedFrom: sealed.length + 1 };
  return { first: null, kind: "ok" };
};
C.verifySeal = function (lines, sealed, start) {
  const hashes = Array.isArray(sealed) ? sealed : sealed.hashes;
  start = Array.isArray(sealed) ? (start || ZERO) : sealed.start;
  return C.compareSeal(C.chainOf(lines, start), hashes);
};

/* ---------- series verification ----------
   files: [{name, n (rows), seal|null, mine (chain from seal.start)|null, lineHashes|null, prev: [prev_hash per row]}]
   in series order. Returns {method, perFile, boundaries, first: {file, row}|null, notes}. */
C.verifySeries = function (files, method) {
  const out = { method, perFile: [], boundaries: [], first: null, notes: [] };
  const setFirst = (file, row) => { if (!out.first || file < out.first.file || (file === out.first.file && row < out.first.row)) out.first = { file, row }; };
  if (method === "seal") {
    files.forEach((f, k) => {
      if (!f.seal) { out.perFile.push({ k, sealed: false }); return; }
      const res = C.compareSeal(f.mine || [], f.seal.hashes);
      out.perFile.push(Object.assign({ k, sealed: true }, res));
      if (res.first) setFirst(k, res.first);
    });
    if (files[0] && files[0].seal && files[0].seal.start !== ZERO) out.notes.push("firstStartsLater");
    for (let k = 1; k < files.length; k++) {
      const a = files[k - 1], b = files[k];
      let ok, why;
      if (!a.seal || !b.seal) { ok = null; why = "noSeal"; }
      else if (b.seal.start !== C.sealFinal(a.seal)) { ok = false; why = "startMismatch"; }
      else if (a.n > a.seal.hashes.length) { ok = false; why = "rowsPastSeal"; }
      else if (out.perFile[k - 1].first) { ok = true; why = "linkHoldsFileBroken"; }
      else { ok = true; why = "holds"; }
      out.boundaries.push({ from: k - 1, to: k, ok, why });
      if (ok === false) setFirst(k, 1);
    }
  } else if (method === "prev_hash") {
    // rows joined across files; row 1 of file k must carry the hash of the last row of file k-1
    let prevHash = null, broke = false;
    files.forEach((f, k) => {
      for (let i = 0; i < f.n; i++) {
        const global0 = k === 0 && i === 0;
        if (!global0 && !broke && f.prev[i] !== prevHash) { broke = true; setFirst(k, i + 1); }
        prevHash = f.lineHashes[i];
      }
      if (k === 0 && f.n && f.prev[0] != null && f.prev[0] !== ZERO) out.notes.push("firstPointsEarlier");
      out.perFile.push({ k });
    });
    for (let k = 1; k < files.length; k++) {
      let ok, why;
      if (out.first && out.first.file === k && out.first.row === 1) { ok = false; why = "prevMismatch"; }
      else if (out.first && (out.first.file < k)) { ok = null; why = "brokeEarlier"; }
      else if (!files[k].n || !files[k - 1].n) { ok = null; why = "emptyFile"; }
      else { ok = true; why = "holds"; }
      out.boundaries.push({ from: k - 1, to: k, ok, why });
    }
  }
  return out;
};

/* ---------- parse + normalise ---------- */
function scoreLabel(score, keys) {
  if (typeof score !== "number") return null;
  const byName = keys.find(k => Number(k) === score);
  if (byName !== undefined) return byName;
  return keys[score - 1] ?? null;
}
const inUnit = v => typeof v === "number" && isFinite(v) && v >= 0 && v <= 1;

/* ---------- redaction screen: counts only, nothing kept ---------- */
const SKIP_FMT = { request_hash: /^[0-9a-f]{64}(-deliberate)?$/, request_id: /^[0-9a-f]{32}$/, original_trace_id: /^[0-9a-f]{32}$/,
  calibration_version: /^([0-9a-f]{64})?$/, prev_hash: /^[0-9a-f]{64}$/, ts: /^\d{4}-\d\d-\d\dT[\d:.]+Z$/ };
const RX_EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)*\.[A-Z]{2,}/i;
const RX_PHONE = /(?:\+|\b00)?\d[\d ().\/-]{6,20}\d/g;
const RX_IBAN = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g;
const RX_NAME = /(?:^|[^\p{L}])(?:(?:Mr|Mrs|Ms|Dr)\.? )?\p{Lu}\p{Ll}+(?:(?: (?:van|von|de|der|den|du|di|da|del|la|le|ten|ter|bin|al))*[ -]\p{Lu}\p{Ll}+)+/u;
C.ibanValid = function (s) {
  const t = s.replace(/ /g, "").toUpperCase();
  if (t.length < 15 || t.length > 34 || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(t)) return false;
  const r = t.slice(4) + t.slice(0, 4);
  let mod = 0;
  for (const ch of r) { const v = ch >= "A" ? String(ch.charCodeAt(0) - 55) : ch; for (const d of v) mod = (mod * 10 + (d.charCodeAt(0) - 48)) % 97; }
  return mod === 1;
};
C.scanText = function (s) {
  const hit = { email: false, phone: false, iban: false, name: false };
  if (typeof s !== "string" || s.length < 4) return hit;
  if (s.length > 20000) s = s.slice(0, 20000);
  hit.email = RX_EMAIL.test(s);
  // blank out only the IBAN spans that pass their checksum, so a phone number beside one still counts
  let m, rest = "", last = 0; RX_IBAN.lastIndex = 0;
  while ((m = RX_IBAN.exec(s))) if (C.ibanValid(m[0])) { hit.iban = true; rest += s.slice(last, m.index) + " "; last = m.index + m[0].length; }
  const sp = hit.iban ? rest + s.slice(last) : s;
  RX_PHONE.lastIndex = 0;
  while ((m = RX_PHONE.exec(sp))) {
    const t = m[0], digits = t.replace(/\D/g, "").length;
    if (digits < 9 || digits > 15) continue;
    if (/^\d+\.\d+$/.test(t) || /\d{4}-\d\d-\d\d/.test(t)) continue;
    hit.phone = true; break;
  }
  hit.name = RX_NAME.test(s);
  return hit;
};
C.RED_KINDS = ["email", "phone", "iban", "name"];
/* fields and redByField are Maps, so a key such as __proto__, constructor or toString is just a name */
C.newAcc = () => ({ red: { email: 0, phone: 0, iban: 0, name: 0 }, redByField: new Map(), fields: new Map(), scanned: 0 });
/* Walk every string value and object key in a parsed row; count hits per kind and per top-level field. */
C.scanRow = function (o, acc) {
  for (const top of Object.keys(o)) {
    acc.fields.set(top, (acc.fields.get(top) || 0) + 1);
    const stack = [[o[top], 0]];
    const tally = v => {
      acc.scanned++;
      const h = C.scanText(v);
      for (const k of C.RED_KINDS) if (h[k]) {
        acc.red[k]++;
        let f = acc.redByField.get(top); if (!f) { f = { email: 0, phone: 0, iban: 0, name: 0 }; acc.redByField.set(top, f); } f[k]++;
      }
    };
    tally(top);
    let guard = 0;
    while (stack.length && guard++ < 5000) {
      const [v, d] = stack.pop();
      if (typeof v === "string") { const fmt = Object.hasOwn(SKIP_FMT, top) ? SKIP_FMT[top] : null; if (!(d === 0 && fmt && fmt.test(v))) tally(v); }
      else if (v && typeof v === "object" && d < 64) {
        if (Array.isArray(v)) for (const x of v) stack.push([x, d + 1]);
        else for (const k of Object.keys(v)) { tally(k); stack.push([v[k], d + 1]); }
      }
    }
  }
};

C.normRow = function (line, n, acc) {
  const r = { n, ok: false };
  let o;
  const text = line.charCodeAt(0) === 0xfeff ? line.slice(1) : line;
  try { o = JSON.parse(text); }
  catch (e) { r.parseError = e instanceof RangeError ? "nested too deeply to read" : "not valid JSON"; return r; }
  if (!o || typeof o !== "object" || Array.isArray(o)) { r.parseError = o === null ? "null, not a JSON object" : Array.isArray(o) ? "an array, not a JSON object" : "not a JSON object"; return r; }
  r.ok = true;
  const str = v => typeof v === "string" ? v : (v == null ? "" : String(v));
  r.ts = typeof o.ts === "string" ? o.ts : ""; r.t = Date.parse(r.ts);
  if (!isFinite(r.t)) r.t = NaN;
  r.rid = str(o.request_id); r.rh = typeof o.request_hash === "string" ? o.request_hash : null;
  r.status = o.status; r.mode = typeof o.mode === "string" ? o.mode : null;
  r.qid = o.question_id == null ? null : str(o.question_id);
  r.backend = str(o.backend); r.calv = str(o.calibration_version);
  r.cache = o.cache_hit === true; r.low = o.low_confidence === true;
  r.reason = str(o.handoff_reason); r.error = o.error == null ? null : str(o.error);
  r.prob = null; r.maxp = null; r.label = ""; r.key = "null"; r.options = null; r.rawYes = null; r.oor = null;
  if (Object.prototype.hasOwnProperty.call(o, "prev_hash")) { r.hasPrev = true; r.prev = typeof o.prev_hash === "string" ? o.prev_hash : null; }
  const a = o.answer;
  r.success = o.status === 200 && r.qid != null && !!a && typeof a === "object" && !Array.isArray(a);
  if (r.success) {
    r.type = typeof a.type === "string" ? a.type : "";
    r.degraded = a.degraded === true || o.degraded === true;
    if (r.type === "noul") {
      r.options = ["Yes", "No"];
      const rd = o.raw_distribution; if (rd && inUnit(rd.Yes)) r.rawYes = rd.Yes;
      if (typeof a.noul === "number") {
        if (inUnit(a.noul)) { r.prob = a.noul; r.maxp = Math.max(a.noul, 1 - a.noul); r.label = a.noul >= 0.5 ? "Yes" : "No"; r.key = String(a.noul); }
        else { r.oor = a.noul; r.label = "out of range"; }
      } else r.label = "no reading";
    } else {
      const pr = a.probabilities;
      if (pr && typeof pr === "object" && !Array.isArray(pr)) {
        const ks = Object.keys(pr); r.options = ks.slice(0, 50);
        const bad = ks.find(k => typeof pr[k] === "number" && !inUnit(pr[k]));
        let best = null; for (const k of ks) if (inUnit(pr[k]) && (best === null || pr[k] > pr[best])) best = k;
        if (bad !== undefined) { r.oor = pr[bad]; r.label = "out of range"; }
        else if (best !== null) {
          r.maxp = r.prob = pr[best];
          const lab = r.type === "choice" ? (a.choice ?? best) : (scoreLabel(a.score, ks) ?? best);
          r.label = str(lab);
          r.key = JSON.stringify(ks.map(k => pr[k]));
        } else r.label = "no reading";
      } else r.label = "no reading";
    }
  } else if (r.error) {
    r.label = `refused ${str(o.status)} ${r.error}`;
  } else if (o.status === 200) {
    r.label = "200 row without an answer";
  }
  if (acc) C.scanRow(o, acc);
  return r;
};

/* ---------- duplicate files: FNV-1a over the lines finds candidates, SHA-256 of the content confirms ---------- */
C.fnvLine = function (h, line) {
  for (let i = 0; i < line.length; i++) { h ^= line.charCodeAt(i); h = Math.imul(h, 16777619); }
  h ^= 10; return Math.imul(h, 16777619) >>> 0;
};
C.findDuplicates = function (files) {
  const seen = new Map(), dups = [];
  for (const f of files) {
    const key = f.lines.length + ":" + f.fnv;
    const prev = seen.get(key);
    if (prev && prev.lines.length === f.lines.length && prev.lines.every((l, i) => l === f.lines[i])) {
      dups.push({ dup: f, of: prev, sha: sha256hex(f.lines.join("\n")) });
    } else if (!prev) seen.set(key, f);
  }
  return dups;
};

/* ---------- order files: by first readable timestamp, then by name ---------- */
const natural = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
C.orderFiles = function (files) {
  const firstT = f => { for (const r of f.rows) if (r.ok && isFinite(r.t)) return r.t; return Infinity; };
  return files.map(f => ({ f, t: firstT(f) })).sort((a, b) => (a.t - b.t) || natural(a.f.name, b.f.name)).map(x => x.f);
};
/* Pair seals with logs: by "# file:" or "<log>.chain" name, then by the first hash, then a lone pair. */
C.pairSeals = function (files, seals) {
  const used = new Set(), pairs = new Map();
  const base = s => s.replace(/^.*[\\/]/, "");
  for (const s of seals) {
    const f = files.find(f => !pairs.has(f) && (base(s.parsed.file || "") === base(f.name) || base(s.name) === base(f.name) + ".chain"));
    if (f) { pairs.set(f, s); used.add(s); }
  }
  for (const s of seals) {
    if (used.has(s) || !s.parsed.hashes.length) continue;
    const f = files.find(f => !pairs.has(f) && f.lines.length && C.chainStep(s.parsed.start, f.lines[0]) === s.parsed.hashes[0]);
    if (f) { pairs.set(f, s); used.add(s); }
  }
  // last resort: one log and one seal left. Refuse when the seal names a different file.
  const refused = [];
  const lf = files.filter(f => !pairs.has(f)), ls = seals.filter(s => !used.has(s));
  if (lf.length === 1 && ls.length === 1) {
    const s = ls[0], f = lf[0], named = s.parsed.file ? base(s.parsed.file) : (/\.chain$/i.test(base(s.name)) ? base(s.name).replace(/\.chain$/i, "") : "");
    if (named && /\.\w+$/.test(named) && named !== base(f.name)) refused.push({ seal: s.name, names: named, log: f.name });
    else { pairs.set(f, s); used.add(s); }
  }
  return { pairs, unused: seals.filter(s => !used.has(s) && !refused.some(r => r.seal === s.name)), refused };
};

/* ---------- statistics ---------- */
C.ks2 = function (a, b) {
  a = a.slice().sort((x, y) => x - y); b = b.slice().sort((x, y) => x - y);
  let i = 0, j = 0, d = 0;
  while (i < a.length && j < b.length) {
    const v = Math.min(a[i], b[j]);
    while (i < a.length && a[i] <= v) i++;
    while (j < b.length && b[j] <= v) j++;
    d = Math.max(d, Math.abs(i / a.length - j / b.length));
  }
  return d;
};
C.tvd = function (la, lb) {
  const ca = {}, cb = {}; la.forEach(x => ca[x] = (ca[x] || 0) + 1); lb.forEach(x => cb[x] = (cb[x] || 0) + 1);
  const keys = new Set([...Object.keys(ca), ...Object.keys(cb)]); let s = 0;
  keys.forEach(k => s += Math.abs((ca[k] || 0) / la.length - (cb[k] || 0) / lb.length));
  return s / 2;
};
/* Textbook two-sample KS coefficients c(alpha): D > c * sqrt((n+m)/(n*m)). */
C.KS_C = { "0.10": 1.224, "0.05": 1.358, "0.01": 1.628 };

/* ---------- calibration view: yes/no questions only, distribution only ---------- */
C.calibTable = function (rows, qid, band) {
  const segs = new Map(), order = [];
  let deliberate = 0, other = 0;
  for (const r of rows) {
    if (!r.ok || !r.success || r.qid !== qid || r.type !== "noul") continue;
    if (r.prob == null) { other++; continue; }
    if (r.mode === "deliberate") { deliberate++; continue; }
    const key = r.calv || "";
    if (!segs.has(key)) { segs.set(key, { calv: key, firstRow: r.n, rs: [] }); order.push(key); }
    segs.get(key).rs.push(r);
  }
  const segments = order.map(key => {
    const s = segs.get(key), n = s.rs.length;
    const bins = [];
    for (let i = 0; i < 10; i++) bins.push({ lo: i / 10, hi: (i + 1) / 10, n: 0, sumP: 0, yes: 0, sumRaw: 0, nRaw: 0, low: 0 });
    let sumP = 0, sumRaw = 0, nRaw = 0, inBand = 0, yes = 0;
    for (const r of s.rs) {
      const b = bins[Math.min(9, Math.floor(r.prob * 10))];
      b.n++; b.sumP += r.prob; if (r.label === "Yes") { b.yes++; yes++; } if (r.low) b.low++;
      if (r.rawYes != null) { b.sumRaw += r.rawYes; b.nRaw++; sumRaw += r.rawYes; nRaw++; }
      sumP += r.prob; if (band && r.prob >= band[0] && r.prob <= band[1]) inBand++;
    }
    return { calv: key, firstRow: s.firstRow, n,
      meanP: sumP / n, meanRaw: nRaw ? sumRaw / nRaw : null, shareYes: yes / n, shareInBand: band ? inBand / n : null,
      bins: bins.map(b => ({ lo: b.lo, hi: b.hi, n: b.n, share: b.n / n, meanP: b.n ? b.sumP / b.n : null,
        shareYes: b.n ? b.yes / b.n : null, meanRaw: b.nRaw ? b.sumRaw / b.nRaw : null, shareLow: b.n ? b.low / b.n : null })) };
  });
  return { qid, segments, deliberate, other };
};

/* ---------- request-level view ---------- */
C.caseKey = rh => rh ? rh.replace(/-deliberate$/, "") : null;
C.buildCases = function (rows) {
  const map = new Map();
  for (const r of rows) {
    if (!r.ok || !r.success) continue;
    const k = C.caseKey(r.rh); if (!k) continue;
    let c = map.get(k); if (!c) { c = { key: k, rows: [], reqMap: new Map() }; map.set(k, c); }
    c.rows.push(r);
    const rk = r.rid + "\u0000" + r.ts;
    let q = c.reqMap.get(rk); if (!q) { q = { rid: r.rid, ts: r.ts, t: r.t, firstRow: r.n, mode: r.mode, rows: [] }; c.reqMap.set(rk, q); }
    q.rows.push(r);
  }
  const cases = [];
  for (const c of map.values()) {
    const reqs = [...c.reqMap.values()].sort((a, b) => ((isFinite(a.t) ? a.t : Infinity) - (isFinite(b.t) ? b.t : Infinity)) || a.firstRow - b.firstRow);
    reqs.forEach((q, i) => { q.gap = i && isFinite(q.t) && isFinite(reqs[i - 1].t) ? q.t - reqs[i - 1].t : null; });
    const byQ = new Map();
    for (const q of reqs) for (const r of q.rows) {
      if (!byQ.has(r.qid)) byQ.set(r.qid, []);
      byQ.get(r.qid).push(r);
    }
    const conflicts = [];
    for (const [qid, rs] of byQ) {
      const labels = [...new Set(rs.map(r => r.label).filter(l => l && l !== "no reading" && l !== "out of range"))];
      if (labels.length > 1) conflicts.push({ qid, labels, rows: rs.map(r => r.n) });
    }
    cases.push({ key: c.key, reqs, nRows: c.rows.length, questions: [...byQ.keys()], conflicts, cacheOnly: reqs.slice(1).every(q => q.rows.every(r => r.cache)) });
  }
  return cases;
};

/* ---------- saved screens ---------- */
C.SETTINGS_KEY = "audit-row-reader.screens.v1";
C.DEFAULTS = Object.freeze({ bandLo: 0.4, bandHi: 0.6, runN: 3, runKey: "exact", shiftAlpha: "0.05", tvdLine: 0.2 });
C.cleanSettings = function (o) {
  const d = C.DEFAULTS, out = Object.assign({}, d);
  if (!o || typeof o !== "object") return out;
  const num = (v, lo, hi) => typeof v === "number" && isFinite(v) && v >= lo && v <= hi;
  if (num(o.bandLo, 0, 1)) out.bandLo = o.bandLo;
  if (num(o.bandHi, 0, 1)) out.bandHi = o.bandHi;
  if (out.bandLo > out.bandHi) { out.bandLo = d.bandLo; out.bandHi = d.bandHi; }
  if (num(o.runN, 2, 50) && Number.isInteger(o.runN)) out.runN = o.runN;
  if (o.runKey === "exact" || o.runKey === "label") out.runKey = o.runKey;
  if (Object.prototype.hasOwnProperty.call(C.KS_C, o.shiftAlpha)) out.shiftAlpha = o.shiftAlpha;
  if (num(o.tvdLine, 0.01, 1)) out.tvdLine = o.tvdLine;
  return out;
};
C.loadSettings = function (storage) {
  try { const s = storage && storage.getItem(C.SETTINGS_KEY); return { settings: C.cleanSettings(s ? JSON.parse(s) : null), ok: true }; }
  catch (e) { return { settings: C.cleanSettings(null), ok: false, error: String(e && e.name || e) }; }
};
C.saveSettings = function (storage, s) {
  try { storage.setItem(C.SETTINGS_KEY, JSON.stringify(C.cleanSettings(s))); return { ok: true }; }
  catch (e) { return { ok: false, error: String(e && e.name || e) }; }
};
C.resetSettings = function (storage) {
  try { storage.removeItem(C.SETTINGS_KEY); return { ok: true, settings: C.cleanSettings(null) }; }
  catch (e) { return { ok: false, settings: C.cleanSettings(null), error: String(e && e.name || e) }; }
};

/* ---------- export ---------- */
C.csvCell = function (v) {
  let s = v == null ? "" : String(v);
  if (typeof v !== "number" && /^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
C.sanitiseLine = function (line, keep) {
  let o;
  try { o = JSON.parse(line.charCodeAt(0) === 0xfeff ? line.slice(1) : line); } catch (e) { return null; }
  if (!o || typeof o !== "object" || Array.isArray(o)) return null;
  const out = Object.create(null);  // a "__proto__" field stays an ordinary key
  for (const k of Object.keys(o)) if (keep.has(k)) out[k] = o[k];
  return JSON.stringify(out);
};

root.ARR = C;
if (typeof module !== "undefined" && module.exports) module.exports = C;
})(typeof window !== "undefined" ? window : globalThis);
