/* Audit Row Reader, page script. Reads decision-head audit logs entirely in the browser.
   No fetch, no XHR. localStorage holds only the screen settings (band, run length, shift lines).
   Logic lives in core.js (global ARR); the self-check is selfcheck.js. */
"use strict";
(function () {
const A = window.ARR;
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const f2 = x => x == null || !isFinite(x) ? "·" : x.toFixed(2);
const f3 = x => x == null || !isFinite(x) ? "·" : x.toFixed(3);
const pct = x => x == null || !isFinite(x) ? "·" : (x * 100).toFixed(0) + "%";
const tsShort = ts => ts ? ts.replace("T", " ").replace(/\.\d+Z$/, "").replace(/Z$/, "") : "·";
const nf = n => Number(n).toLocaleString("en-US");
const secs = ms => ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} s`;

/* ---------- state ---------- */
const S = { files: [], lines: [], rows: [], multi: false, method: "none", integ: null, questions: [], flags: [], shift: [],
  cases: [], acc: A.newAcc(), view: [], sel: null, srcs: [], sealSrcs: [], timing: null, keep: null, caseShown: 50, printAll: false, label: "" };
let JOB = 0;

/* ---------- storage (settings only) ---------- */
function store() { try { return window.localStorage; } catch (e) { return null; } }
function readInputs() {
  return A.cleanSettings({ bandLo: parseFloat($("bandLo").value), bandHi: parseFloat($("bandHi").value), runN: parseInt($("runN").value, 10),
    runKey: $("runKey").value, shiftAlpha: $("shiftAlpha").value, tvdLine: parseFloat($("tvdLine").value) });
}
function applySettings(s) {
  $("bandLo").value = s.bandLo; $("bandHi").value = s.bandHi; $("runN").value = s.runN; $("runKey").value = s.runKey;
  $("shiftAlpha").value = s.shiftAlpha; $("tvdLine").value = s.tvdLine;
}
function saveScreens() {
  const st = store();
  const res = st ? A.saveSettings(st, readInputs()) : { ok: false, error: "storage unavailable" };
  $("savedNote").textContent = res.ok ? "settings saved in this browser" : `settings not saved (${res.error}); they last until this tab closes`;
  return res;
}

/* ---------- progress ---------- */
let progTimer = null, lastTick = 0, progFrac = 0, progMsg = "";
function progStart() {
  clearTimeout(progTimer); progFrac = 0; progMsg = "";
  progTimer = setTimeout(() => $("prog").classList.remove("hidden"), 120);
}
function progSet(frac, msg) { progFrac = Math.max(0, Math.min(1, frac)); progMsg = msg; }
function progPaint() { $("progBar").value = progFrac; $("progText").textContent = progMsg; }
function progEnd() { clearTimeout(progTimer); $("prog").classList.add("hidden"); }
/* Yield with a message task: setTimeout is clamped to 1 s in background tabs, a message is not. */
const yieldTask = () => new Promise(r => { const ch = new MessageChannel(); ch.port1.onmessage = () => r(); ch.port2.postMessage(0); });
async function tick(job, force) {
  const now = performance.now();
  if (force || now - lastTick > 40) { progPaint(); await yieldTask(); lastTick = performance.now(); }
  return job !== JOB;
}

/* ---------- reading ---------- */
async function readSource(src, job, onLine, onChars) {
  const sp = new A.LineSplitter();
  const fromText = async t => {
    const STEP = 1 << 18;
    for (let i = 0; i < t.length; i += STEP) {
      for (const l of sp.push(t.slice(i, i + STEP))) onLine(l);
      onChars(Math.min(STEP, t.length - i));
      if (await tick(job)) return false;
    }
    return true;
  };
  if (src.text != null) { if (!(await fromText(src.text))) return null; }
  else if (src.file.stream && typeof TextDecoderStream !== "undefined") {
    const reader = src.file.stream().pipeThrough(new TextDecoderStream("utf-8", { ignoreBOM: true })).getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const l of sp.push(value)) onLine(l);
      onChars(value.length);
      if (await tick(job)) { try { await reader.cancel(); } catch (e) { /* stream already closed */ } return null; }
    }
  } else {
    const t = new TextDecoder("utf-8", { ignoreBOM: true }).decode(await src.file.arrayBuffer());
    if (!(await fromText(t))) return null;
  }
  for (const l of sp.end()) onLine(l);
  return { bareCR: sp.bareCR };
}
const srcSize = s => s.text != null ? s.text.length : s.file.size;

async function loadAll(logSrcs, sealSrcs, label) {
  const job = ++JOB;
  hideTip(); progStart();
  const t0 = performance.now();
  try {
    const acc = A.newAcc(), files = [];
    const total = logSrcs.reduce((s, x) => s + srcSize(x), 0) || 1;
    let done = 0, nRows = 0;
    for (const src of logSrcs) {
      const f = { name: src.name, lines: [], rows: [], size: srcSize(src), fnv: 2166136261 };
      const res = await readSource(src, job, line => { f.lines.push(line); f.fnv = A.fnvLine(f.fnv, line); f.rows.push(A.normRow(line, f.lines.length, acc)); nRows++; },
        c => { done += c; progSet(0.85 * done / total, `reading ${src.name} · ${nf(nRows)} rows · ${(done / 1048576).toFixed(1)} of ${(total / 1048576).toFixed(1)} MB`); });
      if (!res) return false;
      f.bareCR = res.bareCR; files.push(f);
    }
    const tRead = performance.now();
    const dups = A.findDuplicates(files);
    const kept = files.filter(f => !dups.some(d => d.dup === f));
    const allSeals = sealSrcs.map(s => ({ name: s.name, parsed: A.parseSeal(s.text) }));
    const unreadableSeals = allSeals.filter(s => s.parsed.unreadable), seals = allSeals.filter(s => !s.parsed.unreadable);
    const ordered = A.orderFiles(kept);
    const { pairs, unused, refused } = A.pairSeals(ordered, seals);
    let g = 0; const lines = [], rows = [];
    ordered.forEach((f, k) => {
      const s = pairs.get(f); f.seal = s ? s.parsed : null; f.sealName = s ? s.name : ""; f.offset = g;
      for (let i = 0; i < f.rows.length; i++) { const r = f.rows[i]; r.f = k; r.fn = i + 1; r.n = ++g; rows.push(r); lines.push(f.lines[i]); }
    });
    const T = { files: ordered, lines, rows, multi: ordered.length > 1, acc, unusedSeals: unused, refusedSeals: refused, unreadableSeals, dups, sel: null, srcs: logSrcs, sealSrcs, label, caseShown: 50 };
    if (!(await runIntegrity(job, T))) return false;
    Object.assign(S, T);
    markRows();
    const tHash = performance.now();
    progSet(1, "drawing"); await tick(job, true);
    if (job !== JOB) return false;
    renderAll();
    const tEnd = performance.now();
    S.timing = { read: tRead - t0, hash: tHash - tRead, render: tEnd - tHash, total: tEnd - t0, rows: rows.length };
    renderFileList();
    return true;
  } catch (e) {
    console.error("Audit Row Reader could not read the input", e);
    $("pasteNote").textContent = `Could not read this input: ${e && e.message ? e.message : e}`;
    return false;
  } finally {
    if (job === JOB) progEnd();
  }
}

/* ---------- integrity ---------- */
/* Hashes into the staging object T; the page state S changes only after this finishes,
   so a load that is stopped or overtaken never leaves S half-replaced. */
async function runIntegrity(job, T) {
  const files = T.files;
  const anySeal = files.some(f => f.seal), anyPrev = T.rows.some(r => r.ok && r.hasPrev);
  T.method = anySeal ? "seal" : anyPrev ? "prev_hash" : "none";
  const total = Math.max(1, T.rows.length); let done = 0;
  for (const f of files) {
    if (T.method === "seal" && f.seal) {
      f.mine = new Array(f.lines.length); let prev = f.seal.start;
      for (let i = 0; i < f.lines.length; i++) {
        prev = A.chainStep(prev, f.lines[i]); f.mine[i] = prev;
        if ((++done & 1023) === 0) { progSet(0.85 + 0.13 * done / total, `checking the seal · row ${nf(done)} of ${nf(total)}`); if (await tick(job)) return false; }
      }
    } else if (T.method === "prev_hash") {
      f.lineHashes = new Array(f.lines.length);
      f.prev = f.rows.map(r => r.ok && r.hasPrev ? r.prev : undefined);
      for (let i = 0; i < f.lines.length; i++) {
        f.lineHashes[i] = A.sha256hex(f.lines[i]);
        if ((++done & 1023) === 0) { progSet(0.85 + 0.13 * done / total, `checking prev_hash links · row ${nf(done)} of ${nf(total)}`); if (await tick(job)) return false; }
      }
    }
  }
  T.integ = T.method === "none" ? null : A.verifySeries(files.map(f => ({ name: f.name, n: f.lines.length, seal: f.seal, mine: f.mine, lineHashes: f.lineHashes, prev: f.prev })), T.method);
  return true;
}
const rowLabel = r => r ? (S.multi ? `${r.f + 1}:${r.fn}` : String(r.n)) : "";
const fileShort = k => S.multi ? `file ${k + 1} (${S.files[k].name})` : "the log";
function firstBreakGlobal() {
  if (S.method === "none") { const bad = S.rows.find(r => !r.ok); return bad ? bad.n : null; }
  const fb = S.integ && S.integ.first; return fb ? S.files[fb.file].offset + fb.row : null;
}
function markRows() {
  const fbG = firstBreakGlobal();
  for (const r of S.rows) {
    if (S.method === "none") { r.chain = r.ok ? "not sealed" : "unreadable"; continue; }
    if (S.method === "prev_hash") { r.chain = fbG && r.n === fbG ? "first break" : fbG && r.n > fbG ? "after break" : "ok"; continue; }
    const pf = S.integ.perFile[r.f];
    if (!pf.sealed) { r.chain = "no seal"; continue; }
    const b = r.f > 0 ? S.integ.boundaries[r.f - 1] : null;
    if (pf.first && r.fn === pf.first) r.chain = "first break";
    else if (pf.first && r.fn > pf.first) r.chain = "after break";
    else if (pf.appendedFrom && r.fn >= pf.appendedFrom) r.chain = "after seal";
    else if (b && b.ok === false && r.fn === 1) r.chain = "link broken";
    else r.chain = "ok";
  }
}
function fileNote(k) {
  const pf = S.integ.perFile[k], f = S.files[k], who = fileShort(k), Who = who[0].toUpperCase() + who.slice(1);
  if (!pf.sealed) return `${Who} has no seal, so its rows are unverified.`;
  if (pf.kind === "edit") return `Row ${pf.first} of ${who} no longer matches its seal. It was edited or removed, or rows around it moved. Every later row in ${S.multi ? "that file" : "the log"} is unverified.`;
  if (pf.kind === "truncated") return `${Who} ends at row ${f.lines.length} and its seal covers ${f.seal.hashes.length} rows. ${pf.missing} row(s) are missing from the end.`;
  if (pf.kind === "appended") return `All ${f.seal.hashes.length} sealed rows of ${who} match. Rows ${pf.appendedFrom} to ${f.lines.length} were written after the seal and are not covered.`;
  return `All ${nf(f.lines.length)} rows of ${who} match ${S.multi ? "its" : "the"} seal.`;
}
function boundaryNote(b) {
  const A_ = S.files[b.from].name, B_ = S.files[b.to].name;
  return ({
    holds: `${B_} starts where ${A_} ends. The link holds.`,
    linkHoldsFileBroken: `The seals link, but ${A_} is broken inside, at row ${S.integ.perFile[b.from].first}.`,
    startMismatch: `${B_}'s seal does not start where ${A_}'s seal ends. A file between them is missing, the files are out of order, or a seal was rewritten.`,
    rowsPastSeal: `${A_} has rows past its seal, so ${B_} does not follow on from its last row.`,
    noSeal: `One of these files has no seal, so the link is unchecked.`,
    prevMismatch: `Row 1 of ${B_} does not carry the hash of ${A_}'s last row. That row was edited, a file between them is missing, or the files are out of order.`,
    brokeEarlier: `Unchecked. The chain broke earlier.`,
    emptyFile: `One of these files is empty, so there is nothing to link.`
  })[b.why] || b.why;
}
function integrityNote() {
  const fbG = firstBreakGlobal(), r = fbG ? S.rows[fbG - 1] : null;
  if (!S.rows.length) return { stamp: "empty", cls: "", note: "The log is empty. There is nothing to check." };
  if (S.method !== "seal" && S.unreadableSeals && S.unreadableSeals.length) {
    const u = S.unreadableSeals[0];
    return { stamp: "seal unreadable", cls: "", note: `The seal could not be read. ${u.name} has ${u.parsed.bad} line(s) and none of them is a 64-character hash, so the page gives no verdict on these rows. Load a readable seal to check them.` };
  }
  if (S.method !== "seal" && S.refusedSeals && S.refusedSeals.length) {
    const x = S.refusedSeals[0];
    return { stamp: "seal not applied", cls: "", note: `${x.seal} names ${x.names}, and the loaded log is ${x.log}. The page did not apply it and gives no verdict. Load the log it names, or a seal for this log.` };
  }
  if (S.method === "none") {
    return r ? { stamp: "unreadable row", cls: "break", note: `Row ${rowLabel(r)} does not parse (${r.parseError}). No seal is loaded and the rows carry no prev_hash, so the reader cannot tell whether other rows changed.` }
             : { stamp: "not sealed", cls: "", note: `Every line parses. No seal is loaded and the rows carry no prev_hash, so nothing here proves the rows are unchanged.` };
  }
  if (S.method === "prev_hash") {
    const n = S.rows.length;
    return r ? { stamp: "broken", cls: "break", note: `Row ${rowLabel(r)}'s prev_hash does not match the row before it. That row was edited or removed, or this link was. Every row from here on is unverified.` }
             : { stamp: "verified", cls: "ok", note: `${nf(Math.max(0, n - 1))} links hold${S.multi ? `, across ${S.files.length} files` : ""}; row 1 has no predecessor to check. A prev_hash chain cannot show an edit to the last row or rows cut from the end.` };
  }
  const notes = S.files.map((f, k) => fileNote(k));
  const broken = S.integ.first || S.integ.boundaries.some(b => b.ok === false);
  const unsealed = S.integ.perFile.some(p => !p.sealed);
  if (broken) {
    const fb = S.integ.first, b = S.integ.boundaries.find(x => x.ok === false && x.to === fb.file && fb.row === 1);
    const lead = b ? `The series breaks at the boundary into ${S.files[fb.file].name}. ${boundaryNote(b)}` : fileNote(fb.file);
    return { stamp: "broken", cls: "break", note: lead + (S.multi ? ` First break: row ${rowLabel(r)}.` : "") };
  }
  if (!S.multi) return { stamp: "verified", cls: "ok", note: notes[0] };
  return { stamp: unsealed ? "partly sealed" : "verified", cls: unsealed ? "" : "ok",
    note: unsealed ? `Some files have no seal. ${notes.filter((n, k) => !S.integ.perFile[k].sealed).join(" ")}` : `All ${nf(S.rows.length)} rows in ${S.files.length} files match their seals, and every boundary holds.` };
}

/* ---------- entered band ---------- */
function band() {
  const lo = parseFloat($("bandLo").value), hi = parseFloat($("bandHi").value);
  if (!(isFinite(lo) && isFinite(hi) && lo >= 0 && hi <= 1 && lo <= hi)) return null;
  return [lo, hi];
}
function applyBand() {
  const b = band();
  for (const r of S.rows) r.bandIn = !!(b && r.ok && r.success && r.type === "noul" && r.prob != null && r.prob >= b[0] && r.prob <= b[1]);
  $("bandNote").textContent = b
    ? `Entered band ${b[0].toFixed(2)} to ${b[1].toFixed(2)}: the low-confidence list, the histograms and the calibration table use these bounds for yes/no answers, alongside the server's own low_confidence flag.`
    : "The band bounds need 0 <= low <= high <= 1. Until then only the server's own flag counts.";
}

/* ---------- flags ---------- */
function shiftScreen() {
  const st = readInputs(), c = A.KS_C[st.shiftAlpha], out = [];
  const byQ = new Map(); for (const r of S.rows) if (r.ok && r.success && r.prob != null) { if (!byQ.has(r.qid)) byQ.set(r.qid, []); byQ.get(r.qid).push(r); }
  for (const q of S.questions) {
    const num = byQ.get(q) || [];
    if (num.length < 20) { out.push({ q, skipped: true, n: num.length }); continue; }
    const h = Math.floor(num.length / 2), A1 = num.slice(0, h), B1 = num.slice(h);
    const D = A.ks2(A1.map(r => r.prob), B1.map(r => r.prob));
    const line = c * Math.sqrt((A1.length + B1.length) / (A1.length * B1.length));
    const tv = A.tvd(A1.map(r => r.label), B1.map(r => r.label));
    const mean = xs => xs.reduce((s, r) => s + r.prob, 0) / xs.length;
    out.push({ q, n: num.length, D, line, tv, m1: mean(A1), m2: mean(B1), splitRow: B1[0], type: num[0].type, flagged: D > line || tv >= st.tvdLine });
  }
  return out;
}
const rowF = r => ({ n: r.n, ts: r.ts || "", rid: r.rid || "", qid: r.qid || "", answer: r.label || "", prob: r.prob });
function buildFlags() {
  applyBand();
  const F = [], st = readInputs();
  const fbG = firstBreakGlobal();
  if (fbG) F.push(Object.assign(rowF(S.rows[fbG - 1]), { kind: "chain break", detail: integrityNote().note }));
  if (S.integ) for (const b of S.integ.boundaries) if (b.ok === false) {
    const r = S.rows[S.files[b.to].offset];
    if (r && r.n !== fbG) F.push(Object.assign(rowF(r), { kind: "chain break", detail: `Boundary ${S.files[b.from].name} to ${S.files[b.to].name}: ${boundaryNote(b)}` }));
  }
  if (S.integ && S.method === "seal") S.integ.perFile.forEach((pf, k) => {
    if (pf.first && !(S.integ.first && S.integ.first.file === k && S.integ.first.row === pf.first)) {
      const r = S.rows[S.files[k].offset + Math.min(pf.first, S.files[k].lines.length) - 1];
      if (r) F.push(Object.assign(rowF(r), { kind: "chain break", detail: fileNote(k) }));
    }
  });
  for (const r of S.rows) if (!r.ok && !(fbG === r.n && S.method === "none")) F.push(Object.assign(rowF(r), { kind: "unreadable line", detail: `Row ${rowLabel(r)} is ${r.parseError}.` }));
  for (const r of S.rows) if (r.ok && r.oor != null) F.push(Object.assign(rowF(r), { kind: "value out of range",
    detail: `${r.type === "noul" ? "P(yes)" : "An option probability"} is ${String(r.oor)}, outside 0 to 1. decision-head writes strict JSON probabilities, so this row was written by something else or edited.` }));
  const rid = new Map();
  for (const r of S.rows) if (r.ok && r.rid) { let e = rid.get(r.rid); if (!e) { e = { ts: new Set(), rows: [] }; rid.set(r.rid, e); } e.ts.add(r.ts); if (e.rows.length < 6) e.rows.push(r); }
  for (const [id, e] of rid) if (e.ts.size > 1) F.push(Object.assign(rowF(e.rows[0]), { kind: "repeated request id",
    detail: `request_id ${id.length > 40 ? id.slice(0, 40) + "…" : id} appears with ${e.ts.size} different timestamps (rows ${e.rows.map(rowLabel).join(", ")}${e.rows.length >= 6 ? ", …" : ""}). Every row of one request shares its ts.` }));
  for (const c of S.cases) for (const cf of c.conflicts) {
    const r = S.rows[cf.rows[0] - 1];
    F.push(Object.assign(rowF(r), { kind: "answer changed in a case", answer: "", prob: null,
      detail: `Case ${c.key.slice(0, 12)}: ${cf.qid} got ${cf.labels.map(l => `"${l}"`).join(", then ")} across ${c.reqs.length} requests (rows ${cf.rows.map(n => rowLabel(S.rows[n - 1])).join(", ")}).` }));
  }
  const b = band();
  for (const r of S.rows) {
    if (r.ok && r.low) F.push(Object.assign(rowF(r), { kind: "low confidence", detail: "Server flag: " + (r.reason || (r.degraded ? "degraded reading, no usable answer." : "low_confidence.")) }));
    else if (r.bandIn) F.push(Object.assign(rowF(r), { kind: "low confidence", detail: `Entered band: P(yes) ${r.prob.toFixed(4)} is inside ${b[0].toFixed(2)} to ${b[1].toFixed(2)}. The server did not flag this row; its band was off or set differently when the row was written.` }));
  }
  const N = st.runN, byLabel = st.runKey === "label";
  const byQ = new Map(); for (const r of S.rows) if (r.ok && r.success) { if (!byQ.has(r.qid)) byQ.set(r.qid, []); byQ.get(r.qid).push(r); }
  for (const q of S.questions) {
    const rs = byQ.get(q) || []; let i = 0;
    while (i < rs.length) {
      const keyOf = r => r.prob == null ? null : (byLabel ? r.label : r.key);
      const k = keyOf(rs[i]); let j = i + 1;
      if (k === null) { i = j; continue; }
      while (j < rs.length && keyOf(rs[j]) === k) j++;
      const len = j - i;
      if (len >= N) {
        const c = rs.slice(i, j).filter(r => r.cache).length;
        F.push(Object.assign(rowF(rs[i]), { kind: "identical run",
          detail: `${len} ${q} rows in a row give ${byLabel ? "the same answer" : "the same reading to the last digit"} (rows ${rowLabel(rs[i])} to ${rowLabel(rs[j - 1])}).` + (c ? ` ${c} of them are cache hits, which repeat an earlier reading by design.` : " None is a cache hit.") }));
      }
      i = j;
    }
  }
  S.shift = shiftScreen();
  for (const s of S.shift) if (s.flagged) {
    const what = s.type === "noul" ? "P(yes)" : "top probability";
    F.push(Object.assign(rowF(s.splitRow), { kind: "distribution shift", answer: "", prob: null,
      detail: `${s.q}: ${what} moved from a mean of ${s.m1.toFixed(2)} in the first half to ${s.m2.toFixed(2)} in the second (row ${rowLabel(s.splitRow)} on). Two-sample KS distance ${s.D.toFixed(2)} against a screening line of ${s.line.toFixed(2)} (KS ${st.shiftAlpha}); the answer mix moved ${(s.tv * 100).toFixed(0)} points against a line of ${(st.tvdLine * 100).toFixed(0)}. This is a screen. The halves are not independent draws and nothing corrects for screening several questions.` }));
  }
  S.flags = F;
}

/* ---------- render: integrity + flags ---------- */
function renderIntegrity() {
  $("secIntegrity").classList.remove("hidden");
  $("chainMethod").textContent = { seal: "method: seal file", prev_hash: "method: prev_hash links in the rows", none: "method: none available" }[S.method];
  const v = integrityNote();
  $("verdict").innerHTML = `<span class="stamp ${v.cls}">${esc(v.stamp)}</span> ${esc(v.note)}`;
  const succ = S.rows.filter(r => r.success), reqs = new Set(S.rows.filter(r => r.ok).map(r => r.rid)).size;
  const low = S.rows.filter(r => r.ok && r.low).length, refused = S.rows.filter(r => r.ok && r.error).length;
  const fbG = firstBreakGlobal();
  const figs = [[nf(S.rows.length), "rows"], [nf(reqs), "requests"], [nf(succ.length), "answers"], [nf(low), "flagged low_confidence"],
    [fbG ? "row " + rowLabel(S.rows[fbG - 1]) : (S.method === "none" ? "n/a" : "none"), "first break"]];
  if (refused) figs.splice(3, 0, [nf(refused), "refused requests"]);
  if (S.multi) figs.unshift([S.files.length, "files"]);
  $("figs").innerHTML = figs.map(([n, l]) => `<li><span class="fig-n">${esc(n)}</span><span class="fig-l">${esc(l)}</span></li>`).join("");
  const bw = $("boundsWrap");
  if (S.multi) {
    bw.classList.remove("hidden");
    const items = [];
    S.files.forEach((f, k) => {
      const fn = S.method === "seal" ? fileNote(k) : `${nf(f.lines.length)} rows`;
      items.push(`<li class="file"><span class="mono">file ${k + 1}</span> <b>${esc(f.name)}</b>${f.sealName ? ` <span class="mono">· seal ${esc(f.sealName)}</span>` : ""}<br>${esc(fn)}</li>`);
      if (k < S.files.length - 1 && S.integ) {
        const b = S.integ.boundaries[k];
        const st = b.ok === true ? '<span class="stamp ok">holds</span>' : b.ok === false ? '<span class="stamp break">broken</span>' : '<span class="stamp">unchecked</span>';
        items.push(`<li class="bnd">${st} <span class="mono">boundary ${k + 1} to ${k + 2}</span> ${esc(boundaryNote(b))}</li>`);
      } else if (k < S.files.length - 1) items.push(`<li class="bnd"><span class="stamp">unchecked</span> <span class="mono">boundary ${k + 1} to ${k + 2}</span> No seal or prev_hash to link these files.</li>`);
    });
    $("bounds").innerHTML = items.join("");
  } else bw.classList.add("hidden");
  const notes = [];
  const cr = S.files.reduce((s, f) => s + (f.bareCR || 0), 0);
  if (cr) notes.push(`${cr} line(s) hold a bare carriage return. The reader splits rows on line feeds only, the same rule tools/seal.py uses, so rows separated by a bare CR read as one line.`);
  if (S.integ && S.integ.notes.includes("firstStartsLater")) notes.push("The first file's seal starts from an earlier file's last hash. That earlier file is not loaded, so the link into it is unchecked.");
  if (S.integ && S.integ.notes.includes("firstPointsEarlier")) notes.push("Row 1 carries a prev_hash, so an earlier file existed. It is not loaded, so that link is unchecked.");
  if (S.unusedSeals && S.unusedSeals.length) notes.push(`${S.unusedSeals.length} seal file(s) matched no loaded log: ${S.unusedSeals.map(s => s.name).join(", ")}.`);
  if (S.dups && S.dups.length) notes.push(S.dups.map(d => `${d.dup.name} has the same content as ${d.of.name} (SHA-256 ${d.sha.slice(0, 16)}…), so it was read once.`).join(" "));
  if (S.refusedSeals && S.refusedSeals.length && S.method === "seal") notes.push(S.refusedSeals.map(x => `${x.seal} names ${x.names}, not ${x.log}, so it was not applied.`).join(" "));
  if (S.unreadableSeals && S.unreadableSeals.length && S.method === "seal") notes.push(`The seal ${S.unreadableSeals.map(u => u.name).join(", ")} could not be read and was set aside.`);
  const badSeal = S.files.filter(f => f.seal && f.seal.bad);
  if (badSeal.length) notes.push(`The seal for ${badSeal.map(f => f.name).join(", ")} holds lines that are not 64-character hashes; they were skipped.`);
  $("lineNote").textContent = notes.join(" ");
}
const KIND_ORDER = ["chain break", "unreadable line", "value out of range", "repeated request id", "answer changed in a case", "distribution shift", "identical run", "low confidence"];
const SHOW_MAX = 300;
function renderFlags() {
  buildFlags();
  $("secFlags").classList.remove("hidden");
  let html = "";
  const screened = S.shift.filter(s => !s.skipped).length, bb = band();
  for (const kind of KIND_ORDER) {
    const items = S.flags.filter(f => f.kind === kind);
    let head = `${nf(items.length)}`;
    if (kind === "distribution shift") head = `${items.length} of ${screened} questions screened`;
    if (kind === "low confidence") { const sv = items.filter(f => S.rows[f.n - 1].low).length; head = `${nf(items.length)} · ${nf(sv)} server flag, ${nf(items.length - sv)} entered band` + (bb ? ` ${bb[0].toFixed(2)} to ${bb[1].toFixed(2)}` : " (bounds invalid)"); }
    if (!items.length && kind !== "distribution shift" && kind !== "chain break") continue;
    const li = f => `<li><span class="k${kind === "chain break" ? " break" : ""}">${esc(kind)}</span><span class="d">${esc(f.detail)}<span class="mono">row <button type="button" class="link" data-row="${f.n}" aria-label="Show row ${esc(rowLabel(S.rows[f.n - 1]))} in the trail">${esc(rowLabel(S.rows[f.n - 1]))}</button>${f.ts ? " · " + esc(tsShort(f.ts)) : ""}${f.qid ? " · " + esc(f.qid) : ""}${f.answer ? " · " + esc(f.answer) : ""}${f.prob != null ? " · " + f3(f.prob) : ""}</span></span></li>`;
    html += `<h3 style="margin-top:1rem">${esc(kind[0].toUpperCase() + kind.slice(1))} <span class="groupcount">${esc(head)}</span></h3>`;
    if (!items.length) { html += `<p class="empty" style="margin:.3rem 0 0">${kind === "chain break" ? "No break found." : "Nothing crossed the screening line."}</p>`; continue; }
    html += `<ul class="flags">${items.slice(0, 6).map(li).join("")}</ul>`;
    if (items.length > 6) {
      const rest = items.slice(6, SHOW_MAX);
      html += `<details class="more"><summary>${nf(items.length - 6)} more</summary><ul class="flags">${rest.map(li).join("")}</ul>${items.length > SHOW_MAX ? `<p class="mono">The first ${SHOW_MAX} are listed here. The CSV export holds all ${nf(items.length)}.</p>` : ""}</details>`;
    }
  }
  $("flagGroups").innerHTML = html;
}

/* ---------- cases ---------- */
function fmtGap(ms) {
  if (ms == null) return "·";
  if (ms < 1000) return "same second";
  const s = ms / 1000; if (s < 90) return `${s.toFixed(0)} s`;
  const m = s / 60; if (m < 90) return `${m.toFixed(0)} min`;
  const h = m / 60; if (h < 36) return `${h.toFixed(1)} h`;
  return `${(h / 24).toFixed(1)} days`;
}
function renderCases() {
  $("secCases").classList.remove("hidden");
  const cs = S.cases, rep = cs.filter(c => c.reqs.length > 1), changed = cs.filter(c => c.conflicts.length), cacheOnly = rep.filter(c => c.cacheOnly);
  $("caseFigs").innerHTML = [[nf(cs.length), "cases"], [nf(rep.length), "asked more than once"], [nf(cacheOnly.length), "repeats served from cache"], [nf(changed.length), "with an answer that changed"]]
    .map(([n, l]) => `<li><span class="fig-n">${esc(n)}</span><span class="fig-l">${esc(l)}</span></li>`).join("");
  const mode = $("caseFilter").value;
  const list = mode === "changed" ? changed : mode === "repeat" ? rep : cs;
  const shown = list.slice(0, S.caseShown);
  const reqRow = (c, q) => `<tr><td class="m" data-l="time">${esc(tsShort(q.ts))}</td><td class="m" data-l="since previous">${esc(fmtGap(q.gap))}</td><td class="m" data-l="mode">${esc(q.mode || "·")}${q.rows.every(r => r.cache) ? " · cache" : ""}</td><td>${q.rows.map(r => {
      const changedQ = c.conflicts.some(cf => cf.qid === r.qid);
      return `<span class="qa${changedQ ? " chg" : ""}"><button type="button" class="link" data-row="${r.n}" aria-label="Show row ${esc(rowLabel(r))} in the trail">${esc(rowLabel(r))}</button> ${esc(r.qid)} <b>${esc(r.label || "·")}</b>${r.prob != null ? " " + f2(r.prob) : ""}${changedQ ? ' <span class="mono">changed</span>' : ""}</span>`;
    }).join("")}</td></tr>`;
  $("caseList").innerHTML = shown.length ? shown.map((c, i) => `<details class="case"${i < 3 && mode !== "all" ? " open" : ""}><summary><span class="mono">case ${esc(c.key.slice(0, 12))}</span> · ${c.reqs.length} request${c.reqs.length > 1 ? "s" : ""} · ${c.nRows} rows${c.conflicts.length ? ` · <span class="chgtxt">changed: ${esc(c.conflicts.map(x => x.qid).join(", "))}</span>` : ""}${c.reqs.length > 1 ? ` · first to last ${esc(fmtGap(c.reqs[c.reqs.length - 1].t - c.reqs[0].t))}` : ""}</summary>
      <div class="tablewrap" tabindex="0" role="region" aria-label="Requests in case ${esc(c.key.slice(0, 12))}"><table class="cases"><thead><tr><th scope="col">Time (UTC)</th><th scope="col">Since previous</th><th scope="col">Mode</th><th scope="col">Questions answered, in log order</th></tr></thead><tbody>${c.reqs.map(q => reqRow(c, q)).join("")}</tbody></table></div></details>`).join("")
    : `<p class="empty">${mode === "changed" ? "No case got two different answers to one question." : mode === "repeat" ? "No case was asked more than once." : "No answered rows carry a request_hash."}</p>`;
  const more = $("btnMoreCases");
  more.classList.toggle("hidden", list.length <= S.caseShown);
  more.textContent = `Show more cases (${nf(Math.min(50, list.length - S.caseShown))} of ${nf(list.length - S.caseShown)} left)`;
}

/* ---------- calibration view ---------- */
function renderCalib() {
  const nq = S.questions.filter(q => S.rows.some(r => r.success && r.qid === q && r.type === "noul"));
  const sec = $("secCalib"); sec.classList.toggle("hidden", !nq.length);
  if (!nq.length) return;
  const sel = $("calQ"), keep = sel.value;
  sel.innerHTML = nq.map(q => `<option value="${esc(q)}">${esc(q)}</option>`).join("");
  if (nq.includes(keep)) sel.value = keep;
  const b = band(), t = A.calibTable(S.rows, sel.value, b);
  const lab = s => s.calv ? `calibration ${s.calv.slice(0, 10)}` : "no calibration document";
  let cmp = "";
  for (let i = 1; i < t.segments.length; i++) {
    const a = t.segments[i - 1], c = t.segments[i];
    cmp += `<li>From row ${esc(rowLabel(S.rows[c.firstRow - 1]))}, ${esc(lab(a))} to ${esc(lab(c))}: mean P(yes) ${f3(a.meanP)} to ${f3(c.meanP)}; mean raw P(yes) ${f3(a.meanRaw)} to ${f3(c.meanRaw)}; answered Yes ${pct(a.shareYes)} to ${pct(c.shareYes)}${b ? `; inside the entered band ${pct(a.shareInBand)} to ${pct(c.shareInBand)}` : ""}.</li>`;
  }
  $("calCompare").innerHTML = (cmp ? `<h3>Before and after each calibration change</h3><ul class="cmp">${cmp}</ul>` : `<p class="mono">One calibration document covers every row of this question, so there is no before and after.</p>`)
    + `<p class="mono">${nf(t.segments.reduce((s, x) => s + x.n, 0))} rows in the table${t.deliberate ? ` · ${t.deliberate} deliberate rows left out (their P(yes) is a vote share, uncalibrated)` : ""}${t.other ? ` · ${t.other} rows without a usable reading left out` : ""}. Raw P(yes) is raw_distribution.Yes, read before calibration.</p>`;
  $("calTables").innerHTML = t.segments.map(s => `<figure class="caltable"><figcaption><h3>${esc(lab(s))}</h3><span class="mono">${nf(s.n)} rows from row ${esc(rowLabel(S.rows[s.firstRow - 1]))} · mean P(yes) ${f3(s.meanP)} · mean raw ${f3(s.meanRaw)}${b ? ` · ${pct(s.shareInBand)} inside the entered band` : ""}</span></figcaption>
    <div class="tablewrap" tabindex="0" role="region" aria-label="Probability bins for ${esc(lab(s))}"><table class="calib"><thead><tr><th scope="col">P(yes) bin</th><th scope="col" class="num">Rows</th><th scope="col">Share</th><th scope="col" class="num">Mean P</th><th scope="col" class="num">Mean raw</th><th scope="col" class="num">Yes</th><th scope="col" class="num">Flagged</th></tr></thead>
    <tbody>${s.bins.map(x => `<tr${b && x.hi > b[0] && x.lo < b[1] ? ' class="inband"' : ""}><td class="m">${x.lo.toFixed(1)}-${x.hi.toFixed(1)}${b && x.hi > b[0] && x.lo < b[1] ? ' <span class="bandtag">band</span>' : ""}</td><td class="num">${x.n}</td><td><span class="bar" style="width:${(x.share * 100).toFixed(1)}%" aria-hidden="true"></span><span class="barv">${pct(x.share)}</span></td><td class="num">${f3(x.meanP)}</td><td class="num">${f3(x.meanRaw)}</td><td class="num">${pct(x.shareYes)}</td><td class="num">${pct(x.shareLow)}</td></tr>`).join("")}</tbody></table></div></figure>`).join("");
}

/* ---------- charts ---------- */
const nbOpen = {};
function numbers(host, caption, head, rows) {
  const key = host.id || caption, open = !!nbOpen[key];
  host.innerHTML = `<button type="button" aria-expanded="${open}">${open ? "Hide the numbers" : "Show the numbers"}</button><div class="nbwrap${open ? "" : " hidden"}" tabindex="0" role="region" aria-label="${esc(caption)}"><table><caption class="sr">${esc(caption)}</caption><thead><tr>${head.map(h => `<th scope="col">${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  const b = host.querySelector("button");
  b.addEventListener("click", () => { nbOpen[key] = !nbOpen[key]; host.querySelector(".nbwrap").classList.toggle("hidden", !nbOpen[key]); b.setAttribute("aria-expanded", nbOpen[key]); b.textContent = nbOpen[key] ? "Hide the numbers" : "Show the numbers"; });
}
function showTip(e, html) { const t = $("tip"); t.innerHTML = html; t.style.display = "block";
  const x = e.clientX + 14, y = e.clientY + 14, w = t.offsetWidth, h = t.offsetHeight;
  t.style.left = Math.max(4, Math.min(x, window.innerWidth - w - 8)) + "px"; t.style.top = (y + h > window.innerHeight ? Math.max(4, e.clientY - h - 10) : y) + "px"; }
function hideTip() { const t = $("tip"); if (t) t.style.display = "none"; }
const SLOT = ["var(--c1)", "var(--c2)", "var(--c3)", "var(--c4)"];
function roundTop(x, y, w, h, r) {
  if (h <= 0) return "";
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
const DAY = 86400000;
const dayKey = t => new Date(t).toISOString().slice(0, 10);
const fmtDay = t => new Date(t).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
function chartRows() { const q = $("chartQ").value; return S.rows.filter(r => r.ok && r.success && isFinite(r.t) && (q === "__all" || r.qid === q)); }

function renderDrift() {
  const host = $("chDrift"), W = host.clientWidth || 600, H = W < 520 ? 220 : 260;
  const narrow = W < 520, m = { l: 34, r: narrow ? 12 : 158, t: 22, b: 26 };
  const rs = chartRows(), win = Math.max(5, Math.min(5000, parseInt($("win").value, 10) || 40));
  if (rs.length < win + 1) { host.innerHTML = `<p class="empty">Fewer than ${win + 1} answered rows with a readable timestamp for this choice. Shorten the window.</p>`; $("lgDrift").innerHTML = ""; $("nbDrift").innerHTML = ""; return; }
  // prefix sums so a 100k-row log costs one pass; plot at most ~1200 points
  const n = rs.length, cTop = new Float64Array(n + 1), cNum = new Uint32Array(n + 1), cLow = new Uint32Array(n + 1);
  for (let i = 0; i < n; i++) { const r = rs[i]; cTop[i + 1] = cTop[i] + (r.maxp != null ? r.maxp : 0); cNum[i + 1] = cNum[i] + (r.maxp != null ? 1 : 0); cLow[i + 1] = cLow[i] + (r.low ? 1 : 0); }
  const step = Math.max(1, Math.ceil((n - win + 1) / 1200)), pts = [];
  for (let i = win - 1; i < n; i += step) {
    const a = i - win + 1, k = cNum[i + 1] - cNum[a];
    pts.push({ t: rs[i].t, i, top: k ? (cTop[i + 1] - cTop[a]) / k : null, low: (cLow[i + 1] - cLow[a]) / win, from: rs[a], to: rs[i] });
  }
  if (pts[pts.length - 1].i !== n - 1) { const i = n - 1, a = i - win + 1, k = cNum[n] - cNum[a]; pts.push({ t: rs[i].t, i, top: k ? (cTop[n] - cTop[a]) / k : null, low: (cLow[n] - cLow[a]) / win, from: rs[a], to: rs[i] }); }
  $("driftNote").textContent = `rolling mean of the top probability, and the share of answers flagged low_confidence, over the last ${win} answered rows` + (step > 1 ? `; every ${step}th window is plotted` : "");
  let t0 = Infinity, t1 = -Infinity; for (const r of rs) { if (r.t < t0) t0 = r.t; if (r.t > t1) t1 = r.t; }
  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const X = t => m.l + (t1 === t0 ? pw / 2 : (t - t0) / (t1 - t0) * pw), Y = v => m.t + (1 - v) * ph;
  let g = "";
  for (const v of [0, .25, .5, .75, 1]) g += `<line class="grid" x1="${m.l}" x2="${m.l + pw}" y1="${Y(v)}" y2="${Y(v)}"/><text x="${m.l - 6}" y="${Y(v) + 3.5}" text-anchor="end">${v.toFixed(2)}</text>`;
  const nT = Math.max(2, Math.min(7, Math.floor(pw / 80))), tstep = Math.max(DAY, Math.ceil((t1 - t0) / nT / DAY) * DAY);
  let guard = 0;
  for (let t = Math.ceil(t0 / DAY) * DAY; t <= t1 && guard++ < 20; t += tstep) g += `<line class="axis" x1="${X(t)}" x2="${X(t)}" y1="${m.t + ph}" y2="${m.t + ph + 4}"/><text x="${X(t)}" y="${H - 8}" text-anchor="middle">${fmtDay(t)}</text>`;
  let prev = null, marks = "", nMarks = 0, lastX = -1e9;
  for (const r of rs) { if (r.calv && prev !== null && r.calv !== prev && nMarks < 12) { const x = X(r.t); const flip = x + 120 > W - 2; marks += `<line x1="${x}" x2="${x}" y1="${m.t - 6}" y2="${m.t + ph}" stroke="var(--graphite)" stroke-width="1"/>${x - lastX > 120 ? `<text x="${flip ? x - 4 : x + 4}" y="${m.t - 9}" text-anchor="${flip ? "end" : "start"}">calibration ${esc(r.calv.slice(0, 8))}</text>` : ""}`; lastX = x; nMarks++; } if (r.calv) prev = r.calv; }
  const path = key => { let d = "", pen = false; for (const p of pts) { if (p[key] == null) { pen = false; continue; } d += (pen ? "L" : "M") + X(p.t).toFixed(1) + "," + Y(p[key]).toFixed(1); pen = true; } return d; };
  const last = pts[pts.length - 1];
  let labels = "";
  if (!narrow) {
    const yA = Y(last.top ?? 0), yB = Y(last.low);
    if (Math.abs(yA - yB) >= 14) labels = `<text x="${X(last.t) + 8}" y="${yA + 3.5}" style="fill:var(--ink)">top probability ${f2(last.top)}</text><text x="${X(last.t) + 8}" y="${yB + 3.5}" style="fill:var(--ink)">flagged share ${f2(last.low)}</text>`;
  }
  host.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Rolling mean of top probability and rolling share of low_confidence answers over time">
    ${g}<line class="axis" x1="${m.l}" x2="${m.l + pw}" y1="${m.t + ph}" y2="${m.t + ph}"/>${marks}
    <path d="${path("top")}" fill="none" stroke="var(--c1)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    <path d="${path("low")}" fill="none" stroke="var(--c2)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    ${last.top != null ? `<circle cx="${X(last.t)}" cy="${Y(last.top)}" r="4" fill="var(--c1)" stroke="var(--paper)" stroke-width="2"/>` : ""}
    <circle cx="${X(last.t)}" cy="${Y(last.low)}" r="4" fill="var(--c2)" stroke="var(--paper)" stroke-width="2"/>
    ${labels}<g class="xh" style="display:none"><line class="xhl" y1="${m.t}" y2="${m.t + ph}" stroke="var(--graphite)" stroke-width="1"/><circle class="xha" r="4" fill="var(--c1)" stroke="var(--paper)" stroke-width="2"/><circle class="xhb" r="4" fill="var(--c2)" stroke="var(--paper)" stroke-width="2"/></g>
    <rect x="${m.l}" y="${m.t}" width="${pw}" height="${ph}" fill="transparent" class="hit"/></svg>`;
  const hit = host.querySelector(".hit"), svg = host.querySelector("svg");
  const move = e => {
    const bb = svg.getBoundingClientRect(), x = (e.clientX - bb.left) * (W / bb.width);
    let lo = 0, hi = pts.length - 1;
    while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (X(pts[mid].t) < x) lo = mid; else hi = mid; }
    const best = Math.abs(X(pts[lo].t) - x) <= Math.abs(X(pts[hi].t) - x) ? pts[lo] : pts[hi];
    host.querySelector(".xh").style.display = "";
    const l = host.querySelector(".xhl"); l.setAttribute("x1", X(best.t)); l.setAttribute("x2", X(best.t));
    const a = host.querySelector(".xha"); if (best.top != null) { a.setAttribute("cx", X(best.t)); a.setAttribute("cy", Y(best.top)); a.style.display = ""; } else a.style.display = "none";
    const b = host.querySelector(".xhb"); b.setAttribute("cx", X(best.t)); b.setAttribute("cy", Y(best.low));
    showTip(e, `<b>${esc(tsShort(rs[best.i].ts))}</b><br>top probability ${f3(best.top)}<br>flagged share ${f3(best.low)}<br>rows ${esc(rowLabel(best.from))} to ${esc(rowLabel(best.to))}`);
  };
  hit.addEventListener("pointermove", move); hit.addEventListener("pointerdown", move);
  hit.addEventListener("pointerleave", () => { hideTip(); host.querySelector(".xh").style.display = "none"; });
  $("lgDrift").innerHTML = `<li><span class="sw line" style="background:var(--c1)"></span>top probability, rolling mean of ${win}</li><li><span class="sw line" style="background:var(--c2)"></span>share flagged low_confidence, same window</li><li><span class="sw line" style="background:var(--graphite);height:1px"></span>calibration_version changed</li>`;
  numbers($("nbDrift"), "Calibration drift, one line per plotted window", ["time (UTC)", "rows", "top probability", "flagged share"], pts.map(p => [tsShort(rs[p.i].ts), `${rowLabel(p.from)} to ${rowLabel(p.to)}`, f3(p.top), f3(p.low)]));
}

function renderMix() {
  const host = $("chMix"), W = host.clientWidth || 600, H = 230, m = { l: 40, r: 10, t: 10, b: 26 };
  let q = $("chartQ").value;
  const note = $("mixNote");
  if (q === "__all") { q = S.questions.find(x => { const r = S.rows.find(y => y.success && y.qid === x); return r && r.type !== "noul"; }) || S.questions[0]; note.textContent = `share of each answer per day for ${q}; pick a question above to change it`; }
  else note.textContent = `share of each answer per day for ${q}`;
  const rs = S.rows.filter(r => r.ok && r.success && r.qid === q && isFinite(r.t));
  if (!rs.length) { host.innerHTML = '<p class="empty">No answered rows with a readable timestamp for this question.</p>'; $("lgMix").innerHTML = ""; $("nbMix").innerHTML = ""; return; }
  const opts = (rs.find(r => r.options) || {}).options || [];
  const cats = opts.slice(0, 4), special = ["no reading", "out of range"];
  const hasOther = opts.length > 4 || rs.some(r => !special.includes(r.label) && !cats.includes(r.label));
  const all = cats.concat(hasOther ? ["other"] : [], special.filter(s => rs.some(r => r.label === s)));
  const color = c => cats.includes(c) ? SLOT[cats.indexOf(c)] : "var(--graphite)";
  const catOf = r => special.includes(r.label) ? r.label : (cats.includes(r.label) ? r.label : "other");
  const byDay = new Map();
  for (const r of rs) { const d = dayKey(r.t); let e = byDay.get(d); if (!e) { e = { d, c: {}, n: 0 }; byDay.set(d, e); } const c = catOf(r); e.c[c] = (e.c[c] || 0) + 1; e.n++; }
  let counts = [...byDay.values()].sort((a, b) => a.d < b.d ? -1 : 1), dropped = 0;
  if (counts.length > 120) { dropped = counts.length - 120; counts = counts.slice(-120); }
  note.textContent += dropped ? `; the last 120 days are drawn and the table holds every day` : "";
  const pw = W - m.l - m.r, ph = H - m.t - m.b, bandw = pw / counts.length, bw = Math.max(2, Math.min(24, bandw * 0.62));
  let g = "";
  for (const v of [0, .5, 1]) g += `<line class="grid" x1="${m.l}" x2="${m.l + pw}" y1="${m.t + (1 - v) * ph}" y2="${m.t + (1 - v) * ph}"/><text x="${m.l - 6}" y="${m.t + (1 - v) * ph + 3.5}" text-anchor="end">${v * 100}%</text>`;
  const every = Math.ceil(counts.length / Math.max(2, Math.floor(pw / 60)));
  let bars = ""; const hits = [];
  counts.forEach((dc, i) => {
    const x = m.l + i * bandw + (bandw - bw) / 2; let y = m.t + ph;
    const present = all.filter(c => dc.c[c]);
    present.forEach((c, k) => {
      const h = dc.c[c] / dc.n * ph, top = k === present.length - 1;
      const yy = y - h, hh = Math.max(0, h - (k > 0 ? 2 : 0));
      bars += top ? `<path d="${roundTop(x, yy, bw, hh, 4)}" fill="${color(c)}"/>` : `<rect x="${x}" y="${yy}" width="${bw}" height="${hh}" fill="${color(c)}"/>`;
      hits.push({ x: m.l + i * bandw, y: yy, w: bandw, h: Math.max(h, 6), html: `<b>${fmtDay(Date.parse(dc.d))}</b><br>${esc(c)}: ${dc.c[c]} of ${dc.n} (${(dc.c[c] / dc.n * 100).toFixed(0)}%)` });
      y = yy;
    });
    if (i % every === 0) g += `<text x="${m.l + i * bandw + bandw / 2}" y="${H - 8}" text-anchor="middle">${fmtDay(Date.parse(dc.d))}</text>`;
  });
  host.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Answer mix per day for ${esc(q)}">${g}${bars}<line class="axis" x1="${m.l}" x2="${m.l + pw}" y1="${m.t + ph}" y2="${m.t + ph}"/>${hits.map((h, i) => `<rect data-i="${i}" x="${h.x}" y="${h.y}" width="${h.w}" height="${h.h}" fill="transparent"/>`).join("")}</svg>`;
  host.querySelectorAll("rect[data-i]").forEach(el => { const f = e => showTip(e, hits[+el.dataset.i].html); el.addEventListener("pointermove", f); el.addEventListener("pointerdown", f); el.addEventListener("pointerleave", hideTip); });
  $("lgMix").innerHTML = all.map(c => `<li><span class="sw" style="background:${color(c)}"></span>${esc(c)}</li>`).join("");
  numbers($("nbMix"), `Answer mix by day for ${q}`, ["day"].concat(all, ["rows"]), [...byDay.values()].sort((a, b) => a.d < b.d ? -1 : 1).map(dc => [dc.d].concat(all.map(c => dc.c[c] || 0), [dc.n])));
}

function renderHists() {
  const host = $("chHist"); host.innerHTML = "";
  const bnd = band();
  const byQ = new Map(); for (const r of S.rows) if (r.ok && r.success) { if (!byQ.has(r.qid)) byQ.set(r.qid, []); byQ.get(r.qid).push(r); }
  S.questions.slice(0, 40).forEach((q, qi) => {
    const all = byQ.get(q) || [], rs = all.filter(r => r.prob != null), type = (all[0] || {}).type;
    const fig = document.createElement("figure");
    fig.innerHTML = `<figcaption><h3>${esc(q)}</h3><span class="mono">${esc(type || "")} · ${nf(rs.length)} answered rows · x is ${type === "noul" ? "P(yes)" + (bnd ? ` · ${nf(rs.filter(r => r.prob >= bnd[0] && r.prob <= bnd[1]).length)} inside the entered band ${bnd[0].toFixed(2)} to ${bnd[1].toFixed(2)}` : "") : "top probability"}</span></figcaption><div class="chart"></div><div class="numbers" id="nbHist-${qi}"></div>`;
    host.appendChild(fig);
    const c = fig.querySelector(".chart"), W = c.clientWidth || 340, H = 160, m = { l: 34, r: 8, t: 8, b: 24 };
    const bins = new Array(10).fill(0); rs.forEach(r => bins[Math.min(9, Math.max(0, Math.floor(r.prob * 10)))]++);
    const mx = Math.max(1, ...bins), top = mx <= 4 ? 4 : mx <= 10 ? 10 : Math.ceil(mx / 10) * 10;
    const pw = W - m.l - m.r, ph = H - m.t - m.b, bwid = pw / 10, bw = Math.min(24, bwid - 2);
    const X = v => m.l + v * pw, Y = v => m.t + (1 - v / top) * ph;
    let s = "";
    if (bnd && type === "noul") s += `<rect x="${X(bnd[0])}" y="${m.t}" width="${Math.max(1, X(bnd[1]) - X(bnd[0]))}" height="${ph}" fill="var(--wash)"/><text x="${(X(bnd[0]) + X(bnd[1])) / 2}" y="${m.t + 10}" text-anchor="middle">entered band</text>`;
    for (const v of [0, top / 2, top]) s += `<line class="grid" x1="${m.l}" x2="${m.l + pw}" y1="${Y(v)}" y2="${Y(v)}"/><text x="${m.l - 5}" y="${Y(v) + 3.5}" text-anchor="end">${nf(Math.round(v))}</text>`;
    for (const v of [0, .5, 1]) s += `<text x="${X(v)}" y="${H - 8}" text-anchor="${v === 0 ? "start" : v === 1 ? "end" : "middle"}">${v.toFixed(1)}</text>`;
    const hits = [];
    bins.forEach((n, i) => {
      const x = m.l + i * bwid + (bwid - bw) / 2;
      if (n) s += `<path d="${roundTop(x, Y(n), bw, Y(0) - Y(n), 4)}" fill="var(--c1)"/>`;
      hits.push(`<rect data-b="${i}" x="${m.l + i * bwid}" y="${m.t}" width="${bwid}" height="${ph}" fill="transparent"/>`);
    });
    c.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Histogram for ${esc(q)}">${s}<line class="axis" x1="${m.l}" x2="${m.l + pw}" y1="${Y(0)}" y2="${Y(0)}"/>${hits.join("")}</svg>`;
    c.querySelectorAll("rect[data-b]").forEach(el => { const i = +el.dataset.b; const f = e => showTip(e, `<b>${esc(q)}</b><br>${(i / 10).toFixed(1)} to ${((i + 1) / 10).toFixed(1)}: ${bins[i]} rows`); el.addEventListener("pointermove", f); el.addEventListener("pointerdown", f); el.addEventListener("pointerleave", hideTip); });
    numbers(fig.querySelector(".numbers"), `Histogram for ${q}`, ["bin", "rows"], bins.map((n, i) => [`${(i / 10).toFixed(1)} to ${((i + 1) / 10).toFixed(1)}`, n]));
  });
  if (S.questions.length > 40) host.insertAdjacentHTML("beforeend", `<p class="mono">The first 40 of ${S.questions.length} questions are drawn.</p>`);
}
function renderCharts() {
  const has = S.rows.some(r => r.ok && r.success);
  $("secCharts").classList.toggle("hidden", !has);
  if (!has) return;
  const sel = $("chartQ"), keep = sel.value;
  sel.innerHTML = `<option value="__all">all questions</option>` + S.questions.map(q => `<option value="${esc(q)}">${esc(q)}</option>`).join("");
  if ([...sel.options].some(o => o.value === keep)) sel.value = keep;
  renderDrift(); renderMix(); renderHists();
}

/* ---------- trail table, virtualised ---------- */
const V = { rh: 34, over: 12, raf: 0 };
function filtered() {
  const q = $("fQ").value, b = $("fBand").value, md = $("fMode").value;
  if (q === "__all" && b === "all" && md === "all") return S.rows;
  return S.rows.filter(r => {
    if (q === "__refused") { if (!(r.ok && r.error)) return false; }
    else if (q === "__bad") { if (r.ok) return false; }
    else if (q !== "__all" && r.qid !== q) return false;
    if (b === "in" && !(r.ok && (r.low || r.bandIn))) return false;
    if (b === "out" && r.ok && (r.low || r.bandIn)) return false;
    if (md !== "all" && r.mode !== md) return false;
    return true;
  });
}
function renderTrail() {
  $("secTrail").classList.remove("hidden");
  const sel = $("fQ"), keep = sel.value;
  sel.innerHTML = `<option value="__all">all rows</option>` + S.questions.map(q => `<option value="${esc(q)}">${esc(q)}</option>`).join("") + `<option value="__refused">refused requests</option><option value="__bad">unreadable lines</option>`;
  if ([...sel.options].some(o => o.value === keep)) sel.value = keep;
  setView(true);
}
function setView(resetScroll) {
  S.view = filtered();
  $("trail").setAttribute("aria-rowcount", String(S.view.length + 1));
  $("trailCount").textContent = `${nf(S.view.length)} of ${nf(S.rows.length)} rows`;
  if (resetScroll) $("vwrap").scrollTop = 0;
  drawWindow();
}
function rowHtml(r, i) {
  const cls = [r.chain === "first break" || r.chain === "link broken" ? "brk" : "", r.chain === "after break" ? "after" : "", S.sel === r.n ? "sel" : ""].join(" ").trim();
  const head = `<tr class="${cls}" data-n="${r.n}" aria-rowindex="${i + 2}"><td class="num n"><button type="button" class="rowbtn" data-open="${r.n}" aria-label="Open row ${esc(rowLabel(r))}">${esc(rowLabel(r))}</button></td>`;
  if (!r.ok) return head + `<td colspan="7" class="empty">unreadable line (${esc(r.parseError)})</td><td class="m">${esc(r.chain)}</td></tr>`;
  const be = r.mode === "deliberate" ? `${esc(r.backend)} · votes` : r.backend ? `${esc(r.backend)} · ${r.calv ? esc(r.calv.slice(0, 10)) : "none"}` : "·";
  const lab = r.label || "·";
  return head + `<td class="m">${esc(tsShort(r.ts))}</td><td class="clip" title="${esc(r.qid ?? "")}">${esc(r.qid ?? "·")}</td><td class="clip" title="${esc(lab)}">${esc(lab)}${r.cache ? ' <span class="mono">cache</span>' : ""}</td><td class="num">${r.oor != null ? "out of range" : f3(r.prob)}</td><td><span class="flag${r.low || r.bandIn ? " on" : ""}">${r.low ? "flagged" : r.bandIn ? "in band" : "·"}</span></td><td class="m">${esc(r.mode ?? "·")}</td><td class="m clip">${be}</td><td class="m">${esc(r.chain)}</td></tr>`;
}
function drawWindow(depth) {
  const rs = S.view, wrap = $("vwrap"), tb = $("tbody");
  const thead = wrap.querySelector("thead"), headH = thead ? thead.offsetHeight : 0;
  const act = document.activeElement, focusN = act && act.dataset && act.dataset.open ? act.dataset.open : null;
  let a, b;
  if (S.printAll) { a = 0; b = Math.min(rs.length, 2000); }
  else {
    const top = Math.max(0, wrap.scrollTop - headH), vis = Math.ceil((wrap.clientHeight || 600) / V.rh) + 1;
    a = Math.max(0, Math.floor(top / V.rh) - V.over); b = Math.min(rs.length, a + vis + 2 * V.over);
  }
  const sp = h => h > 0 ? `<tr class="spacer" aria-hidden="true"><td colspan="9" style="height:${h}px"></td></tr>` : "";
  let html = sp(a * V.rh);
  for (let i = a; i < b; i++) html += rowHtml(rs[i], i);
  html += sp((rs.length - b) * V.rh);
  tb.innerHTML = rs.length ? html : `<tr><td colspan="9" class="empty">No rows match these filters.</td></tr>`;
  const tr = tb.querySelector("tr[data-n]");
  if (tr && !S.printAll) { const h = tr.getBoundingClientRect().height; if (h > 10 && Math.abs(h - V.rh) > 0.5 && !depth) { V.rh = h; return drawWindow(1); } }
  if (focusN) { const btn = tb.querySelector(`button[data-open="${focusN}"]`); if (btn) btn.focus({ preventScroll: true }); else if (wrap.contains(act) || !document.body.contains(act)) wrap.focus({ preventScroll: true }); }
  S.drawn = b - a;
}
function showRaw(n) {
  const r = S.rows[n - 1]; if (!r) return;
  S.sel = n; const pre = $("raw"); pre.classList.remove("hidden");
  let line = S.lines[n - 1], body;
  try { const t = line.charCodeAt(0) === 0xfeff ? line.slice(1) : line; body = JSON.stringify(JSON.parse(t), null, 2); } catch (e) { body = line; }
  if (body.length > 200000) body = body.slice(0, 200000) + `\n… ${nf(body.length - 200000)} more characters not shown`;
  pre.textContent = `row ${rowLabel(r)}${S.multi ? ` (${S.files[r.f].name}, series row ${r.n})` : ""} · chain: ${r.chain}\n` + body;
}
function jumpTo(n) {
  if (!S.rows[n - 1]) return;
  $("fQ").value = "__all"; $("fBand").value = "all"; $("fMode").value = "all";
  S.view = S.rows; $("trail").setAttribute("aria-rowcount", String(S.view.length + 1));
  $("trailCount").textContent = `${nf(S.view.length)} of ${nf(S.rows.length)} rows`;
  showRaw(n);
  const wrap = $("vwrap"), headH = wrap.querySelector("thead").offsetHeight;
  wrap.scrollTop = Math.max(0, headH + (n - 1) * V.rh - wrap.clientHeight / 2);
  drawWindow();
  wrap.scrollIntoView({ block: "nearest" });
  const btn = $("tbody").querySelector(`button[data-open="${n}"]`); if (btn) btn.focus({ preventScroll: true });
}
function parseRowRef(s) {
  s = String(s).trim(); let m;
  if ((m = /^(\d+)\s*:\s*(\d+)$/.exec(s))) { const f = S.files[+m[1] - 1]; return f && +m[2] >= 1 && +m[2] <= f.lines.length ? f.offset + +m[2] : null; }
  if ((m = /^\d+$/.exec(s))) { const n = +s; return n >= 1 && n <= S.rows.length ? n : null; }
  return null;
}

/* ---------- export ---------- */
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function flagsCsv() {
  const head = ["kind", "row", "file", "ts", "request_id", "question_id", "answer", "probability", "detail"];
  return [head.join(",")].concat(S.flags.map(f => { const r = S.rows[f.n - 1]; return [f.kind, rowLabel(r), S.files[r ? r.f : 0] ? S.files[r ? r.f : 0].name : "", f.ts, f.rid, f.qid, f.answer, f.prob == null ? "" : f.prob, f.detail].map(A.csvCell).join(","); })).join("\r\n") + "\r\n";
}
function sanitisedJsonl() {
  const out = []; let skipped = 0;
  for (const l of S.lines) { const s = A.sanitiseLine(l, S.keep); if (s == null) skipped++; else out.push(s); }
  return { text: out.length ? out.join("\n") + "\n" : "", rows: out.length, skipped };
}
const FIG_LABEL = { email: "values holding an email address", phone: "values holding a phone number", iban: "values holding an IBAN that passes its checksum", name: "values with name-like words" };
const KIND_LABEL = { email: "email address", phone: "phone number", iban: "IBAN (checksum passes)", name: "name-like words" };
function redCounts(fields) {
  const tot = { email: 0, phone: 0, iban: 0, name: 0 };
  for (const [f, c] of S.acc.redByField) if (!fields || fields.has(f)) for (const k of A.RED_KINDS) tot[k] += c[k];
  return tot;
}
function renderExport() {
  $("secExport").classList.remove("hidden");
  const tot = redCounts(null), any = A.RED_KINDS.some(k => tot[k]);
  const fieldsHit = [...S.acc.redByField].map(([f, c]) => `${f} (${A.RED_KINDS.filter(k => c[k]).map(k => `${c[k]} ${k}`).join(", ")})`);
  $("redSummary").innerHTML = `<ul class="figures red">${A.RED_KINDS.map(k => `<li><span class="fig-n">${nf(tot[k])}</span><span class="fig-l">${esc(FIG_LABEL[k])}</span></li>`).join("")}</ul>`
    + `<p class="mono">${nf(S.acc.scanned)} text values and keys scanned. ${any ? `Fields with matches: ${esc(fieldsHit.join("; "))}. Those fields start unticked below.` : "No matches."}</p>`;
  const fields = [...S.acc.fields].sort((a, b) => b[1] - a[1]);
  if (!S.keep) S.keep = new Set(fields.map(([f]) => f).filter(f => !S.acc.redByField.has(f)));
  $("fieldPick").innerHTML = fields.length ? fields.map(([f, n], i) => `<label class="chk"><input type="checkbox" data-field="${esc(f)}" id="fp${i}"${S.keep.has(f) ? " checked" : ""}> <span class="mono">${esc(f)}</span> <span class="cnt">${nf(n)}${S.acc.redByField.has(f) ? " · has matches" : ""}</span></label>`).join("") : '<p class="empty">No readable rows.</p>';
}
let pending = null, lastBtn = null;
function guarded(action, fields, what) {
  const tot = redCounts(fields), parts = A.RED_KINDS.filter(k => tot[k]).map(k => `${nf(tot[k])} ${KIND_LABEL[k]}`);
  if (!parts.length) { action(); return; }
  pending = action;
  $("warnText").textContent = `The ${what} would include fields where the redaction check matched: ${parts.join(", ")}. These are counts from the patterns above. The matched text was not kept and is not shown here. Untick those fields or redact the log first, or export anyway.`;
  const w = $("warn"); w.classList.remove("hidden"); w.focus();
}
function closeWarn(go) {
  $("warn").classList.add("hidden");
  const p = pending; pending = null;
  if (go && p) p();
  (lastBtn || $("btnCsv")).focus();
}

/* ---------- seal download ---------- */
function saveSeals() {
  if (!S.files.length) return;
  let start = A.ZERO; const out = [];
  for (const f of S.files) {
    const text = A.sealText(f.lines, start, f.name);
    const ch = A.parseSeal(text); start = A.sealFinal(ch);
    const base = f.name.replace(/ \(sample\)$/, "");
    out.push({ name: base === "pasted rows" ? `pasted-${new Date().toISOString().slice(0, 10)}.jsonl.chain` : base + ".chain", text });
  }
  out.forEach((o, i) => setTimeout(() => download(o.name, o.text, "text/plain"), i * 350));
  return out;
}

/* ---------- wiring ---------- */
function renderFileList() {
  const t = S.timing;
  $("fileList").innerHTML = S.files.map((f, k) => `<li><span class="mono">${S.multi ? `file ${k + 1}` : "log"}</span> ${esc(f.name)} <span class="mono">· ${nf(f.lines.length)} rows${f.sealName ? ` · seal ${esc(f.sealName)}` : " · no seal"}</span></li>`).join("")
    + (t ? `<li class="mono">read ${secs(t.read)} · hashed ${secs(t.hash)} · drawn ${secs(t.render)} · ${nf(t.rows)} rows</li>` : "");
}
function renderAll() {
  S.questions = []; const seen = new Set();
  for (const r of S.rows) if (r.ok && r.success && !seen.has(r.qid)) { seen.add(r.qid); S.questions.push(r.qid); }
  S.cases = A.buildCases(S.rows); S.keep = null;
  S.cases.sort((a, b) => (b.conflicts.length - a.conflicts.length) || (b.reqs.length - a.reqs.length) || (a.reqs[0].firstRow - b.reqs[0].firstRow));
  renderIntegrity();
  const has = S.rows.length > 0;
  ["secFlags", "secCases", "secTrail", "secExport"].forEach(id => $(id).classList.toggle("hidden", !has));
  if (has) { renderFlags(); renderCases(); renderCalib(); renderCharts(); renderTrail(); renderExport(); }
  else { $("secCalib").classList.add("hidden"); $("secCharts").classList.add("hidden"); }
  $("raw").classList.add("hidden");
  pending = null; $("warn").classList.add("hidden"); $("expNote").textContent = "";
  const span = S.rows.filter(r => r.ok && r.success && isFinite(r.t));
  $("srcline").textContent = `${S.label}` + (span.length ? ` · ${tsShort(span[0].ts).slice(0, 10)} to ${tsShort(span[span.length - 1].ts).slice(0, 10)}` : "") + (S.files.some(f => f.seal) ? " · seal loaded" : "");
  $("btnSeal").disabled = !S.lines.length;
  $("btnSeal").textContent = S.multi ? "Save seals for these files" : "Save a seal for this log";
  $("pasteNote").textContent = "";
}
async function readFiles(fileList) {
  const list = [...fileList]; if (!list.length) return;
  const logs = [], seals = [];
  for (const f of list) {
    let isSeal = /\.chain$/i.test(f.name);
    if (!isSeal) { try { const head = await f.slice(0, 200).text(); isSeal = /^# audit-row-reader chain/.test(head) || /^[0-9a-fA-F]{64}\s*(\r?\n|$)/.test(head); } catch (e) { isSeal = false; /* unreadable head: treat as a log; reading it will report the error */ } }
    if (isSeal) seals.push({ name: f.name, text: await f.text() }); else logs.push({ name: f.name, file: f });
  }
  if (logs.length) return loadAll(logs, seals, logs.length > 1 ? `${logs.length} files` : logs[0].name);
  if (seals.length && S.srcs.length) return loadAll(S.srcs, S.sealSrcs.concat(seals), S.label);
  $("pasteNote").textContent = "Only seal files were chosen. Load a log first, then add its seal.";
}
function sampleSealText() { return `${A.CHAIN_HEADER}\n# start: ${A.ZERO}\n# file: sample-audit.jsonl\n${window.SAMPLE_CHAIN.join("\n")}\n`; }
function sampleSeries() {
  const L = window.SAMPLE_LINES, H = window.SAMPLE_CHAIN, cuts = [];
  L.forEach((l, i) => { const d = JSON.parse(l).ts.slice(0, 10); if (d >= "2026-09-26" && cuts.length === 0) cuts.push(i); if (d >= "2026-10-01" && cuts.length === 1) cuts.push(i); });
  const bounds = [0, cuts[0], cuts[1], L.length];
  const logs = [], seals = [];
  for (let k = 0; k < 3; k++) {
    const a = bounds[k], b = bounds[k + 1], name = `audit.${k + 1}.jsonl`;
    logs.push({ name, text: L.slice(a, b).join("\n") + "\n" });
    seals.push({ name: name + ".chain", text: `${A.CHAIN_HEADER}\n# start: ${a ? H[a - 1] : A.ZERO}\n# file: ${name}\n${H.slice(a, b).join("\n")}\n` });
  }
  return { logs, seals, cuts };
}
function init() {
  const st = store(), ld = A.loadSettings(st);
  applySettings(ld.settings);
  if (!ld.ok) $("savedNote").textContent = `saved settings could not be read (${ld.error}); using the defaults`;
  const drop = $("drop");
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => readFiles(e.dataTransfer.files));
  window.addEventListener("dragover", e => e.preventDefault()); window.addEventListener("drop", e => e.preventDefault());
  $("fileLog").addEventListener("change", e => { readFiles(e.target.files); e.target.value = ""; });
  $("fileChain").addEventListener("change", e => { readFiles(e.target.files); e.target.value = ""; });
  $("btnSample").addEventListener("click", () => loadAll([{ name: "sample-audit.jsonl", text: window.SAMPLE_LINES.join("\n") + "\n" }], [{ name: "sample-audit.jsonl.chain", text: sampleSealText() }], "sample-audit.jsonl (sample)"));
  $("btnSeries").addEventListener("click", () => { const s = sampleSeries(); loadAll(s.logs, s.seals, "sample as three rotated files"); });
  $("btnPaste").addEventListener("click", () => {
    const t = $("paste").value;
    if (!t.trim()) { $("pasteNote").textContent = "The box is empty. Paste rows first."; return; }
    if (t.length > 1e6) $("paste").value = "";
    loadAll([{ name: "pasted rows", text: t }], [], "pasted rows").then(ok => {
      if (ok && t.length > 1e6) $("pasteNote").textContent = `The ${(t.length / 1048576).toFixed(1)} MB paste was read and taken out of the box, because a box that size slows every redraw. For big logs, drop the file instead.`;
    });
  });
  $("btnStop").addEventListener("click", () => { JOB++; progEnd(); $("pasteNote").textContent = "Stopped. The page still shows the last log that finished loading."; });
  $("btnSeal").addEventListener("click", saveSeals);
  $("btnCsv").addEventListener("click", () => { lastBtn = $("btnCsv"); $("expNote").textContent = ""; guarded(() => { download("flagged-rows.csv", flagsCsv(), "text/csv"); $("expNote").textContent = `${nf(S.flags.length)} flagged entries written to flagged-rows.csv`; }, null, "CSV"); });
  $("btnJsonl").addEventListener("click", () => {
    lastBtn = $("btnJsonl");
    if (!S.keep || !S.keep.size) { $("expNote").textContent = "Tick at least one field to export."; return; }
    guarded(() => { const r = sanitisedJsonl(); download("audit-sanitised.jsonl", r.text, "application/x-ndjson"); $("expNote").textContent = `${nf(r.rows)} rows written to audit-sanitised.jsonl with ${S.keep.size} field(s)${r.skipped ? `; ${nf(r.skipped)} unreadable lines left out` : ""}.`; }, S.keep, "JSONL");
  });
  $("btnWarnGo").addEventListener("click", () => closeWarn(true));
  $("btnWarnCancel").addEventListener("click", () => closeWarn(false));
  $("warn").addEventListener("keydown", e => { if (e.key === "Escape") closeWarn(false); });
  $("fieldPick").addEventListener("change", e => { const f = e.target.dataset.field; if (f == null) return; if (e.target.checked) S.keep.add(f); else S.keep.delete(f); });
  $("btnAllFields").addEventListener("click", () => { S.keep = new Set(S.acc.fields.keys()); renderExport(); });
  $("btnNoFields").addEventListener("click", () => { S.keep = new Set(); renderExport(); });
  const rescreen = () => { saveScreens(); if (!S.rows.length) return; renderFlags(); renderHists(); renderCalib(); drawWindow(); };
  ["runN", "runKey", "shiftAlpha", "tvdLine", "bandLo", "bandHi"].forEach(id => $(id).addEventListener("change", rescreen));
  $("btnReset").addEventListener("click", () => {
    const res = st ? A.resetSettings(st) : { ok: false, settings: A.cleanSettings(null), error: "storage unavailable" };
    applySettings(res.settings);
    $("savedNote").textContent = res.ok ? "settings reset to the defaults" : `settings reset for this tab (${res.error})`;
    if (S.rows.length) { renderFlags(); renderHists(); renderCalib(); drawWindow(); }
  });
  $("caseFilter").addEventListener("change", () => { S.caseShown = 50; renderCases(); });
  $("btnMoreCases").addEventListener("click", () => { S.caseShown += 50; renderCases(); });
  $("calQ").addEventListener("change", renderCalib);
  ["chartQ", "win"].forEach(id => $(id).addEventListener("change", () => { renderDrift(); renderMix(); }));
  ["fQ", "fBand", "fMode"].forEach(id => $(id).addEventListener("change", () => setView(true)));
  $("gotoRow").addEventListener("change", e => { const n = parseRowRef(e.target.value); if (n) jumpTo(n); else e.target.setAttribute("aria-invalid", "true"); });
  $("gotoRow").addEventListener("input", e => e.target.removeAttribute("aria-invalid"));
  $("vwrap").addEventListener("scroll", () => { if (V.raf) return; V.raf = requestAnimationFrame(() => { V.raf = 0; drawWindow(); }); }, { passive: true });
  $("tbody").addEventListener("click", e => { const tr = e.target.closest("tr[data-n]"); if (tr) { showRaw(+tr.dataset.n); drawWindow(); } });
  document.addEventListener("click", e => { const b = e.target.closest("button[data-row]"); if (b) jumpTo(+b.dataset.row); });
  window.addEventListener("beforeprint", () => { if (S.rows.length) { S.printAll = true; drawWindow(); } });
  window.addEventListener("afterprint", () => { if (S.printAll) { S.printAll = false; drawWindow(); } });
  let rt; window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { if (S.rows.length) { renderDrift(); renderMix(); renderHists(); drawWindow(); } }, 150); });
}

window.ARR_APP = { sampleSealText, S, V, loadAll, readFiles, sampleSeries, buildFlags, renderAll, drawWindow, setView, jumpTo, showRaw, flagsCsv, sanitisedJsonl, saveSeals, guarded, closeWarn,
  readInputs, applySettings, saveScreens, parseRowRef, rowLabel, integrityNote, boundaryNote, firstBreakGlobal, store, esc };
document.addEventListener("DOMContentLoaded", () => {
  init();
  const done = () => document.dispatchEvent(new Event("arr-ready"));
  if (/[?&]sample\b/.test(location.search)) $("btnSample").click();
  if (/[?&]series\b/.test(location.search)) $("btnSeries").click();
  if (/[?&]seriesgap\b/.test(location.search)) { const s = sampleSeries(); loadAll([s.logs[0], s.logs[2]], [s.seals[0], s.seals[2]], "sample series with file 2 removed"); }
  done();
});
})();
