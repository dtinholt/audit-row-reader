/* Audit Row Reader self-check.
   On every page open: the core checks run against the embedded sample (no page state is touched).
   With ?selfcheck in the URL: the page-level checks run too (they load logs into the page).
   With ?bench=N: one timed load of N synthetic rows through the file-reading path.
   Results: console.table, the footer line, and body[data-selfcheck] = pass | fail. */
"use strict";
(function () {
const A = window.ARR;
const $ = id => document.getElementById(id);

function sampleRows() { return window.SAMPLE_LINES.map((l, i) => A.normRow(l, i + 1)); }
function splitSeries(L, H) {
  const cuts = [];
  L.forEach((l, i) => { const d = JSON.parse(l).ts.slice(0, 10); if (d >= "2026-09-26" && cuts.length === 0) cuts.push(i); if (d >= "2026-10-01" && cuts.length === 1) cuts.push(i); });
  const b = [0, cuts[0], cuts[1], L.length];
  return [0, 1, 2].map(k => ({ name: `audit.${k + 1}.jsonl`, lines: L.slice(b[k], b[k + 1]), seal: { start: b[k] ? H[b[k] - 1] : A.ZERO, hashes: H.slice(b[k], b[k + 1]), file: null, bad: 0 } }));
}
const asSeries = files => files.map(f => ({ name: f.name, n: f.lines.length, seal: f.seal, mine: f.seal ? A.chainOf(f.lines, f.seal.start) : null }));
function withPrev(lines) { const out = []; for (let i = 0; i < lines.length; i++) { const o = JSON.parse(lines[i]); o.prev_hash = i ? A.sha256hex(out[i - 1]) : null; out.push(JSON.stringify(o)); } return out; }
const asPrevSeries = parts => parts.map(lines => ({ name: "", n: lines.length, lineHashes: lines.map(A.sha256hex), prev: lines.map(l => JSON.parse(l).prev_hash) }));
function fakeStorage(mode) {
  const m = new Map();
  return { getItem: k => { if (mode === "throwGet") throw new DOMException("denied", "SecurityError"); return m.has(k) ? m.get(k) : null; },
    setItem: (k, v) => { if (mode === "quota") throw new DOMException("full", "QuotaExceededError"); m.set(k, String(v)); },
    removeItem: k => m.delete(k), _m: m };
}

function coreChecks() {
  const res = [], ok = (feature, name, pass, got) => res.push({ feature, check: name, pass: !!pass, got: String(got) });
  const L = window.SAMPLE_LINES, H = window.SAMPLE_CHAIN, n = L.length;
  ok("chain", "sha256('') known vector", A.sha256hex("") === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", A.sha256hex("").slice(0, 16));
  ok("chain", "sha256('abc') known vector", A.sha256hex("abc") === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", A.sha256hex("abc").slice(0, 16));
  const base = A.verifySeal(L, H);
  ok("chain", `sample seal (written by tools/seal.py) verifies all ${n} rows`, base.kind === "ok", base.kind);
  const k = 137, edited = L.slice(), mid = Math.floor(edited[k - 1].length / 2);
  edited[k - 1] = edited[k - 1].slice(0, mid) + (edited[k - 1][mid] === "7" ? "8" : "7") + edited[k - 1].slice(mid + 1);
  ok("chain", `one character changed in row ${k}: break at row ${k}`, A.verifySeal(edited, H).first === k, A.verifySeal(edited, H).first);
  const e2 = A.verifySeal(L.slice(0, 249).concat(L.slice(250)), H); ok("chain", "row 250 deleted: break at row 250", e2.first === 250, e2.first);
  const e3 = A.verifySeal(L.slice(0, n - 3), H); ok("chain", `last 3 rows cut: break at row ${n - 2}`, e3.first === n - 2 && e3.kind === "truncated", e3.first);
  const sw = L.slice(); [sw[99], sw[100]] = [sw[100], sw[99]];
  ok("chain", "rows 100 and 101 swapped: break at row 100", A.verifySeal(sw, H).first === 100, A.verifySeal(sw, H).first);
  const e5 = A.verifySeal(L.concat(['{"ts": "2026-10-05T00:00:00.000Z"}']), H);
  ok("chain", "one row appended: no break, appended row reported", e5.first === null && e5.appendedFrom === n + 1, e5.appendedFrom);
  const ph = withPrev(L);
  const p0 = A.verifySeries(asPrevSeries([ph]), "prev_hash"); ok("chain", "prev_hash copy of the sample verifies", p0.first === null, JSON.stringify(p0.first));
  const ph2 = ph.slice(); ph2[k - 1] = ph2[k - 1].replace('"ts":"2026', '"ts":"2027');
  const p1 = A.verifySeries(asPrevSeries([ph2]), "prev_hash"); ok("chain", `prev_hash copy, row ${k} edited: break at row ${k + 1}`, p1.first && p1.first.row === k + 1 && ph2[k - 1] !== ph[k - 1], JSON.stringify(p1.first));
  const rows = sampleRows();
  ok("parse", "every sample row parses", rows.every(r => r.ok), rows.filter(r => !r.ok).length + " unreadable");
  const inB = (lo, hi) => rows.filter(r => r.success && r.type === "noul" && r.prob != null && r.prob >= lo && r.prob <= hi);
  const srv = inB(0.4, 0.6), extra = inB(0.3, 0.7).filter(r => !r.low);
  ok("band", "re-screen at 0.4 to 0.6 matches every server band flag", srv.length > 0 && srv.every(r => r.low) && rows.filter(r => r.low && !r.degraded && r.type === "noul" && r.mode === "fast").every(r => srv.includes(r)), srv.length + " rows");
  ok("band", "re-screen at 0.3 to 0.7 finds rows the server did not flag", extra.length > 0, extra.length + " extra rows");

  // 1. large logs
  const text = L.join("\r\n") + "\n" + L[0];
  const sp = new A.LineSplitter(); let got = [];
  for (let i = 0; i < text.length; i += 7) got = got.concat(sp.push(text.slice(i, i + 7)));
  got = got.concat(sp.end());
  ok("large logs", "streaming splitter, 7-character chunks across CRLF, equals the whole-text rule", got.length === n + 1 && got.every((l, i) => l === A.splitLines(text)[i]), got.length + " lines");
  const sp2 = new A.LineSplitter(); const g2 = sp2.push("a\rb\nc\r\nd"); g2.push(...sp2.end());
  ok("large logs", "bare carriage return is counted and kept inside its line, as seal.py does", sp2.bareCR === 1 && g2[0] === "a\rb" && g2.length === 3, `${sp2.bareCR} bare CR, ${g2.length} lines`);
  const big = []; for (let i = 0; i < n * 10; i++) big.push(L[i % n]);
  const t0 = performance.now(); const acc = A.newAcc(); const br = big.map((l, i) => A.normRow(l, i + 1, acc)); const t1 = performance.now();
  const ch = A.chainOf(big); const t2 = performance.now();
  ok("large logs", `10x sample (${big.length} rows): parse, redaction scan and seal`, br.length === big.length && br.every(r => r.ok) && ch.length === big.length, `parse ${Math.round(t1 - t0)} ms, seal ${Math.round(t2 - t1)} ms`);

  // 2. multi-file
  const ser = splitSeries(L, H);
  const s0 = A.verifySeries(asSeries(ser), "seal");
  ok("multi-file", "sample as three rotated files: every file and both boundaries hold", s0.first === null && s0.boundaries.length === 2 && s0.boundaries.every(b => b.ok === true && b.why === "holds"), s0.boundaries.map(b => b.why).join(","));
  ok("multi-file", "the series' last hash equals the single-file seal's last hash", A.sealFinal(ser[2].seal) === H[n - 1], A.sealFinal(ser[2].seal).slice(0, 12));
  const gap = [ser[0], ser[2]], s1 = A.verifySeries(asSeries(gap), "seal");
  ok("multi-file", "middle file missing: breaks at the boundary into the third file, row 1", s1.first && s1.first.file === 1 && s1.first.row === 1 && s1.boundaries[0].why === "startMismatch", JSON.stringify(s1.first) + " " + s1.boundaries[0].why);
  const cut = ser.map(f => Object.assign({}, f)); cut[0] = Object.assign({}, ser[0], { lines: ser[0].lines.slice(0, -1).concat([ser[0].lines[ser[0].lines.length - 1].replace("2026-09", "2026-08")]) });
  const s2 = A.verifySeries(asSeries(cut), "seal");
  ok("multi-file", "last row of file 1 edited: break in file 1 at its last row, boundary reports file 1 broken", s2.first && s2.first.file === 0 && s2.first.row === ser[0].lines.length && s2.boundaries[0].why === "linkHoldsFileBroken" && s2.boundaries[1].why === "holds", JSON.stringify(s2.first) + " " + s2.boundaries.map(b => b.why));
  const app = ser.map(f => Object.assign({}, f)); app[0] = Object.assign({}, ser[0], { lines: ser[0].lines.concat([ser[0].lines[0]]) });
  const s3 = A.verifySeries(asSeries(app), "seal");
  ok("multi-file", "rows appended to a closed file: boundary 1 to 2 breaks at file 2 row 1", s3.first && s3.first.file === 1 && s3.first.row === 1 && s3.boundaries[0].why === "rowsPastSeal", JSON.stringify(s3.first));
  const parts = [ph.slice(0, 150), ph.slice(150, 300), ph.slice(300)];
  const ps0 = A.verifySeries(asPrevSeries(parts), "prev_hash");
  ok("multi-file", "prev_hash across three files holds at both boundaries", ps0.first === null && ps0.boundaries.every(b => b.ok === true), ps0.boundaries.map(b => b.why).join(","));
  const bad = parts.map(p => p.slice()); bad[1][bad[1].length - 1] = bad[1][bad[1].length - 1].replace('"ts":"2026', '"ts":"2025');
  const ps1 = A.verifySeries(asPrevSeries(bad), "prev_hash");
  ok("multi-file", "prev_hash, last row of file 2 edited: break at file 3 row 1, boundary 2 to 3 broken, 1 to 2 holds", ps1.first && ps1.first.file === 2 && ps1.first.row === 1 && ps1.boundaries[1].why === "prevMismatch" && ps1.boundaries[0].ok === true, JSON.stringify(ps1.first));
  const shuffled = [ser[2], ser[0], ser[1]].map(f => ({ name: "x" + f.name, rows: f.lines.map((l, i) => A.normRow(l, i + 1)) }));
  ok("multi-file", "files given out of order are put back in order by first timestamp", A.orderFiles(shuffled).map(f => f.name).join() === "xaudit.1.jsonl,xaudit.2.jsonl,xaudit.3.jsonl", A.orderFiles(shuffled).map(f => f.name).join());
  const pr = A.pairSeals(ser.map(f => ({ name: "renamed-" + f.name, lines: f.lines })), ser.map((f, i) => ({ name: `seal-${i}.chain`, parsed: f.seal })).reverse());
  ok("multi-file", "seals with unrelated names pair with their logs by first hash", pr.unused.length === 0 && [...pr.pairs].every(([f, s]) => s.parsed.hashes[0] === A.chainStep(s.parsed.start, f.lines[0])), pr.pairs.size + " paired");
  const sealRound = A.parseSeal(A.sealText(ser[1].lines, ser[1].seal.start, "audit.2.jsonl"));
  ok("multi-file", "a written v2 seal round-trips its start line and file name", sealRound.start === ser[1].seal.start && sealRound.file === "audit.2.jsonl" && sealRound.hashes.join() === ser[1].seal.hashes.join(), sealRound.hashes.length + " hashes");

  // 3. calibration view
  const ct = A.calibTable(rows, "coi_current", [0.4, 0.6]);
  const binsOk = ct.segments.every(s => s.bins.reduce((a, b) => a + b.n, 0) === s.n && s.bins.every(b => b.meanP == null || (b.meanP >= b.lo && b.meanP <= b.hi)));
  ok("calibration", "coi_current splits at the calibration change; bins add up and each bin's mean sits inside it", ct.segments.length === 2 && binsOk, ct.segments.map(s => `${s.calv.slice(0, 8)}:${s.n}`).join(" "));
  ok("calibration", "deliberate rows are left out, raw P(yes) is read for every fast row", ct.deliberate > 0 && ct.segments.every(s => s.meanRaw != null), `${ct.deliberate} deliberate left out`);
  ok("calibration", "share answered Yes is 0 below 0.5 and 1 from 0.5", ct.segments.every(s => s.bins.every(b => b.shareYes == null || (b.hi <= 0.5 ? b.shareYes === 0 : b.lo >= 0.5 ? b.shareYes === 1 : true))), "ok");

  // 4. request-level view
  const cases = A.buildCases(rows);
  const distinct = new Set(rows.filter(r => r.success && r.rh).map(r => r.rh.replace(/-deliberate$/, ""))).size;
  const changed = cases.filter(c => c.conflicts.length);
  ok("cases", "one case per distinct request_hash (deliberate suffix set aside)", cases.length === distinct, `${cases.length} cases`);
  ok("cases", "the three re-asked sample cases show a changed answer; cache repeats do not", changed.length === 3 && cases.filter(c => c.reqs.length > 1 && c.cacheOnly).every(c => !c.conflicts.length), changed.map(c => c.conflicts.map(x => x.qid).join("+")).join(" | "));
  ok("cases", "requests inside a case are in time order with gaps measured", cases.every(c => c.reqs.every((q, i) => i === 0 || (q.gap != null && q.gap >= 0))), "ok");

  // 5. saved screens
  const fs = fakeStorage();
  const sv = A.saveSettings(fs, { bandLo: 0.3, bandHi: 0.7, runN: 5, runKey: "label", shiftAlpha: "0.01", tvdLine: 0.3 });
  const back = A.loadSettings(fs).settings;
  ok("saved screens", "settings round-trip through storage", sv.ok && back.bandLo === 0.3 && back.runN === 5 && back.runKey === "label" && back.shiftAlpha === "0.01", JSON.stringify(back));
  const rs = A.resetSettings(fs);
  ok("saved screens", "reset removes the key and returns the defaults", rs.ok && !fs._m.size && A.loadSettings(fs).settings.bandLo === 0.4, fs._m.size + " keys left");
  const q = A.saveSettings(fakeStorage("quota"), back), g = A.loadSettings(fakeStorage("throwGet"));
  ok("saved screens", "a full or blocked storage is reported, never thrown", !q.ok && q.error === "QuotaExceededError" && !g.ok && g.settings.bandLo === 0.4, `${q.error}; ${g.error}`);
  const cl = A.cleanSettings({ bandLo: 0.8, bandHi: 0.2, runN: NaN, shiftAlpha: "0.5", tvdLine: 7 });
  ok("saved screens", "bad stored values fall back to the defaults", cl.bandLo === 0.4 && cl.bandHi === 0.6 && cl.runN === 3 && cl.shiftAlpha === "0.05" && cl.tvdLine === 0.2, JSON.stringify(cl));

  // 6. redaction check
  const racc = A.newAcc();
  A.scanRow({ ts: "2026-10-01T00:00:00.000Z", request_hash: "a".repeat(64), handoff_reason: "mail jan.devries@example.nl or call +31 6 1234 5678",
    question_id: "Pieter Jansen", raw_distribution: { "NL91ABNA0417164300": 0.5, "GB82 WEST 1234 5698 7654 33": 0.5 } }, racc);
  ok("redaction", "finds an email, a phone, a checksum-valid IBAN in an option name, and a name-like question id", racc.red.email === 1 && racc.red.phone >= 1 && racc.red.iban === 1 && racc.red.name === 1, JSON.stringify(racc.red));
  ok("redaction", "an IBAN with a bad checksum is not counted as one", !A.ibanValid("GB82 WEST 1234 5698 7654 33") && A.ibanValid("GB82 WEST 1234 5698 7654 32"), "ok");
  const dump = JSON.stringify(racc);
  ok("redaction", "only counts are kept: no matched text in the result", !/@|Jansen|ABNA|1234/.test(dump), dump.length + " chars of counts");
  const sacc = A.newAcc(); window.SAMPLE_LINES.forEach((l, i) => A.normRow(l, i + 1, sacc));
  ok("redaction", "the sample has no matches (hashes and timestamps are skipped)", A.RED_KINDS.every(k2 => sacc.red[k2] === 0), JSON.stringify(sacc.red));

  // 7. export
  ok("export", "CSV cells: quotes, commas and newlines escaped; formula-looking text neutralised; numbers left alone",
    A.csvCell('a,"b"\nc') === '"a,""b""\nc"' && A.csvCell("=HYPERLINK(1)") === "'=HYPERLINK(1)" && A.csvCell(-0.5) === "-0.5" && A.csvCell("-0.25") === "-0.25", A.csvCell("=HYPERLINK(1)"));
  const keep = new Set(["ts", "question_id", "answer"]);
  const sl = A.sanitiseLine(L[0], keep), so = JSON.parse(sl);
  ok("export", "sanitised JSONL keeps only the ticked fields; unreadable lines give nothing", Object.keys(so).every(x => keep.has(x)) && Object.keys(so).length === 3 && A.sanitiseLine("{oops", keep) === null && A.sanitiseLine("[]", keep) === null, Object.keys(so).join(","));


  // second independent check: eight fixes
  const pacc = A.newAcc();
  const pr1 = A.normRow('{"ts": "2026-10-01T00:00:00.000Z", "constructor": "c", "toString": "t", "valueOf": 1, "hasOwnProperty": "h", "status": 200}', 1, pacc);
  ok("fix 1", "top-level fields named constructor, toString, valueOf and hasOwnProperty load and are counted", pr1.ok && pacc.fields.get("constructor") === 1 && pacc.fields.get("toString") === 1 && pacc.fields.get("valueOf") === 1, [...pacc.fields.keys()].join(","));
  const protoLine = '{"ts": "2026-10-01T00:00:00.000Z", "__proto__": {"email": "jan@example.nl", "polluted": true}, "status": 200}';
  const pr2 = A.normRow(protoLine, 2, pacc);
  ok("fix 2", "a __proto__ key stays a field: Object.prototype is untouched and the field is counted", pr2.ok && ({}).email === undefined && ({}).polluted === undefined && pacc.fields.get("__proto__") === 1 && pacc.redByField.get("__proto__").email === 1, `({}).email=${({}).email}`);
  const spP = A.sanitiseLine(protoLine, new Set(["__proto__", "ts"]));
  ok("fix 2", "sanitised JSONL keeps a ticked __proto__ field as an ordinary key", spP.includes('"__proto__":{"email"') && ({}).email === undefined, spP.slice(0, 60));
  const both = A.scanText("NL91ABNA0417164300 or call +31 6 1234 5678"), lone = A.scanText("pay NL91ABNA0417164300 today");
  ok("fix 3", "a phone number beside a valid IBAN still counts; the IBAN alone does not count as a phone", both.iban && both.phone && lone.iban && !lone.phone, JSON.stringify({ both, lone }));
  const L1 = ["x"], other = { name: "other.jsonl.chain", parsed: A.parseSeal(A.sealText(["y"], A.ZERO, "other.jsonl")) };
  const rf = A.pairSeals([{ name: "audit.jsonl", lines: L1 }], [other]);
  const byName = A.pairSeals([{ name: "audit.jsonl", lines: L1 }], [{ name: "other.jsonl.chain", parsed: A.parseSeal(A.ZERO.replace(/0/g, "a")) }]);
  const anon = A.pairSeals([{ name: "audit.jsonl", lines: L1 }], [{ name: "seal.txt", parsed: A.parseSeal(A.ZERO.replace(/0/g, "a")) }]);
  ok("fix 4", "the lone-pair fallback refuses a seal that names another file (by # file: or by its own name) and says so", rf.pairs.size === 0 && rf.refused.length === 1 && rf.refused[0].names === "other.jsonl" && byName.refused.length === 1 && anon.pairs.size === 1, `${rf.refused.length} + ${byName.refused.length} refused, anonymous paired ${anon.pairs.size}`);
  const up = A.parseSeal("# audit-row-reader chain v2\r\n# start: " + A.ZERO + "\r\n" + H.slice(0, 3).join("\r\n").toUpperCase() + "\r\n");
  const junk = A.parseSeal("garbage\r\nmore garbage\r\n"), emptyLog = A.parseSeal(A.sealText([], A.ZERO, "e.jsonl"));
  ok("fix 5", "upper-case hex with CRLF reads as the same seal; a seal with no hash lines is unreadable; an empty log's seal is not", up.hashes.join() === H.slice(0, 3).join() && !up.unreadable && junk.unreadable && junk.bad === 2 && !emptyLog.unreadable, `${up.hashes.length} hashes; junk unreadable ${junk.unreadable}`);
  const d = A.findDuplicates([{ name: "a", lines: L.slice(0, 50), fnv: L.slice(0, 50).reduce(A.fnvLine, 2166136261) }, { name: "b", lines: L.slice(0, 50), fnv: L.slice(0, 50).reduce(A.fnvLine, 2166136261) }, { name: "c", lines: L.slice(1, 51), fnv: L.slice(1, 51).reduce(A.fnvLine, 2166136261) }]);
  ok("fix 6", "the same content under two names is found as one duplicate, with its SHA-256", d.length === 1 && d[0].dup.name === "b" && d[0].of.name === "a" && d[0].sha === A.sha256hex(L.slice(0, 50).join("\n")), d.map(x => x.dup.name + "=" + x.of.name).join());
  // hostile input at the parser
  const h = [A.normRow('{"answer": {"type": "noul", "noul": NaN}}', 1), A.normRow('{"status": 200, "question_id": "q", "answer": {"type": "noul", "noul": 1e400}}', 2),
    A.normRow("[".repeat(20000) + "]".repeat(20000), 3), A.normRow("﻿" + L[0], 4), A.normRow("null", 5), A.normRow('{"status": 200, "question_id": "q", "answer": {"type": "noul", "noul": -0.3}}', 6)];
  ok("hostile input", "NaN unreadable; 1e400 and -0.3 out of range; deep nesting read or refused without a crash; BOM row parses; null refused",
    !h[0].ok && h[1].oor === Infinity && h[5].oor === -0.3 && typeof h[2].ok === "boolean" && h[3].ok && !h[4].ok, h.map(r => r.ok ? (r.oor != null ? "oor" : "ok") : r.parseError).join(" | "));

  // 8. seal guide
  const guide = $("secGuide");
  ok("seal guide", "the guide is on the page and quotes the security review", !!guide && /operator-controlled but not integrity-checked/.test(guide.textContent) && /tools\/seal\.py rotate/.test(guide.textContent), guide ? "present" : "missing");
  return res;
}

/* ---------- page-level checks (?selfcheck) ---------- */
async function pageChecks() {
  const P = window.ARR_APP, S = P.S, res = [], ok = (feature, name, pass, got) => res.push({ feature, check: name, pass: !!pass, got: String(got) });
  const protoLineP = '{"ts": "2026-10-01T00:00:00.000Z", "__proto__": {"email": "jan@example.nl"}, "status": 200}';
  const ctorLineP = '{"ts": "2026-10-01T00:00:01.000Z", "constructor": "c", "toString": "t", "status": 200}';
  const L = window.SAMPLE_LINES, H = window.SAMPLE_CHAIN;
  await P.loadAll([{ name: "sample-audit.jsonl", text: L.join("\n") + "\n" }], [{ name: "sample-audit.jsonl.chain", text: H.join("\n") + "\n" }], "sample");
  ok("page", "sample with its seal loads and verifies", /verified/.test($("verdict").textContent) && S.rows.length === L.length, $("verdict").textContent.slice(0, 60));
  ok("cases", "case view lists the three changed cases", /^3$/.test($("caseFigs").querySelectorAll(".fig-n")[3].textContent) && $("caseList").querySelectorAll("details.case").length === 3, $("caseFigs").textContent.replace(/\s+/g, " ").slice(0, 80));
  ok("calibration", "calibration view draws one table per calibration document", $("calTables").querySelectorAll("table.calib").length === 2 && /Before and after/.test($("calCompare").textContent), $("calTables").querySelectorAll("table.calib").length + " tables");
  ok("cases", "an answer changed in a case also appears under Look at these", S.flags.some(f => f.kind === "answer changed in a case"), S.flags.filter(f => f.kind === "answer changed in a case").length);

  // large: 10x through the File stream path, virtual table
  const big = []; for (let i = 0; i < L.length * 10; i++) big.push(L[i % L.length]);
  const file = new File([big.join("\n") + "\n"], "x10.jsonl", { type: "text/plain" });
  let t0 = performance.now();
  await P.loadAll([{ name: file.name, file }], [], "x10");
  const ms = performance.now() - t0;
  const drawn = $("tbody").querySelectorAll("tr[data-n]").length;
  ok("large logs", `10x sample (${big.length} rows) read through the streaming file path`, S.rows.length === big.length, `${Math.round(ms)} ms (read ${Math.round(S.timing.read)}, draw ${Math.round(S.timing.render)})`);
  ok("large logs", "virtual table draws only the rows in view", drawn > 0 && drawn < 120, `${drawn} of ${big.length} rows in the DOM`);
  P.jumpTo(4000);
  ok("large logs", "jumping to row 4000 draws it and opens its raw JSON", !!$("tbody").querySelector('button[data-open="4000"]') && /^row 4000/.test($("raw").textContent), $("tbody").querySelectorAll("tr[data-n]").length + " rows drawn");
  const stopJob = P.loadAll([{ name: "x10b", file }], [], "x10b"); document.getElementById("btnStop").click();
  const stopped = await stopJob;
  ok("large logs", "Stop cancels a load and keeps the last finished log", stopped === false && S.label === "x10", `kept ${S.label}`);

  // multi-file via the page
  const ser = P.sampleSeries();
  await P.loadAll(ser.logs.slice().reverse(), ser.seals, "series");
  ok("multi-file", "three rotated files load in order and every boundary holds", S.files.map(f => f.name).join() === "audit.1.jsonl,audit.2.jsonl,audit.3.jsonl" && $("bounds").querySelectorAll(".stamp.ok").length === 2 && /verified/.test($("verdict").textContent), S.files.map(f => f.name).join());
  await P.loadAll([ser.logs[0], ser.logs[2]], [ser.seals[0], ser.seals[2]], "series, file 2 missing");
  const brk = S.flags.find(f => f.kind === "chain break");
  ok("multi-file", "file 2 missing: the page breaks at row 2:1 and names the boundary", /broken/.test($("verdict").textContent) && brk && P.rowLabel(S.rows[brk.n - 1]) === "2:1" && $("bounds").querySelectorAll(".stamp.break").length === 1, brk ? P.rowLabel(S.rows[brk.n - 1]) + " · " + $("verdict").textContent.slice(0, 70) : "no flag");
  const ed = ser.logs.map(x => Object.assign({}, x)); const l3 = ed[2].text.split("\n"); l3[4] = l3[4].replace("2026-10", "2026-11"); ed[2].text = l3.join("\n");
  await P.loadAll(ed, ser.seals, "series, file 3 row 5 edited");
  ok("multi-file", "row 5 of file 3 edited: break at 3:5, both boundaries still hold", S.integ.first && S.integ.first.file === 2 && S.integ.first.row === 5 && $("bounds").querySelectorAll(".stamp.ok").length === 2, JSON.stringify(S.integ.first));

  // hostile text in every field
  const X = '<script>window.__pwned=1<\/script><img src=x onerror="window.__pwned=2">';
  const hostile = [JSON.stringify({ ts: "2026-10-01T00:00:00.000Z", request_id: X, status: 200, mode: X, question_id: X, model: X, backend: X, request_hash: X, calibration_version: X,
      raw_distribution: { [X]: 0.6, B: 0.4 }, answer: { type: "choice", choice: X, probabilities: { [X]: 0.6, "B<b>": 0.4 } }, low_confidence: true, handoff_reason: X }),
    JSON.stringify({ ts: "2026-10-01T00:00:01.000Z", request_id: X, status: 500, error: X, mode: null, request_hash: null, n_questions: null }), "not json " + X];
  const imgs0 = document.querySelectorAll("img").length, scripts0 = document.querySelectorAll("script").length;
  await P.loadAll([{ name: X, text: hostile.join("\n") }], [], X);
  P.jumpTo(1); P.setView(true);
  await new Promise(r => setTimeout(r, 50));
  ok("hostile input", "script and img payloads in every text field render as text", window.__pwned === undefined && document.querySelectorAll("img").length === imgs0 && document.querySelectorAll("script").length === scripts0 && $("tbody").textContent.includes("<script>"), `pwned=${window.__pwned}, img=${document.querySelectorAll("img").length}`);

  // empty
  await P.loadAll([{ name: "empty.jsonl", text: "" }], [], "empty.jsonl");
  ok("hostile input", "an empty log says it is empty and hides the other sections", /empty/i.test($("verdict").textContent) && $("secTrail").classList.contains("hidden") && $("secCharts").classList.contains("hidden"), $("verdict").textContent.slice(0, 50));

  // saved screens through the page controls
  const st = P.store();
  $("bandLo").value = "0.31"; $("bandLo").dispatchEvent(new Event("change"));
  let stored = null; try { stored = st && JSON.parse(st.getItem(window.ARR.SETTINGS_KEY)); } catch (e) { stored = null; }
  $("btnReset").click();
  let after = "x"; try { after = st && st.getItem(window.ARR.SETTINGS_KEY); } catch (e) { after = "x"; }
  ok("saved screens", "changing the band saves it; reset clears storage and the inputs", (!st || (stored && stored.bandLo === 0.31 && after === null)) && $("bandLo").value === "0.4", st ? `stored ${stored && stored.bandLo}, after reset ${after}` : "no storage in this context");

  // export guard
  const pii = L.slice(0, 20).concat([L[20].replace('"status": 200', '"handoff_reason": "call +31 6 1234 5678", "status": 200')]);
  await P.loadAll([{ name: "pii.jsonl", text: pii.join("\n") }], [], "pii");
  let ran = 0;
  P.guarded(() => ran++, null, "CSV");
  const shown = !$("warn").classList.contains("hidden");
  P.closeWarn(false);
  ok("export", "a phone number in the log stops the CSV export behind a warning with counts; Cancel exports nothing", shown && ran === 0 && /1 phone number/.test($("warnText").textContent) && !/1234/.test($("warnText").textContent), $("warnText").textContent.slice(0, 80));
  ok("export", "the field with the match starts unticked in the JSONL picker", !S.keep.has("handoff_reason") && S.keep.has("ts"), [...S.keep].length + " fields ticked");
  const sj = P.sanitisedJsonl();
  ok("export", "sanitised JSONL holds every readable row and only ticked fields", sj.rows === pii.length && sj.text.trim().split("\n").every(l => Object.keys(JSON.parse(l)).every(k => S.keep.has(k))), `${sj.rows} rows`);
  await P.loadAll([{ name: "clean.jsonl", text: L.slice(0, 20).join("\n") }], [], "clean");
  P.guarded(() => ran++, null, "CSV");
  ok("export", "a clean log exports without the warning", ran === 1 && $("warn").classList.contains("hidden"), `ran ${ran}`);
  const csv = P.flagsCsv();
  ok("export", "flagged CSV has a header and one line per flag", csv.split("\r\n").filter(Boolean).length === S.flags.length + 1, `${S.flags.length} flags`);

  // review fixes
  const first = P.loadAll([{ name: "a.jsonl", file: new File([big.join("\n")], "a.jsonl") }], [], "load A");
  const second = P.loadAll([{ name: "b.jsonl", text: L.slice(0, 40).join("\n") }], [], "load B");
  const [ra, rb] = await Promise.all([first, second]);
  ok("review", "two loads started back to back: the first stops, the page holds the second whole", ra === false && rb === true && S.label === "load B" && S.rows.length === 40 && S.lines.length === 40, `${S.label}, ${S.rows.length} rows`);
  await P.loadAll([{ name: "pii.jsonl", text: pii.join("\n") }], [], "pii again");
  P.guarded(() => {}, null, "CSV");
  const warnWasOpen = !$("warn").classList.contains("hidden");
  const odd = [
    '{"ts": "2026-10-01T00:00:00.000Z", "request_id": "' + "1".repeat(32) + '", "status": 200, "mode": "fast", "question_id": "q", "request_hash": "' + "a".repeat(64) + '", "answer": {"type": "noul", "noul": 1.7}}',
    '{"ts": "2026-10-01T00:00:01.000Z", "request_id": "' + "1".repeat(32) + '", "status": 200, "mode": "fast", "question_id": "q", "request_hash": "' + "a".repeat(64) + '", "answer": {"type": "noul", "noul": null}}',
    '{"ts": "2026-10-01T00:00:02.000Z", "request_id": "' + "2".repeat(32) + '", "status": 200, "mode": "fast", "question_id": "q", "request_hash": "' + "b".repeat(64) + '", "answer": {"type": "noul", "noul": null}}',
    '{"ts": "2026-10-01T00:00:03.000Z", "request_id": "' + "3".repeat(32) + '", "status": 200, "mode": "fast", "question_id": "q", "request_hash": "' + "c".repeat(64) + '", "answer": {"type": "noul", "noul": null}}\rtrailing'];
  await P.loadAll([{ name: "odd.jsonl", text: odd.join("\n") + "\n" }], [], "odd");
  const kinds = S.flags.map(f => f.kind);
  ok("review", "a new load closes an open export warning", warnWasOpen && $("warn").classList.contains("hidden"), `open before: ${warnWasOpen}`);
  ok("review", "out-of-range probability and a request id reused at two times are flagged", kinds.includes("value out of range") && kinds.includes("repeated request id"), [...new Set(kinds)].join(", "));
  ok("review", "rows with no reading never form an identical run", !kinds.includes("identical run"), kinds.filter(k => k === "identical run").length + " runs");
  ok("review", "a bare carriage return is reported under the hash chain", /bare carriage return/.test($("lineNote").textContent), $("lineNote").textContent.slice(0, 50));
  await P.loadAll([{ name: "sample-audit.jsonl", text: L.join("\n") + "\n" }], [], "sample, no seal");
  ok("review", "in-band calibration bins carry a text tag, so the shading is never the only signal", $("calTables").querySelectorAll("tr.inband .bandtag").length === $("calTables").querySelectorAll("tr.inband").length && $("calTables").querySelectorAll("tr.inband").length > 0, $("calTables").querySelectorAll(".bandtag").length + " tags");
  const btn = $("tbody").querySelector("button[data-open]"); btn.focus(); btn.click();
  ok("review", "opening a row keeps keyboard focus on its button after the table redraws", document.activeElement && document.activeElement.dataset.open === btn.dataset.open, document.activeElement && document.activeElement.tagName);


  // second independent check: page side
  await P.loadAll([{ name: "proto.jsonl", text: L.slice(0, 5).concat([protoLineP, ctorLineP]).join("\n") }], [], "proto");
  ok("fix 2", "after loading a __proto__ row, ({}).email is undefined and __proto__ is in the export field picker", ({}).email === undefined && !!$("fieldPick").querySelector('input[data-field="__proto__"]') && !!$("fieldPick").querySelector('input[data-field="constructor"]'), `picker has ${$("fieldPick").querySelectorAll("input").length} fields`);
  await P.loadAll([{ name: "sample-audit.jsonl", text: L.join("\n") + "\n" }], [{ name: "sample-audit.jsonl.chain", text: "NOT A SEAL\r\nstill not\r\n" }], "unreadable seal");
  ok("fix 5", "an unreadable seal gives no verdict and says the seal could not be read", /seal unreadable/i.test($("verdict").textContent) && /could not be read/.test($("verdict").textContent) && !/verified|broken/i.test($("verdict").querySelector(".stamp").textContent), $("verdict").textContent.slice(0, 70));
  const edited1 = L.slice(); edited1[0] = edited1[0].replace("2026-09-21", "2026-09-20");
  await P.loadAll([{ name: "audit.jsonl", text: edited1.join("\n") }], [{ name: "x.chain", text: A.sealText(L.slice(0, 3), A.ZERO, "other.jsonl") }], "refused seal");
  ok("fix 4", "a lone seal naming another file is not applied and the page says so", /seal not applied/.test($("verdict").textContent) && /other\.jsonl/.test($("verdict").textContent) && S.method !== "seal", $("verdict").textContent.slice(0, 80));
  await P.loadAll([{ name: "one.jsonl", text: L.join("\n") + "\n" }, { name: "copy-of-one.jsonl", text: L.join("\n") + "\n" }], [], "twice");
  ok("fix 6", "the same file loaded twice is read once and reported as a duplicate by content hash", S.files.length === 1 && S.rows.length === L.length && /same content as one\.jsonl \(SHA-256 [0-9a-f]{16}/.test($("lineNote").textContent), $("lineNote").textContent.slice(0, 90));
  await P.loadAll([{ name: "sample-audit.jsonl", text: L.join("\n") + "\n" }], [{ name: "sample-audit.jsonl.chain", text: P.sampleSealText() }], "sample");
  const inside = host => { const svg = host.querySelector("svg"); if (!svg) return false; const W = +svg.getAttribute("width"); const bad = [...svg.querySelectorAll("text, circle")].filter(el => !el.closest(".xh")).filter(el => { const b = el.getBBox(); return !(b.x >= -0.5 && b.x + b.width <= W + 0.5); }); inside.bad = bad.map(el => `${el.tagName}:${(el.textContent || "").slice(0, 20)}@${Math.round(el.getBBox().x)}+${Math.round(el.getBBox().width)}/${W}`); return !bad.length; };
  const wideOk = inside($("chDrift")), wideBad = inside.bad;
  const dh = $("chDrift"); dh.style.width = "358px"; window.dispatchEvent(new Event("resize")); await new Promise(r => setTimeout(r, 250));
  const narrowOk = inside(dh); dh.style.width = ""; window.dispatchEvent(new Event("resize")); await new Promise(r => setTimeout(r, 250));
  ok("fix 7", "drift-chart labels and end marks stay inside the plot at full width and at a 390 px phone's 358 px", wideOk && narrowOk, `wide ${wideOk} ${wideBad.join(" ")}; narrow ${narrowOk} ${(inside.bad || []).join(" ")}`);
  const th4 = $("trail").querySelector("th:nth-child(4)"), hint = document.querySelector(".scrollhint");
  ok("fix 7", "the trail's Answer column keeps a minimum width and the scroll cue is visible", th4.getBoundingClientRect().width >= 150 && hint.offsetParent !== null, `${Math.round(th4.getBoundingClientRect().width)} px`);
  ok("fix 8", "the sample seal carries # start: and # file: lines and pairs with its log by name", /# start: 0{64}/.test(P.sampleSealText()) && S.files[0].sealName === "sample-audit.jsonl.chain" && /verified/.test($("verdict").textContent), S.files[0].sealName);
  // put the sample back
  await P.loadAll([{ name: "sample-audit.jsonl (sample)", text: L.join("\n") + "\n" }], [{ name: "sample-audit.jsonl.chain", text: H.join("\n") + "\n" }], "sample-audit.jsonl (sample)");
  return res;
}

async function bench(N) {
  const P = window.ARR_APP, L = window.SAMPLE_LINES, parts = [];
  for (let i = 0; i < N; i++) parts.push(L[i % L.length]);
  const text = parts.join("\n") + "\n", file = new File([text], `bench-${N}.jsonl`);
  const chainText = window.ARR.CHAIN_HEADER + "\n# start: " + window.ARR.ZERO + "\n";
  const t0 = performance.now();
  const ok = await P.loadAll([{ name: file.name, file }], /[?&]benchseal\b/.test(location.search) ? [{ name: file.name + ".chain", text: chainText }] : [], file.name);
  const t = P.S.timing || {};
  return { rows: P.S.rows.length, ok, total: Math.round(performance.now() - t0), read: Math.round(t.read || 0), hash: Math.round(t.hash || 0), render: Math.round(t.render || 0), mb: +(text.length / 1048576).toFixed(1) };
}

async function run() {
  let res = coreChecks();
  const full = /[?&]selfcheck\b/.test(location.search);
  if (full) { try { res = res.concat(await pageChecks()); } catch (e) { console.error(e); res.push({ feature: "page", check: "page checks ran to the end", pass: false, got: String(e && e.stack || e) }); } }
  const m = /[?&]bench=(\d+)/.exec(location.search);
  if (m) { const b = await bench(+m[1]); document.body.dataset.bench = JSON.stringify(b); res.push({ feature: "large logs", check: `bench: ${b.rows} rows, ${b.mb} MB`, pass: b.rows === +m[1], got: `total ${b.total} ms · read ${b.read} · hash ${b.hash} · draw ${b.render}` }); }
  const pass = res.every(r => r.pass), np = res.filter(r => r.pass).length;
  console.log(`Audit Row Reader self-check: ${np} of ${res.length} pass`);
  console.table(res);
  document.body.dataset.selfcheck = pass ? "pass" : "fail";
  document.body.dataset.selfcheckCount = `${np}/${res.length}`;
  if (!pass) document.body.dataset.selfcheckFail = res.filter(r => !r.pass).map(r => r.check + " => " + r.got).join(" || ");
  $("selfcheckLine").textContent = `self-check, run when this page opened: ${np} of ${res.length} pass${full ? " (core and page checks)" : " (core checks; add ?selfcheck for the page checks)"}` + (pass ? "" : ` · failing: ${res.filter(r => !r.pass).map(r => r.check).join("; ")}`);
  return res;
}
window.ARR_SELFCHECK = { run, coreChecks, pageChecks, bench };
document.addEventListener("DOMContentLoaded", () => { setTimeout(() => { run().catch(e => { console.error(e); document.body.dataset.selfcheck = "fail"; }); }, 0); });
})();
