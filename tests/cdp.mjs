// Drive headless Chrome over the DevTools protocol (local pipe on 127.0.0.1 only) and wait for
// the page's self-check. Real time, no virtual clock, so performance.now timings are honest.
// Usage: node tests/cdp.mjs <url> [timeoutSeconds]
// Prints one JSON line: {selfcheck, count, fail, bench, consoleErrors}. Exit 0 only on pass.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const url = process.argv[2];
const limit = (+process.argv[3] || 120) * 1000;
if (!url) { console.error("usage: node tests/cdp.mjs <url> [timeoutSeconds]"); process.exit(2); }

const profile = mkdtempSync(join(tmpdir(), "arr-cdp-"));
const port = 9300 + Math.floor(Math.random() * 500);
const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", `--remote-debugging-port=${port}`, "--remote-debugging-address=127.0.0.1",
  `--user-data-dir=${profile}`, "--no-first-run", "--window-size=1280,900", "about:blank"], { stdio: "ignore" });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const done = code => { try { chrome.kill(); } catch (e) { /* already gone */ } setTimeout(() => { try { rmSync(profile, { recursive: true, force: true }); } catch (e) { /* profile busy */ } process.exit(code); }, 300); };

let target = null;
for (let i = 0; i < 100 && !target; i++) {
  try { const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); target = list.find(t => t.type === "page"); } catch (e) { await sleep(100); }
}
if (!target) { console.log(JSON.stringify({ selfcheck: "no-browser" })); done(2); }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let id = 0; const pending = new Map(), consoleErrors = [];
ws.onmessage = ev => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  if (m.method === "Runtime.exceptionThrown") consoleErrors.push(m.params.exceptionDetails.exception ? m.params.exceptionDetails.exception.description : m.params.exceptionDetails.text);
  if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") consoleErrors.push(m.params.args.map(a => a.value || a.description).join(" "));
  if (m.method === "Log.entryAdded" && m.params.entry.level === "error" && !/favicon|fonts\.g/.test(m.params.entry.url || "")) consoleErrors.push(m.params.entry.text);
};
const send = (method, params = {}) => new Promise(res => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
await send("Runtime.enable"); await send("Log.enable"); await send("Page.enable");
await send("Page.navigate", { url });
const t0 = Date.now();
let out = null;
while (Date.now() - t0 < limit) {
  await sleep(250);
  const r = await send("Runtime.evaluate", { expression: "JSON.stringify({s: document.body && document.body.dataset.selfcheck, c: document.body && document.body.dataset.selfcheckCount, f: document.body && document.body.dataset.selfcheckFail, b: document.body && document.body.dataset.bench})", returnByValue: true });
  const v = r.result && r.result.result && r.result.result.value ? JSON.parse(r.result.result.value) : {};
  if (v.s) { out = { selfcheck: v.s, count: v.c, fail: v.f || null, bench: v.b ? JSON.parse(v.b) : null, consoleErrors, seconds: (Date.now() - t0) / 1000 }; break; }
}
if (!out) out = { selfcheck: "timeout", consoleErrors };
console.log(JSON.stringify(out));
done(out.selfcheck === "pass" && !consoleErrors.length ? 0 : 1);
