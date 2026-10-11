#!/usr/bin/env python3
"""Generate a SAMPLE decision-head audit log in the documented row format.

Nothing here comes from a deployed system. The row shapes follow
tools/decision-head/docs/audit-log.md and docs/http-api.md; the questions are
examples/supplier_onboarding_questions.json; the abstain band 0.4 to 0.6 is the
commented example in decisionhead.example.toml. Every probability is drawn
from a seeded random generator with a story built in so the reader has
something to find:

* a calibration document change on 2026-09-28 (new calibration_version);
* coi_current drifts towards the abstain band in the second half;
* next_step shifts from APPROVE towards REQUEST_DOCS in the second half;
* one stretch where the backend repeats the exact same next_step reading;
* a few cache hits, two degraded readings, five refused requests,
  some deliberate-mode requests.

Writes sample/sample-audit.jsonl, its sidecar chain, sample.js (the copy the
page embeds), and sample/series/ (the same rows as three rotated files with
linked seals) plus sample/series-missing-2/ (the middle file removed).
"""
import datetime as dt
import hashlib
import json
import math
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import seal  # noqa: E402

RNG = random.Random(20260928)
MODEL = "sample-model"
BAND = (0.4, 0.6)
QUESTIONS = {
    "coi_current": {"type": "noul", "instructions": "The certificate of insurance on file is dated within the last 12 months and lists coverage limits meeting the standard supplier requirement."},
    "w9_on_file": {"type": "noul", "instructions": "A signed W-9 (or local equivalent tax form) is present in the file."},
    "next_step": {"type": "choice", "instructions": "Given everything in the state, what should happen to this supplier onboarding case next?",
                  "criteria": ["APPROVE", "REQUEST_DOCS", "ESCALATE"]},
    "risk_level": {"type": "score", "instructions": "Rate the overall onboarding risk of this supplier given everything in the state.",
                   "levels": ["low", "medium", "high"]},
}
CAL_A = {"noul": {"T": 1.35}, "choice": {"T": 1.18}, "score": {"T": 1.22}}
CAL_B = {"noul": {"T": 1.9}, "choice": {"T": 1.05}, "score": {"T": 1.3}}


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))


def clamp(p):
    return min(max(p, 1e-9), 1 - 1e-9)


def temper(p, T):
    p = clamp(p)
    return sigmoid(math.log(p / (1 - p)) / T)


def softmax(xs):
    m = max(xs)
    e = [math.exp(x - m) for x in xs]
    s = sum(e)
    return [v / s for v in e]


def fast_row(qid, q, phase, cal, rh, stuck=None):
    t = q["type"]
    lat = round(RNG.uniform(0.18, 0.9), 6)
    unparsed = round(max(0.0, RNG.gauss(0.01, 0.015)), 6)
    row = {"request_hash": rh, "question_id": qid, "model": MODEL, "backend": "FakeBackend",
           "calibrated": True, "latency_s": lat, "cache_hit": False, "unparsed_mass": unparsed,
           "no_family_match": False, "non_finite_logprob_count": 0, "degraded": False}
    T = cal[t]["T"]
    if t == "noul":
        mu, sd = {"coi_current": (1.5 if phase == 0 else 0.35, 1.0), "w9_on_file": (2.4, 0.8)}[qid]
        p = sigmoid(RNG.gauss(mu, sd))
        row["raw_distribution"] = {"Yes": p, "No": 1 - p}
        pc = temper(p, T)
        ans = {"type": "noul", "noul": pc}
    else:
        opts = q.get("criteria") or q.get("levels")
        if stuck is not None:
            raw = stuck
        else:
            base = {"next_step": ([1.2, 0.3, -0.8] if phase == 0 else [0.25, 1.15, -0.6]),
                    "risk_level": [0.8, 0.4, -0.5]}[qid]
            raw = softmax([b + RNG.gauss(0, 0.9) for b in base])
        row["raw_distribution"] = dict(zip(opts, raw))
        row["letters"] = dict(zip(opts, "ABC"))
        tem = [temper(p, T) for p in raw]
        s = sum(tem)
        probs = [v / s for v in tem]
        order = sorted(range(len(opts)), key=lambda i: -probs[i])
        ans = {"type": t}
        if t == "choice":
            ans["choice"] = opts[order[0]]
        else:
            ans["score"] = float(order[0] + 1)
        ans["probabilities"] = dict(zip(opts, probs))
        ans["confidence"] = probs[order[0]] - probs[order[1]]
    ans.update({"unparsed_mass": unparsed, "no_family_match": False, "non_finite_logprob_count": 0, "degraded": False})
    return row, ans


def degraded_row(qid, rh):
    row = {"request_hash": rh, "question_id": qid, "model": MODEL, "backend": "FakeBackend",
           "calibrated": True, "latency_s": round(RNG.uniform(0.2, 0.6), 6), "cache_hit": False,
           "unparsed_mass": 0.93, "no_family_match": True, "non_finite_logprob_count": 0, "degraded": True,
           "raw_distribution": {"Yes": 0.5, "No": 0.5}}
    ans = {"type": "noul", "noul": None, "unparsed_mass": 0.93, "no_family_match": True,
           "non_finite_logprob_count": 0, "degraded": True}
    return row, ans


def deliberate_row(qid, q, phase, rh):
    t = q["type"]
    k = 8
    row = {"request_hash": rh + "-deliberate", "question_id": qid, "model": MODEL, "backend": "FakeBackend",
           "k": k, "temperature": 0.7, "max_tokens": 512}
    missing = 1 if RNG.random() < 0.08 else 0
    n = k - missing
    malformed = 1 if RNG.random() < 0.15 else 0
    parsed = n - malformed
    if t == "noul":
        p = sigmoid(RNG.gauss(1.5 if (qid == "w9_on_file" or phase == 0) else 0.35, 1.0))
        yes = sum(RNG.random() < p for _ in range(parsed))
        votes = {"yes": yes, "no": parsed - yes}
        share = yes / parsed if parsed else None
        result = share
        ans = {"type": "noul", "noul": share, "vote_share": share}
    else:
        opts = q.get("criteria") or q.get("levels")
        base = {"next_step": ([1.2, 0.3, -0.8] if phase == 0 else [0.25, 1.15, -0.6]), "risk_level": [0.8, 0.4, -0.5]}[qid]
        pr = softmax(base)
        votes = {o: 0 for o in opts}
        for _ in range(parsed):
            r, acc = RNG.random(), 0.0
            for o, pv in zip(opts, pr):
                acc += pv
                if r <= acc:
                    votes[o] += 1
                    break
            else:
                votes[opts[-1]] += 1
        probs = {o: votes[o] / parsed for o in opts}
        top = sorted(opts, key=lambda o: -probs[o])
        result = top[0]
        ans = {"type": t}
        if t == "choice":
            ans["choice"] = top[0]
        else:
            ans["score"] = float(opts.index(top[0]) + 1)
        ans["probabilities"] = probs
        ans["confidence"] = probs[top[0]] - probs[top[1]]
        ans["vote_share"] = probs
    ans.update({"avg_stated_confidence": round(RNG.uniform(0.6, 0.9), 3), "n_samples": n, "n_parsed": parsed,
                "n_malformed": malformed, "n_excess_samples": 0, "n_missing_samples": missing, "degraded": False})
    row.update({"n_samples": n, "n_parsed": parsed, "n_malformed": malformed, "n_unmatched_answer": 0,
                "n_excess_samples": 0, "votes": votes, "result": result, "degraded": False,
                "sampling_requests": 1, "n_param_used": True, "fallback_used": False,
                "latency_s": round(RNG.uniform(2.5, 7.5), 6)})
    return row, ans


def flag(row, ans, reason):
    for d in (ans, row):
        d["low_confidence"] = True
        d["recommended_action"] = "handoff"
        d["handoff_reason"] = reason


def apply_band(row, ans):
    if ans.get("degraded"):
        flag(row, ans, "no usable reading from the model (degraded answer)")
        return
    m = ans.get("n_missing_samples")
    if isinstance(m, int) and m > 0:
        flag(row, ans, "the backend returned %d fewer sample(s) than requested" % m)
        return
    if ans["type"] == "noul" and ans["noul"] is not None and BAND[0] <= ans["noul"] <= BAND[1]:
        flag(row, ans, "noul probability %.4f falls within the abstain band [%s, %s]" % (ans["noul"], BAND[0], BAND[1]))


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


def write_series(lines):
    """Split the sample at day boundaries into three rotated files with linked seals,
    the layout `seal.py rotate` produces, plus a copy with the middle file missing."""
    cuts = []
    for i, ln in enumerate(lines):
        day = json.loads(ln)["ts"][:10]
        if day >= "2026-09-26" and not cuts:
            cuts.append(i)
        if day >= "2026-10-01" and len(cuts) == 1:
            cuts.append(i)
    parts = [lines[:cuts[0]], lines[cuts[0]:cuts[1]], lines[cuts[1]:]]
    for sub, keep in (("series", (0, 1, 2)), ("series-missing-2", (0, 2))):
        d = os.path.join(ROOT, "sample", sub)
        os.makedirs(d, exist_ok=True)
        for name in os.listdir(d):
            os.remove(os.path.join(d, name))
        start = seal.ZERO
        for k, part in enumerate(parts):
            path = os.path.join(d, "audit.%d.jsonl" % (k + 1))
            if k in keep:
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write("\n".join(part) + "\n")
                seal.write_seal(path, part, start)
            start = seal.chain(part, start)[-1]
    print("series split at rows", [c + 1 for c in cuts], "sizes", [len(p) for p in parts])


def main():
    start = dt.datetime(2026, 9, 21, tzinfo=dt.timezone.utc)
    switch = dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc)
    times = []
    for d in range(14):
        day = start + dt.timedelta(days=d)
        for _ in range(RNG.randint(7, 11)):
            times.append(day + dt.timedelta(hours=13, seconds=RNG.uniform(0, 9 * 3600)))
    times.sort()
    n_req = len(times)
    errors = {7: (429, "too_many_requests"), 31: (415, "unsupported_media_type"), 58: (504, "request_timeout"),
              88: (429, "too_many_requests"), 109: (502, "backend_error")}
    degraded_at = {44: "coi_current", 97: "coi_current"}
    stuck_reqs = set(range(92, 97))
    stuck_raw = [0.21418, 0.69137, 0.09445]
    cache_src = {}
    cache_reqs = {40: 12, 41: 12, 75: 70, 118: 115}
    # re-asked cases: the same state sent again after the calibration change, so the
    # request-level view has cases answered more than once (not cache hits)
    reask = {100: 20, 104: 33, 113: 61}
    states = {}
    rows = []
    for i, t in enumerate(times):
        ts = iso(t)
        rid = "%032x" % RNG.getrandbits(128)
        if i in errors:
            st, code = errors[i]
            mode = None if st == 415 else "fast"
            rhv = None if st == 415 else digest({"state": "case-%03d" % i, "questions": QUESTIONS})
            nq = None if st == 415 else 4
            rows.append({"ts": ts, "request_id": rid, "status": st, "error": code, "mode": mode,
                         "request_hash": rhv, "n_questions": nq})
            continue
        phase = 0 if t < switch else 1
        cal = CAL_A if phase == 0 else CAL_B
        cver = digest(cal)
        state = "Supplier case #%03d. Documents received: %d." % (i, RNG.randint(1, 6))
        if i in reask:
            state = states[reask[i]]
        states[i] = state
        if i in cache_reqs:
            src = cache_src[cache_reqs[i]]
            for r in src["rows"]:
                r2 = json.loads(json.dumps(r))
                r2.update({"cache_hit": True, "original_trace_id": src["rid"], "ts": ts, "request_id": rid})
                rows.append(r2)
            continue
        rh = digest({"state": state, "questions": QUESTIONS, "model": MODEL})
        deliberate = RNG.random() < 0.1 and i not in stuck_reqs and i not in degraded_at and i not in cache_reqs.values()
        out = []
        for qid, q in QUESTIONS.items():
            if deliberate:
                row, ans = deliberate_row(qid, q, phase, rh)
                head = {"ts": ts, "request_id": rid, "status": 200, "mode": "deliberate"}
            else:
                if degraded_at.get(i) == qid:
                    row, ans = degraded_row(qid, rh)
                else:
                    stuck = stuck_raw if (i in stuck_reqs and qid == "next_step") else None
                    row, ans = fast_row(qid, q, phase, cal, rh, stuck)
                head = {"ts": ts, "request_id": rid, "status": 200, "mode": "fast", "calibration_version": cver}
            row.update(head)
            row["answer"] = ans
            apply_band(row, ans)
            if "low_confidence" in row:  # keep the flag fields after answer, as the server adds them
                for key in ("low_confidence", "recommended_action", "handoff_reason"):
                    row[key] = row.pop(key)
            out.append(row)
        cache_src[i] = {"rid": rid, "rows": [r for r in out if r.get("mode") == "fast"]}
        rows.extend(out)
    lines = [json.dumps(r, allow_nan=False) for r in rows]
    os.makedirs(os.path.join(ROOT, "sample"), exist_ok=True)
    log = os.path.join(ROOT, "sample", "sample-audit.jsonl")
    with open(log, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    hashes = seal.chain(lines)
    bad = list(lines)
    bad[136] = bad[136].replace('"ts": "2026', '"ts": "2027', 1)
    with open(os.path.join(ROOT, "sample", "sample-audit-corrupted-row137.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(bad) + "\n")
    seal.write_seal(log, lines)  # v2 seal: header, "# start:" and "# file:" lines
    sample_js = os.path.join(ROOT, "sample.js")
    with open(sample_js, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("/* generated by tools/make_sample.py; a generated sample log; no deployed system wrote it */\n"
                 "\"use strict\";\n"
                 "var SAMPLE_LINES = " + json.dumps(lines, indent=0) + ";\n"
                 "var SAMPLE_CHAIN = " + json.dumps(hashes, indent=0) + ";\n")
    print("wrote", sample_js)
    write_series(lines)
    print("%d requests, %d rows -> %s" % (n_req, len(lines), log))


if __name__ == "__main__":
    main()
