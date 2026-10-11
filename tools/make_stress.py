#!/usr/bin/env python3
"""Write hostile and oversized inputs for the Audit Row Reader stress round.

    python3 tools/make_stress.py [outdir]

Small fixtures land in tests/fixtures/ (kept with the build). The large ones
(10x, 100x, 100k rows, a 5 MB paste) go to outdir, default tests/fixtures/big/,
because they run to tens of megabytes. Every row is synthetic: either a copy of
the generated sample with its request id renumbered, or a row built here to
break something.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "tests", "fixtures")
XSS = ['<script>window.__pwned=1</script>', '<img src=x onerror="window.__pwned=2">']


def sample_lines():
    with open(os.path.join(ROOT, "sample", "sample-audit.jsonl"), encoding="utf-8") as fh:
        return [ln for ln in fh.read().split("\n") if ln]


def renumbered(n):
    base = sample_lines()
    out = []
    for i in range(n):
        r = json.loads(base[i % len(base)])
        r["request_id"] = "%032x" % (i + 1)
        out.append(json.dumps(r))
    return out


def hostile():
    p = XSS[0] + XSS[1]
    rows = []
    # every text field carries both payloads, including option names (object keys)
    rows.append({"ts": "2026-03-08T07:59:59.999Z", "request_id": p, "status": 200, "mode": p, "question_id": p,
                 "model": p, "backend": p, "request_hash": p, "latency_s": 0.1, "calibration_version": p,
                 "raw_distribution": {p: 0.6, "B": 0.4}, "letters": {p: "A", "B": "B"},
                 "answer": {"type": "choice", "choice": p, "probabilities": {p: 0.6, "B<b>": 0.4}},
                 "low_confidence": True, "handoff_reason": p, "recommended_action": p})
    rows.append({"ts": "2026-03-08T08:00:00.000Z", "request_id": "a" * 32, "status": 500, "error": p, "mode": None,
                 "request_hash": None, "n_questions": None})
    # unicode, RTL, emoji-free astral chars, combining marks, zero-width
    rows.append({"ts": "2026-11-01T06:30:00.000Z", "request_id": "b" * 32, "status": 200, "mode": "fast",
                 "question_id": "שאלה_नमस्ते_é́_​_\U0001d11e",
                 "model": "m", "backend": "FakeBackend", "request_hash": "c" * 64, "latency_s": 0.2,
                 "calibration_version": "", "answer": {"type": "noul", "noul": 0.55}})
    # out of range, negative, huge exponent (parses to Infinity), string numbers
    for i, v in enumerate([-0.3, 1.7, 1e308, "0.5", None, 0, 1]):
        rows.append({"ts": "2026-12-31T23:59:5%d.000Z" % i, "request_id": "%032x" % (100 + i), "status": 200,
                     "mode": "fast", "question_id": "range_q", "model": "m", "backend": "FakeBackend",
                     "request_hash": "d" * 64, "latency_s": -1, "calibration_version": "",
                     "answer": {"type": "noul", "noul": v}})
    # year boundary and DST boundaries, duplicate request ids
    for ts in ["2026-12-31T23:59:59.999Z", "2027-01-01T00:00:00.000Z", "2026-03-29T01:00:00.000Z",
               "2026-10-25T01:00:00.000Z", "not a date", "+275760-09-13T00:00:00.000Z"]:
        rows.append({"ts": ts, "request_id": "e" * 32, "status": 200, "mode": "fast", "question_id": "dup_q",
                     "model": "m", "backend": "FakeBackend", "request_hash": "f" * 64, "latency_s": 0.1,
                     "calibration_version": "", "answer": {"type": "noul", "noul": 0.42}})
    lines = [json.dumps(r, ensure_ascii=False) for r in rows]
    lines.append('{"ts": "2026-10-01T00:00:00.000Z", "status": 200, "answer": {"type": "noul", "noul": NaN}}')
    lines.append('{"ts": "2026-10-01T00:00:00.000Z", "status": 200, "answer": {"type": "noul", "noul": 1e400}, "question_id": "inf_q", "mode": "fast", "request_id": "%s"}' % ("9" * 32))
    lines.append("[" * 5000 + "]" * 5000)
    lines.append('{"deep": ' + '{"a": ' * 3000 + "1" + "}" * 3000 + "}")
    lines.append("")
    lines.append("not json at all " + XSS[0])
    lines.append("﻿" + json.dumps(rows[2]))
    lines.append('{"ts": "2026-10-01T00:00:00.000Z", "a": 1, "a": 2}')
    lines.append("[]")
    lines.append("null")
    # mixed line endings: CRLF, LF, a bare CR inside, no trailing newline
    body = "\r\n".join(lines[:5]) + "\n" + "\n".join(lines[5:]) + "\r" + json.dumps(rows[3])
    return body


def main(argv):
    big = argv[1] if len(argv) > 1 else os.path.join(FIX, "big")
    os.makedirs(FIX, exist_ok=True)
    os.makedirs(big, exist_ok=True)
    with open(os.path.join(FIX, "hostile.jsonl"), "w", encoding="utf-8", newline="") as fh:
        fh.write(hostile())
    open(os.path.join(FIX, "empty.jsonl"), "w").close()
    n = len(sample_lines())
    for name, count in (("x10.jsonl", n * 10), ("x100.jsonl", n * 100), ("rows100k.jsonl", 100000)):
        with open(os.path.join(big, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(renumbered(count)) + "\n")
    lines, size = [], 0
    for ln in renumbered(10 ** 6):
        if size + len(ln) + 1 > 5 * 1024 * 1024:
            break
        lines.append(ln)
        size += len(ln) + 1
    with open(os.path.join(big, "paste5mb.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("fixtures in", FIX, "and", big)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
