#!/usr/bin/env python3
"""Seal a decision-head audit log with a sidecar hash chain, verify one, or
rotate a live log so that the closed files verify as one series.

decision-head does not chain its audit rows today (docs/audit-log.md, "What
the audit log does not record"; README "Planned"). This sidecar is this
build's own stop-gap. Keep the .chain file where the account that writes the
log cannot write (see the page's "Keeping the seal").

Chain rule, identical in core.js:
    h[-1] = start                                   # 64 zeros for a first file
    h[i]  = sha256_hex(h[i-1] + "\\n" + line[i])    # line without its newline

A file's start is the previous file's final hash, so the seals of rotated
files, laid end to end, equal the seal of the files joined into one log.

Usage:
    seal.py seal   LOG [--after PREV.chain | --start HASH] [--json]
    seal.py verify LOG [CHAIN] [--json]
    seal.py rotate LOG [--dir DIR] [--keep] [--json]
    seal.py verify-series LOG1 LOG2 ... [--json]

Exit codes: 0 verified or written, 1 a break was found, 2 usage or input error.
"""
import hashlib
import json
import os
import re
import shutil
import sys

HEADER_V1 = '# audit-row-reader chain v1: h[i] = sha256(h[i-1] + "\\n" + line[i]), h[-1] = 64 zeros'
HEADER = ('# audit-row-reader chain v2: h[i] = sha256(h[i-1] + "\\n" + line[i]); '
          'h[-1] = the start hash below (64 zeros for a first file)')
ZERO = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SealError(Exception):
    """An input the tool cannot work with (missing file, malformed seal)."""


def split_lines(text):
    """Split on \\n, drop one trailing empty piece, strip one trailing \\r per line."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [ln[:-1] if ln.endswith("\r") else ln for ln in lines]


def chain(lines, start=ZERO):
    prev, out = start, []
    for ln in lines:
        prev = hashlib.sha256((prev + "\n" + ln).encode("utf-8")).hexdigest()
        out.append(prev)
    return out


def line_hash(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def parse_seal(text):
    """Return {"start", "file", "hashes", "bad", "header"}; bad counts non-hash lines.
    CRLF or bare CR line endings and upper-case hex are normalised first."""
    start, name, hashes, bad, header = ZERO, None, [], 0, False
    for ln in split_lines(text.replace("\r\n", "\n").replace("\r", "\n")):
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            header = header or s.startswith("# audit-row-reader chain")
            m = re.match(r"#\s*start:\s*([0-9a-fA-F]{64})\s*$", s)
            if m:
                start = m.group(1).lower()
            m = re.match(r"#\s*file:\s*(.+?)\s*$", s)
            if m:
                name = m.group(1)
            continue
        if re.match(r"^[0-9a-fA-F]{64}$", s):
            s = s.lower()
        if HEX64.match(s):
            hashes.append(s)
        else:
            bad += 1
    return {"start": start, "file": name, "hashes": hashes, "bad": bad, "header": header}


def parse_chain(text):
    """v1 helper kept for callers that want the hash list only."""
    return parse_seal(text)["hashes"]


def final_hash(seal):
    return seal["hashes"][-1] if seal["hashes"] else seal["start"]


def seal_text(lines, start=ZERO, name=None):
    head = [HEADER, "# start: " + start]
    if name:
        head.append("# file: " + os.path.basename(name))
    return "\n".join(head + chain(lines, start)) + "\n"


def verify(lines, sealed, start=ZERO):
    """Return (first_break_row_1_based or None, note)."""
    if isinstance(sealed, dict):
        start, sealed = sealed["start"], sealed["hashes"]
    mine = chain(lines, start)
    for i, (a, b) in enumerate(zip(mine, sealed)):
        if a != b:
            return i + 1, "row %d differs from the sealed copy" % (i + 1)
    if len(lines) < len(sealed):
        return len(lines) + 1, "log ends at row %d; the seal covers %d rows" % (len(lines), len(sealed))
    if len(lines) > len(sealed):
        return None, "rows %d to %d were appended after the seal" % (len(sealed) + 1, len(lines))
    return None, "all %d rows match the seal" % len(lines)


def verify_prev_hash(lines):
    """Check prev_hash links across lines joined in order.
    Return (first_break_row_1_based or None, note)."""
    prev = None
    for i, ln in enumerate(lines):
        try:
            row = json.loads(ln)
        except ValueError:
            row = None
        ph = row.get("prev_hash") if isinstance(row, dict) else None
        if i > 0 and ph != prev:
            return i + 1, "row %d's prev_hash does not match row %d" % (i + 1, i)
        prev = line_hash(ln)
    return None, "%d links hold" % max(0, len(lines) - 1)


def read_lines(path):
    if not os.path.isfile(path):
        raise SealError("no log at %s" % path)
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return split_lines(fh.read())


def read_seal(path):
    if not os.path.isfile(path):
        raise SealError("no seal found at %s; seal the log first or pass the chain file" % path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        seal = parse_seal(fh.read())
    if not seal["hashes"] and (seal["bad"] or not seal["header"]):
        raise SealError("the seal could not be read: %s has no 64-character hash lines" % path)
    if seal["bad"]:
        raise SealError("%s has %d line(s) that are not 64-character hashes" % (path, seal["bad"]))
    return seal


def write_seal(path, lines, start=ZERO):
    out = path + ".chain"
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(seal_text(lines, start, path))
    return out


def seal_file(path, start=ZERO):
    lines = read_lines(path)
    out = write_seal(path, lines, start)
    final = chain(lines, start)[-1] if lines else start
    return {"command": "seal", "log": path, "chain": out, "rows": len(lines), "start": start, "final": final}


def verify_file(path, cpath=None):
    lines = read_lines(path)
    seal = read_seal(cpath or path + ".chain")
    row, note = verify(lines, seal)
    return {"command": "verify", "log": path, "rows": len(lines), "sealed_rows": len(seal["hashes"]),
            "start": seal["start"], "ok": row is None, "first_break": row, "note": note}


ROT = re.compile(r"^(?P<stem>.+)\.(?P<n>\d+)\.jsonl$")


def rotated_names(directory, stem):
    found = []
    for name in os.listdir(directory):
        m = ROT.match(name)
        if m and m.group("stem") == stem:
            found.append((int(m.group("n")), name))
    return sorted(found)


def rotate(path, directory=None, keep=False):
    """Copy-truncate rotation. Copies LOG to DIR/<stem>.<n+1>.jsonl, seals the copy
    starting from the previous rotated file's final hash, then truncates LOG
    (unless keep). Rows appended while copying are carried into the copy before
    the truncate; a row written between the last size check and the truncate
    can still be lost, as with any copy-truncate rotation."""
    if not os.path.isfile(path):
        raise SealError("no log at %s" % path)
    directory = directory or os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    base = os.path.basename(path)
    stem = base[:-6] if base.endswith(".jsonl") else base
    prior = rotated_names(directory, stem)
    start = ZERO
    if prior:
        prev_chain = os.path.join(directory, prior[-1][1] + ".chain")
        start = final_hash(read_seal(prev_chain))
    n = prior[-1][0] + 1 if prior else 1
    dest = os.path.join(directory, "%s.%d.jsonl" % (stem, n))
    with open(path, "rb") as src, open(dest, "wb") as dst:
        for _ in range(3):
            shutil.copyfileobj(src, dst)
            if os.path.getsize(path) == src.tell():
                break
    if not keep:
        with open(path, "r+b") as fh:
            fh.truncate(0)
    res = seal_file(dest, start)
    res.update({"command": "rotate", "rotated_to": dest, "previous": prior[-1][1] if prior else None,
                "truncated": not keep})
    return res


def verify_series(paths):
    """Verify files in the given order as one series.
    Seals when every file has one; prev_hash links when no file has a seal."""
    files = []
    for p in paths:
        lines = read_lines(p)
        cpath = p + ".chain"
        files.append({"log": p, "lines": lines, "seal": read_seal(cpath) if os.path.isfile(cpath) else None})
    with_seal = [f for f in files if f["seal"]]
    out = {"command": "verify-series", "files": [], "boundaries": [], "ok": True, "first_break": None}
    if with_seal and len(with_seal) != len(files):
        missing = [f["log"] for f in files if not f["seal"]]
        raise SealError("no seal for %s; seal every file or none" % ", ".join(missing))
    if with_seal:
        out["method"] = "seal"
        if files[0]["seal"]["start"] != ZERO:
            out["note"] = "the first file's seal starts from an earlier file that is not listed"
        for i, f in enumerate(files):
            row, note = verify(f["lines"], f["seal"])
            appended = row is None and len(f["lines"]) > len(f["seal"]["hashes"])
            out["files"].append({"log": f["log"], "rows": len(f["lines"]), "ok": row is None and not (appended and i < len(files) - 1),
                                 "first_break": row, "note": note})
            if row is not None and out["first_break"] is None:
                out["first_break"] = {"file": f["log"], "row": row}
            if i == 0:
                continue
            prev = files[i - 1]
            link = f["seal"]["start"] == final_hash(prev["seal"])
            prev_extra = len(prev["lines"]) > len(prev["seal"]["hashes"])
            if not link:
                bnote = "%s's seal does not start where %s's seal ends; a file between them is missing, the files are out of order, or a seal was rewritten" % (
                    os.path.basename(f["log"]), os.path.basename(prev["log"]))
            elif prev_extra:
                bnote = "%s has rows after its seal, so %s does not follow on from its last row" % (
                    os.path.basename(prev["log"]), os.path.basename(f["log"]))
            else:
                bnote = "the link holds"
            ok = link and not prev_extra
            out["boundaries"].append({"from": prev["log"], "to": f["log"], "ok": ok, "note": bnote})
            if not ok and (out["first_break"] is None or _earlier(out["first_break"], paths, f["log"], 1)):
                out["first_break"] = {"file": f["log"], "row": 1}
    else:
        out["method"] = "prev_hash"
        joined, owner = [], []
        for f in files:
            for j, ln in enumerate(f["lines"]):
                joined.append(ln)
                owner.append((f["log"], j + 1))
        if not any('"prev_hash"' in ln for ln in joined):
            raise SealError("no seals and no prev_hash fields; nothing to verify")
        row, note = verify_prev_hash(joined)
        if row is not None:
            out["first_break"] = {"file": owner[row - 1][0], "row": owner[row - 1][1]}
        pos = 0
        for i, f in enumerate(files):
            out["files"].append({"log": f["log"], "rows": len(f["lines"])})
            if i > 0:
                ok = row is None or row - 1 > pos
                if row is not None and row - 1 == pos:
                    bnote = "row 1 of %s does not carry the hash of %s's last row" % (
                        os.path.basename(f["log"]), os.path.basename(files[i - 1]["log"]))
                elif row is not None and row - 1 < pos:
                    ok, bnote = None, "unchecked; the chain broke earlier"
                else:
                    bnote = "the link holds"
                out["boundaries"].append({"from": files[i - 1]["log"], "to": f["log"], "ok": ok, "note": bnote})
            pos += len(f["lines"])
        out["note"] = note
    out["ok"] = out["first_break"] is None and all(b["ok"] for b in out["boundaries"]) and all(
        f.get("ok", True) for f in out["files"])
    return out


def _earlier(first, paths, log, row):
    """True when (log, row) comes after first in the series order."""
    a, b = paths.index(first["file"]), paths.index(log)
    return (b, row) < (a, first["row"])


def _human(res):
    cmd = res["command"]
    if cmd in ("seal", "rotate"):
        s = "sealed %d rows -> %s" % (res["rows"], res["chain"])
        if cmd == "rotate":
            s = "rotated to %s (%s); " % (res["rotated_to"], "truncated" if res["truncated"] else "kept") + s
        return s
    if cmd == "verify":
        return ("OK: " if res["ok"] else "BREAK at row %d: " % res["first_break"]) + res["note"]
    lines = []
    for f in res["files"]:
        if "note" in f:
            lines.append("%s: %s" % (f["log"], f["note"]))
    for b in res["boundaries"]:
        flag = "ok" if b["ok"] else ("unchecked" if b["ok"] is None else "BROKEN")
        lines.append("boundary %s -> %s: %s (%s)" % (os.path.basename(b["from"]), os.path.basename(b["to"]), flag, b["note"]))
    fb = res["first_break"]
    lines.append("OK: the series verifies" if res["ok"] else
                 "BREAK" + (" at %s row %d" % (fb["file"], fb["row"]) if fb else "") + "")
    return "\n".join(lines)


def main(argv):
    args = list(argv[1:])
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]

    def opt(name, takes=True):
        if name not in args:
            return None
        i = args.index(name)
        if not takes:
            args.pop(i)
            return True
        if i + 1 >= len(args):
            raise SealError("%s needs a value" % name)
        val = args[i + 1]
        del args[i:i + 2]
        return val

    def emit(res, code):
        print(json.dumps(res, sort_keys=True) if as_json else _human(res))
        return code

    try:
        if not args or args[0] not in ("seal", "verify", "rotate", "verify-series"):
            raise SealError("usage")
        cmd = args.pop(0)
        if cmd == "seal":
            after, start = opt("--after"), opt("--start")
            if not args:
                raise SealError("usage")
            if start and not HEX64.match(start):
                raise SealError("--start must be 64 lowercase hex characters")
            if after:
                start = final_hash(read_seal(after))
            return emit(seal_file(args[0], start or ZERO), 0)
        if cmd == "verify":
            if not args:
                raise SealError("usage")
            res = verify_file(args[0], args[1] if len(args) > 1 else None)
            return emit(res, 0 if res["ok"] else 1)
        if cmd == "rotate":
            directory, keep = opt("--dir"), opt("--keep", takes=False)
            if not args:
                raise SealError("usage")
            return emit(rotate(args[0], directory, bool(keep)), 0)
        if len(args) < 1:
            raise SealError("usage")
        res = verify_series(args)
        return emit(res, 0 if res["ok"] else 1)
    except SealError as exc:
        msg = str(exc)
        if as_json:
            print(json.dumps({"error": msg if msg != "usage" else "usage: see seal.py --help"}))
        else:
            print(__doc__ if msg == "usage" else msg)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
