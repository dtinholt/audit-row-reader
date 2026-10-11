"""stdlib unittest for tools/seal.py, the generated sample and the stress fixtures.
Run from the build folder:  python3 -W error -m unittest discover -s tests -v"""
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import seal  # noqa: E402

LOG = os.path.join(ROOT, "sample", "sample-audit.jsonl")
SERIES = os.path.join(ROOT, "sample", "series")
GAP = os.path.join(ROOT, "sample", "series-missing-2")


def lines():
    with open(LOG, encoding="utf-8") as fh:
        return seal.split_lines(fh.read())


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = seal.main(["seal.py"] + argv)
    return code, buf.getvalue()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="arr-test-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, text, mode="w"):
        path = os.path.join(self.dir, name)
        with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8", "newline": ""})) as fh:
            fh.write(text)
        return path


class LineRules(unittest.TestCase):
    def test_split_lines_drops_one_trailing_empty_and_strips_cr(self):
        self.assertEqual(seal.split_lines("a\r\nb\n\n"), ["a", "b", ""])
        self.assertEqual(seal.split_lines(""), [])
        self.assertEqual(seal.split_lines("a\rb"), ["a\rb"])

    def test_chain_and_start(self):
        import hashlib
        want = hashlib.sha256(("0" * 64 + "\nx").encode()).hexdigest()
        self.assertEqual(seal.chain(["x"]), [want])
        s = "f" * 64
        self.assertEqual(seal.chain(["x"], s)[0], hashlib.sha256((s + "\nx").encode()).hexdigest())
        self.assertEqual(seal.chain([]), [])

    def test_series_of_seals_equals_one_seal(self):
        L = lines()
        whole = seal.chain(L)
        first = seal.chain(L[:100])
        self.assertEqual(seal.chain(L[100:], first[-1]), whole[100:])

    def test_line_hash(self):
        self.assertEqual(seal.line_hash(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


class SealParsing(unittest.TestCase):
    def test_v1_file(self):
        p = seal.parse_seal(seal.HEADER_V1 + "\n" + "a" * 64 + "\n")
        self.assertEqual((p["start"], p["hashes"], p["bad"], p["file"]), (seal.ZERO, ["a" * 64], 0, None))

    def test_v2_header_start_and_file(self):
        text = seal.seal_text(["x", "y"], "b" * 64, "/tmp/dir/audit.2.jsonl")
        p = seal.parse_seal(text)
        self.assertEqual(p["start"], "b" * 64)
        self.assertEqual(p["file"], "audit.2.jsonl")
        self.assertEqual(p["hashes"], seal.chain(["x", "y"], "b" * 64))

    def test_bad_lines_are_counted(self):
        p = seal.parse_seal("nothex\n" + "a" * 64 + "\nxyz" + "a" * 61 + "\n")
        self.assertEqual(p["bad"], 2)
        self.assertEqual(seal.parse_chain("a" * 64), ["a" * 64])

    def test_uppercase_hex_and_crlf_are_normalised(self):
        h = seal.chain(["x", "y"])
        p = seal.parse_seal("# audit-row-reader chain v2\r\n# start: " + "A" * 64 + "\r\n" + "\r\n".join(h).upper() + "\r")
        self.assertEqual(p["hashes"], h)
        self.assertEqual(p["start"], "a" * 64)
        self.assertEqual(p["bad"], 0)

    def test_header_flag(self):
        self.assertTrue(seal.parse_seal(seal.seal_text([]))["header"])
        self.assertFalse(seal.parse_seal("a" * 64)["header"])

    def test_final_hash(self):
        self.assertEqual(seal.final_hash({"start": "c" * 64, "hashes": []}), "c" * 64)
        self.assertEqual(seal.final_hash({"start": "c" * 64, "hashes": ["d" * 64]}), "d" * 64)


class Verify(unittest.TestCase):
    def setUp(self):
        self.L = lines()
        with open(LOG + ".chain", encoding="utf-8") as fh:
            self.sealed = seal.parse_chain(fh.read())

    def test_sample_verifies(self):
        self.assertEqual(seal.verify(self.L, self.sealed)[0], None)

    def test_edit_breaks_at_that_row(self):
        L = list(self.L)
        L[136] = L[136].replace('"ts": "2026', '"ts": "2027')
        self.assertEqual(seal.verify(L, self.sealed)[0], 137)

    def test_corrupted_sample_file_breaks_at_137(self):
        with open(os.path.join(ROOT, "sample", "sample-audit-corrupted-row137.jsonl"), encoding="utf-8") as fh:
            self.assertEqual(seal.verify(seal.split_lines(fh.read()), self.sealed)[0], 137)

    def test_deleted_row(self):
        self.assertEqual(seal.verify(self.L[:249] + self.L[250:], self.sealed)[0], 250)

    def test_truncation(self):
        row, note = seal.verify(self.L[:-3], self.sealed)
        self.assertEqual(row, len(self.L) - 2)
        self.assertIn("seal covers", note)

    def test_append_is_not_a_break(self):
        row, note = seal.verify(self.L + ["{}"], self.sealed)
        self.assertIsNone(row)
        self.assertIn("appended", note)

    def test_verify_accepts_a_parsed_seal_with_start(self):
        s = {"start": "e" * 64, "hashes": seal.chain(["a"], "e" * 64)}
        self.assertEqual(seal.verify(["a"], s), (None, "all 1 rows match the seal"))
        self.assertEqual(seal.verify(["b"], s)[0], 1)

    def test_prev_hash_chain(self):
        rows, out = [json.loads(x) for x in self.L[:30]], []
        for i, r in enumerate(rows):
            r["prev_hash"] = seal.line_hash(out[i - 1]) if i else None
            out.append(json.dumps(r))
        self.assertEqual(seal.verify_prev_hash(out)[0], None)
        bad = list(out)
        bad[9] = bad[9].replace('"ts": "2026', '"ts": "2025')
        self.assertEqual(seal.verify_prev_hash(bad)[0], 11)
        unparsable = list(out)
        unparsable[5] = "{oops"
        self.assertEqual(seal.verify_prev_hash(unparsable)[0], 6)


class Files(Tmp):
    def test_read_lines_missing(self):
        with self.assertRaises(seal.SealError):
            seal.read_lines(os.path.join(self.dir, "nope.jsonl"))

    def test_read_lines_replaces_invalid_utf8(self):
        p = self.write("bad.jsonl", b'{"a": "\xff"}\n', "wb")
        self.assertEqual(seal.read_lines(p), ['{"a": "�"}'])

    def test_read_seal_missing_and_bad(self):
        with self.assertRaises(seal.SealError):
            seal.read_seal(os.path.join(self.dir, "x.chain"))
        p = self.write("x.chain", "garbage\n")
        with self.assertRaises(seal.SealError):
            seal.read_seal(p)

    def test_unreadable_seal_says_so(self):
        p = self.write("u.chain", "NOT A SEAL\r\nstill not\r\n")
        with self.assertRaises(seal.SealError) as cm:
            seal.read_seal(p)
        self.assertIn("the seal could not be read", str(cm.exception))
        empty = self.write("blank.chain", "")
        with self.assertRaises(seal.SealError) as cm:
            seal.read_seal(empty)
        self.assertIn("could not be read", str(cm.exception))

    def test_uppercase_seal_verifies(self):
        p = self.write("a.jsonl", "one\ntwo\n")
        with open(p + ".chain", "w", encoding="utf-8", newline="") as fh:
            fh.write(seal.seal_text(["one", "two"], name=p).upper().replace("\n", "\r\n"))
        self.assertTrue(seal.verify_file(p)["ok"])

    def test_unreadable_seal_cli_exits_2(self):
        p = self.write("a.jsonl", "one\n")
        self.write("a.jsonl.chain", "garbage\n")
        code, out = run(["verify", p])
        self.assertEqual(code, 2)
        self.assertIn("could not be read", out)

    def test_seal_file_and_verify_file(self):
        p = self.write("a.jsonl", "one\ntwo\n")
        res = seal.seal_file(p)
        self.assertEqual(res["rows"], 2)
        self.assertEqual(res["final"], seal.chain(["one", "two"])[-1])
        self.assertTrue(seal.verify_file(p)["ok"])
        self.write("a.jsonl", "one\nTWO\n")
        v = seal.verify_file(p)
        self.assertEqual((v["ok"], v["first_break"]), (False, 2))

    def test_seal_empty_file(self):
        p = self.write("e.jsonl", "")
        res = seal.seal_file(p, "a" * 64)
        self.assertEqual(res["final"], "a" * 64)
        self.assertEqual(seal.read_seal(p + ".chain")["hashes"], [])

    def test_rotated_names(self):
        for n in ("audit.1.jsonl", "audit.10.jsonl", "audit.2.jsonl", "other.3.jsonl", "audit.jsonl"):
            self.write(n, "")
        self.assertEqual([n for n, _ in seal.rotated_names(self.dir, "audit")], [1, 2, 10])


class Rotate(Tmp):
    def test_rotate_twice_links_and_truncates(self):
        live = self.write("audit.jsonl", "r1\nr2\n")
        a = seal.rotate(live)
        self.assertEqual(os.path.getsize(live), 0)
        self.assertTrue(a["truncated"])
        self.assertIsNone(a["previous"])
        self.assertEqual(a["start"], seal.ZERO)
        with open(live, "a", encoding="utf-8") as fh:
            fh.write("r3\n")
        b = seal.rotate(live)
        self.assertEqual(b["previous"], "audit.1.jsonl")
        self.assertEqual(b["start"], a["final"])
        res = seal.verify_series([a["rotated_to"], b["rotated_to"]])
        self.assertTrue(res["ok"])
        self.assertEqual(seal.chain(["r3"], seal.chain(["r1", "r2"])[-1])[-1], b["final"])

    def test_rotate_keep_and_dir(self):
        live = self.write("audit.jsonl", "r1\n")
        out = os.path.join(self.dir, "closed")
        res = seal.rotate(live, out, keep=True)
        self.assertEqual(os.path.getsize(live), 3)
        self.assertTrue(res["rotated_to"].startswith(out))
        self.assertFalse(res["truncated"])

    def test_rotate_missing_log(self):
        with self.assertRaises(seal.SealError):
            seal.rotate(os.path.join(self.dir, "none.jsonl"))

    def test_rotate_name_without_jsonl_suffix(self):
        live = self.write("audit.log", "r1\n")
        res = seal.rotate(live)
        self.assertTrue(res["rotated_to"].endswith("audit.log.1.jsonl"))


class Series(Tmp):
    def paths(self, d, ks=(1, 2, 3)):
        return [os.path.join(d, "audit.%d.jsonl" % k) for k in ks]

    def copy_series(self):
        for name in os.listdir(SERIES):
            shutil.copy(os.path.join(SERIES, name), self.dir)
        return self.paths(self.dir)

    def test_sample_series_verifies(self):
        res = seal.verify_series(self.paths(SERIES))
        self.assertTrue(res["ok"])
        self.assertEqual([b["ok"] for b in res["boundaries"]], [True, True])
        self.assertEqual(res["method"], "seal")

    def test_sample_series_joins_to_the_single_file(self):
        joined = []
        for p in self.paths(SERIES):
            joined += seal.read_lines(p)
        self.assertEqual(joined, lines())
        self.assertEqual(seal.final_hash(seal.read_seal(self.paths(SERIES)[-1] + ".chain")), seal.chain(lines())[-1])

    def test_missing_middle_file_breaks_at_the_boundary(self):
        p = self.paths(GAP, (1, 3))
        res = seal.verify_series(p)
        self.assertFalse(res["ok"])
        self.assertEqual(res["first_break"], {"file": p[1], "row": 1})
        self.assertFalse(res["boundaries"][0]["ok"])
        self.assertIn("missing", res["boundaries"][0]["note"])

    def test_reordered_files_break(self):
        p = self.paths(SERIES)
        res = seal.verify_series([p[1], p[0], p[2]])
        self.assertFalse(res["ok"])
        self.assertEqual(res["first_break"]["row"], 1)
        self.assertIn("note", res)

    def test_rows_appended_to_a_closed_file(self):
        p = self.copy_series()
        with open(p[0], "a", encoding="utf-8") as fh:
            fh.write('{"late": true}\n')
        res = seal.verify_series(p)
        self.assertFalse(res["ok"])
        self.assertEqual(res["first_break"], {"file": p[1], "row": 1})
        self.assertIn("rows after its seal", res["boundaries"][0]["note"])

    def test_edit_inside_file_two(self):
        p = self.copy_series()
        L = seal.read_lines(p[1])
        L[4] = L[4].replace("2026-09", "2026-08", 1)
        with open(p[1], "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(L) + "\n")
        res = seal.verify_series(p)
        self.assertEqual(res["first_break"], {"file": p[1], "row": 5})
        self.assertTrue(all(b["ok"] for b in res["boundaries"]))
        self.assertFalse(res["ok"])

    def test_truncated_first_file(self):
        p = self.copy_series()
        L = seal.read_lines(p[0])
        with open(p[0], "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(L[:-1]) + "\n")
        res = seal.verify_series(p)
        self.assertEqual(res["first_break"], {"file": p[0], "row": len(L)})

    def test_mixed_sealed_and_unsealed_is_an_error(self):
        p = self.copy_series()
        os.remove(p[1] + ".chain")
        with self.assertRaises(seal.SealError):
            seal.verify_series(p)

    def test_first_file_starting_later_is_noted(self):
        p = self.paths(SERIES, (2, 3))
        res = seal.verify_series(p)
        self.assertTrue(res["ok"])
        self.assertIn("earlier file", res["note"])

    def write_prev(self, parts):
        out, prev, paths = [], None, []
        for k, part in enumerate(parts):
            rows = []
            for ln in part:
                r = json.loads(ln)
                r["prev_hash"] = prev
                s = json.dumps(r)
                rows.append(s)
                prev = seal.line_hash(s)
            paths.append(self.write("p.%d.jsonl" % (k + 1), "\n".join(rows) + "\n"))
            out.append(rows)
        return paths, out

    def test_prev_hash_series(self):
        L = lines()[:60]
        paths, rows = self.write_prev([L[:20], L[20:40], L[40:]])
        res = seal.verify_series(paths)
        self.assertTrue(res["ok"])
        self.assertEqual(res["method"], "prev_hash")
        rows[1][-1] = rows[1][-1].replace('"ts": "2026', '"ts": "2025')
        with open(paths[1], "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(rows[1]) + "\n")
        bad = seal.verify_series(paths)
        self.assertEqual(bad["first_break"], {"file": paths[2], "row": 1})
        self.assertEqual([b["ok"] for b in bad["boundaries"]], [True, False])

    def test_prev_hash_break_inside_first_file_leaves_later_boundaries_unchecked(self):
        L = lines()[:30]
        paths, rows = self.write_prev([L[:10], L[10:20], L[20:]])
        rows[0][3] = rows[0][3].replace('"ts": "2026', '"ts": "2025')
        with open(paths[0], "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(rows[0]) + "\n")
        res = seal.verify_series(paths)
        self.assertEqual(res["first_break"], {"file": paths[0], "row": 5})
        self.assertEqual([b["ok"] for b in res["boundaries"]], [None, None])

    def test_no_seals_no_prev_hash_is_an_error(self):
        p = self.write("plain.jsonl", "{}\n")
        with self.assertRaises(seal.SealError):
            seal.verify_series([p])


class Cli(Tmp):
    def test_usage(self):
        self.assertEqual(run([])[0], 2)
        self.assertEqual(run(["frobnicate"])[0], 2)
        for cmd in ("seal", "verify", "rotate", "verify-series"):
            self.assertEqual(run([cmd])[0], 2, cmd)

    def test_usage_json(self):
        code, out = run(["--json"])
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))

    def test_seal_and_verify_exit_codes(self):
        p = self.write("a.jsonl", "x\ny\n")
        self.assertEqual(run(["seal", p])[0], 0)
        self.assertEqual(run(["verify", p])[0], 0)
        self.write("a.jsonl", "x\nz\n")
        code, out = run(["verify", p])
        self.assertEqual(code, 1)
        self.assertIn("BREAK at row 2", out)

    def test_verify_json_and_explicit_chain(self):
        p = self.write("a.jsonl", "x\n")
        seal.seal_file(p)
        os.rename(p + ".chain", os.path.join(self.dir, "elsewhere.chain"))
        code, out = run(["verify", p, os.path.join(self.dir, "elsewhere.chain"), "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["first_break"], None)

    def test_seal_missing_chain_exits_2_with_one_line(self):
        code, out = run(["verify", os.path.join(ROOT, "README.md")])
        self.assertEqual(code, 2)
        self.assertEqual(len(out.strip().splitlines()), 1)

    def test_seal_start_options(self):
        a = self.write("a.jsonl", "x\n")
        b = self.write("b.jsonl", "y\n")
        self.assertEqual(run(["seal", a])[0], 0)
        code, out = run(["seal", b, "--after", a + ".chain", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["start"], seal.chain(["x"])[-1])
        self.assertEqual(run(["verify-series", a, b])[0], 0)
        self.assertEqual(run(["seal", b, "--start", "c" * 64])[0], 0)
        self.assertEqual(run(["verify-series", a, b])[0], 1)
        self.assertEqual(run(["seal", b, "--start", "nothex"])[0], 2)
        self.assertEqual(run(["seal", b, "--start"])[0], 2)

    def test_rotate_cli(self):
        live = self.write("audit.jsonl", "r1\n")
        code, out = run(["rotate", live, "--dir", self.dir, "--json"])
        self.assertEqual(code, 0)
        res = json.loads(out)
        self.assertTrue(res["truncated"])
        with open(live, "a", encoding="utf-8") as fh:
            fh.write("r2\n")
        code, out = run(["rotate", live, "--keep"])
        self.assertEqual(code, 0)
        self.assertIn("kept", out)
        code, out = run(["verify-series", os.path.join(self.dir, "audit.1.jsonl"), os.path.join(self.dir, "audit.2.jsonl")])
        self.assertEqual(code, 0)
        self.assertIn("OK: the series verifies", out)

    def test_verify_series_cli_break_and_json(self):
        p = [os.path.join(GAP, "audit.1.jsonl"), os.path.join(GAP, "audit.3.jsonl")]
        code, out = run(["verify-series"] + p)
        self.assertEqual(code, 1)
        self.assertIn("BROKEN", out)
        code, out = run(["verify-series", "--json"] + p)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["first_break"]["row"], 1)

    def test_verify_series_cli_prev_hash_unchecked_label(self):
        rows, prev = [], None
        for i in range(4):
            r = {"i": i, "prev_hash": prev}
            s = json.dumps(r)
            rows.append(s)
            prev = seal.line_hash(s)
        rows[0] = rows[0].replace('"i": 0', '"i": 9')
        a = self.write("a.jsonl", rows[0] + "\n" + rows[1] + "\n")
        b = self.write("b.jsonl", rows[2] + "\n" + rows[3] + "\n")
        code, out = run(["verify-series", a, b])
        self.assertEqual(code, 1)
        self.assertIn("unchecked", out)

    def test_error_in_json_mode(self):
        code, out = run(["verify", os.path.join(self.dir, "missing.jsonl"), "--json"])
        self.assertEqual(code, 2)
        self.assertIn("no log", json.loads(out)["error"])


class SampleShape(unittest.TestCase):
    def test_rows_follow_documented_fields(self):
        for ln in lines():
            r = json.loads(ln)
            self.assertIn("ts", r)
            self.assertRegex(r["request_id"], r"^[0-9a-f]{32}$")
            self.assertTrue(r["ts"].endswith("Z"))
            if r["status"] == 200:
                for k in ("mode", "question_id", "model", "backend", "request_hash", "latency_s", "answer"):
                    self.assertIn(k, r)
                if r["mode"] == "fast":
                    self.assertIn("calibration_version", r)
                    self.assertIn("raw_distribution", r)
                if r.get("low_confidence"):
                    self.assertIn("handoff_reason", r)
            else:
                for k in ("error", "mode", "request_hash", "n_questions"):
                    self.assertIn(k, r)

    def test_band_flags_match_band(self):
        for ln in lines():
            r = json.loads(ln)
            a = r.get("answer") or {}
            if a.get("type") == "noul" and isinstance(a.get("noul"), float) and not a.get("n_missing_samples"):
                self.assertEqual(bool(r.get("low_confidence")), 0.4 <= a["noul"] <= 0.6)

    def test_reasked_cases_exist_and_are_not_cache_hits(self):
        by = {}
        for ln in lines():
            r = json.loads(ln)
            if r["status"] == 200 and not r.get("cache_hit"):
                by.setdefault(r["request_hash"].replace("-deliberate", ""), set()).add(r["request_id"])
        self.assertEqual(sum(1 for v in by.values() if len(v) > 1), 3)

    def test_sample_seal_is_v2_with_start_and_file(self):
        with open(LOG + ".chain", encoding="utf-8") as fh:
            text = fh.read()
        self.assertTrue(text.startswith(seal.HEADER + "\n"))
        p = seal.parse_seal(text)
        self.assertEqual((p["start"], p["file"], p["bad"]), (seal.ZERO, "sample-audit.jsonl", 0))
        self.assertEqual(p["hashes"], seal.chain(lines()))

    def test_embedded_sample_matches_the_files(self):
        with open(os.path.join(ROOT, "sample.js"), encoding="utf-8") as fh:
            src = fh.read()
        m = re.search(r"var SAMPLE_LINES = (\[.*?\]);\nvar SAMPLE_CHAIN = (\[.*?\]);", src, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(json.loads(m.group(1)), lines())
        self.assertEqual(json.loads(m.group(2)), seal.chain(lines()))

    def test_no_vendor_names_in_build(self):
        banned = ["Oll" + "ama", "Open" + "AI", "Cl" + "aude", "Anth" + "ropic", "G" + "PT-", "Gem" + "ini"]
        for dirpath, _dirs, files in os.walk(ROOT):
            if "shots" in dirpath or "__pycache__" in dirpath:
                continue
            for name in files:
                if name.endswith((".png", ".pdf")):
                    continue
                with open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
                for b in banned:
                    self.assertNotIn(b, text, "%s in %s" % (b, name))

    def test_no_em_dashes_in_page_copy(self):
        for name in ("index.html", "app.js", "README.md"):
            with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
                self.assertNotIn("—", fh.read(), name)


class StressFixtures(unittest.TestCase):
    def test_hostile_fixture_has_every_case(self):
        with open(os.path.join(ROOT, "tests", "fixtures", "hostile.jsonl"), encoding="utf-8", newline="") as fh:
            text = fh.read()
        self.assertIn("\r\n", text)
        self.assertIn("<script>", text)
        self.assertIn("onerror", text)
        self.assertIn("NaN", text)
        self.assertIn("1e400", text)
        self.assertIn("﻿", text)
        self.assertRegex(text, r"\r(?!\n)")
        self.assertEqual(os.path.getsize(os.path.join(ROOT, "tests", "fixtures", "empty.jsonl")), 0)

    def test_hostile_fixture_seals_and_verifies(self):
        with open(os.path.join(ROOT, "tests", "fixtures", "hostile.jsonl"), encoding="utf-8", newline="") as fh:
            L = seal.split_lines(fh.read())
        self.assertEqual(seal.verify(L, seal.chain(L))[0], None)


if __name__ == "__main__":
    unittest.main()
