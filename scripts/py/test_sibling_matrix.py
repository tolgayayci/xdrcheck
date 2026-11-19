#!/usr/bin/env python3
"""Tests of scripts/py/sibling_matrix.py: how defect classes are derived and how each family's cell is judged,
on small made-up records and run cells, and the committed sibling matrix's separate root defects."""
import collections, os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sibling_matrix as S  # noqa: E402


def rec(rid, project, entries, state="duplicate-of", va="", **kw):
    d = {"id": rid, "title": f"defect of {rid}", "state": state, "component": "sdk",
         "target": {"project": project, "versions_affected": va},
         "entries": [{"id": e, "variant": v, "scope": l} for e, v, l in entries]}
    if state == "filed":
        d["upstream"] = {"url": f"https://example.invalid/{rid}"}
    d.update(kw)
    return d


COLUMNS = {
    "js@16.3.0": {"id": "js@16.3.0", "sdk": "js", "version": "16.3.0", "profile": None},
    "js@17.2.0": {"id": "js@17.2.0", "sdk": "js", "version": "17.2.0", "profile": None},
    "js@17.3.0": {"id": "js@17.3.0", "sdk": "js", "version": "17.3.0", "profile": None},
    "go@v0.7.1": {"id": "go@v0.7.1", "sdk": "go", "version": "0.7.1", "profile": None},
    "go@v0.9.0": {"id": "go@v0.9.0", "sdk": "go", "version": "0.9.0", "profile": None},
    "python@17.0.1": {"id": "python@17.0.1", "sdk": "python", "version": "17.0.1", "profile": None},
}
FAM_COLUMNS = collections.defaultdict(list)
for _c in COLUMNS.values():
    FAM_COLUMNS[S.family_of_column(_c)].append(_c["id"])


def cell(verdict, finding=None, pending=False):
    check = "conform" if verdict == "conform" else "n_a" if verdict == "n_a" else "known" if finding else "undeclared"
    return {"verdict": verdict, "check": check, "finding": finding, "pending": pending}


class Fixture:
    def __init__(self):
        self.recs, self.cells = {}, {}

    def fail(self, key, column, rid=None, pending=False, verdict="reject_valid"):
        self.cells[key + (column,)] = cell(verdict, rid, pending)

    def ok(self, key, *columns):
        for c in columns:
            self.cells[key + (c,)] = cell("conform")

    def classes(self):
        return S.build_classes(self.recs, COLUMNS, self.cells)

    def row(self, cls):
        return S.judge(cls, self.recs, COLUMNS, self.cells, FAM_COLUMNS)


POOL = ("cap-0038/pool-order", "", "L4")
MAPSORT = ("cap-0046/map-sort", "", "L4")
IDS = ("classic/offer-id", "", "L4")
COLLIDE = ("cap-0046/map-collide", "none", "L3")
TRAIL = ("xdr-strict/trailing", "", "L4")


class Classes(unittest.TestCase):
    def setUp(self):
        f = Fixture()
        f.recs = {
            # one record, two defects: the pool order fixed in 17.3.0, the map order still failing there
            "F-0001": rec("F-0001", "stellar/js-stellar-sdk", [POOL, MAPSORT], va="17.2.0"),
            "F-0002": rec("F-0002", "stellar/go-stellar-sdk", [POOL], va="v0.7.1", defect_group="DG-pool"),
            "F-0003": rec("F-0003", "stellar/js-stellar-sdk", [IDS], va="17.2.0", defect_group="DG-ids"),
            "F-0004": rec("F-0004", "StellarCN/py-stellar-base", [IDS], va="17.0.1", defect_group="DG-ids", state="filed"),
            "F-0005": rec("F-0005", "stellar/js-stellar-sdk", [COLLIDE], va="17.2.0"),
            "F-0006": rec("F-0006", "stellar/go-stellar-sdk", [TRAIL], va="v0.7.1 - v0.9.0"),
            # a record of another family that is by design: its class has no defect left
            "F-0007": rec("F-0007", "StellarCN/py-stellar-base", [("contract-spec/x", "none", "spec")], state="not-a-defect"),
            # a record the runs never show: an API the drivers do not call
            "F-0008": rec("F-0008", "stellar/js-stellar-sdk", [("cap-0021/precond", "", "L1")], va="17.1.0 - 17.3.0; 16.3.0 is not affected", state="filed"),
        }
        f.fail(POOL, "js@17.2.0", "F-0001")
        f.ok(POOL, "js@17.3.0", "js@16.3.0", "python@17.0.1")
        f.fail(MAPSORT, "js@17.2.0", "F-0001")
        f.fail(MAPSORT, "js@17.3.0", "F-0001")
        f.fail(POOL, "go@v0.7.1", "F-0002")
        f.ok(POOL, "go@v0.9.0")
        f.fail(IDS, "js@17.2.0", "F-0003")
        f.ok(IDS, "js@17.3.0", "go@v0.7.1", "go@v0.9.0")
        f.fail(IDS, "python@17.0.1", "F-0004")
        f.fail(("classic/offer-id-negative", "", "L4"), "python@17.0.1", pending=True, verdict="accepts_invalid")
        f.fail(COLLIDE, "js@17.2.0", "F-0005")
        f.cells[COLLIDE + ("go@v0.9.0",)] = cell("n_a")
        f.fail(TRAIL, "go@v0.7.1", "F-0006")
        f.fail(TRAIL, "go@v0.9.0", "F-0006")
        f.ok(TRAIL, "js@17.3.0", "python@17.0.1")
        f.fail(("contract-spec/x", "none", "spec"), "python@17.0.1", "F-0007")
        f.ok(("cap-0021/precond", "testnet", "L1"), "js@17.2.0", "js@16.3.0", "go@v0.9.0")
        self.f = f
        self.classes = {tuple(c["records"]): c for c in f.classes()}

    def test_root_defects_are_separate_rows(self):
        self.assertIn(("F-0001", "F-0002"), self.classes)  # pool order: joined by the shared cell
        self.assertIn(("F-0001",), self.classes)  # map order: split off F-0001
        self.assertIn(("F-0003", "F-0004"), self.classes)  # ID encoding: joined by the defect group
        self.assertIn(("F-0005",), self.classes)
        self.assertIn(("F-0006",), self.classes)
        self.assertNotIn(("F-0007",), self.classes)  # only not-a-defect: no row

    def test_pool_order_cells(self):
        row = self.f.row(self.classes[("F-0001", "F-0002")])
        self.assertEqual(row["js"]["state"], "reproduces")
        self.assertEqual(row["js"]["versions"], ["17.2.0"])
        self.assertEqual(row["js"]["passes_from"], "17.3.0")
        self.assertEqual(row["js16"]["state"], "not-affected")
        self.assertEqual(row["go"]["passes_from"], "0.9.0")
        self.assertEqual(row["python"]["state"], "not-affected")
        self.assertEqual(row["java"], {"state": "not-run", "why": "no driver in the public column sets"})

    def test_pending_and_records(self):
        cls = self.classes[("F-0003", "F-0004")]
        cls["keys"].append(("classic/offer-id-negative", "", "L4"))
        row = self.f.row(cls)
        self.assertEqual(row["python"]["records"], ["F-0004"])
        self.assertTrue(row["python"]["pending"])
        self.assertEqual(row["go"]["state"], "not-affected")
        self.assertNotIn("pending", row["js"])

    def test_not_run_when_not_applicable(self):
        row = self.f.row(self.classes[("F-0005",)])
        self.assertEqual(row["go"], {"state": "not-run", "why": "no column run gives a verdict on the cells"})

    def test_still_failing_has_no_passes_from(self):
        row = self.f.row(self.classes[("F-0006",)])
        self.assertEqual(row["go"]["versions"], ["0.7.1", "0.9.0"])
        self.assertIsNone(row["go"]["passes_from"])
        self.assertEqual(row["js"]["state"], "not-affected")

    def test_record_outside_runs(self):
        row = self.f.row(self.classes[("F-0008",)])
        self.assertEqual(row["js"]["state"], "outside-runs")
        self.assertEqual(row["js16"]["state"], "not-affected")  # the record's later clause is not its range
        self.assertEqual(row["go"]["state"], "not-affected")

    def test_records_view_links_only_filed(self):
        view = S.record_view(self.f.recs, {"F-0003", "F-0004"})
        self.assertNotIn("url", view["F-0003"])
        self.assertEqual(view["F-0004"]["url"], "https://example.invalid/F-0004")
        self.assertIn("F-0004 ([filed](https://example.invalid/F-0004))", S.record_text("F-0004", view))
        self.assertEqual(S.record_text("F-0003", view), "F-0003 (known upstream)")


class Rulings(unittest.TestCase):
    """findings/siblings-not-applicable.json: a ruled not-run cell becomes not-applicable; anything else wins."""

    FAMS = {f: {"label": f, "columns": ["x@1"] if f in ("js", "go") else []} for f in S.FAMILY_IDS}

    def rows(self):
        cells = {f: {"state": "not-run", "why": S.not_run_why(self.FAMS[f]["columns"])} for f in S.FAMILY_IDS}
        cells["go"] = {"state": "outside-runs", "versions_run": [], "records": ["F-0001"]}
        cells["js"] = {"state": "not-affected", "versions": ["1"]}
        return [{"id": "DC-F-0001", "cells": cells}]

    def test_applies_to_not_run_only(self):
        rows = S.apply_rulings(self.rows(), self.FAMS, {("DC-F-0001", "python"): "no such API",
                                                        ("DC-F-0001", "go"): "no such API",
                                                        ("DC-F-0001", "js"): "no such API"})
        cells = rows[0]["cells"]
        self.assertEqual(cells["python"], {"state": "not-applicable", "why": "no such API"})
        self.assertEqual(cells["go"]["state"], "outside-runs")  # a record wins
        self.assertEqual(cells["js"]["state"], "not-affected")  # an executed result wins
        self.assertEqual(cells["rust"]["state"], "not-run")

    def test_idempotent_and_reversible(self):
        once = S.apply_rulings(self.rows(), self.FAMS, {("DC-F-0001", "python"): "no such API"})
        twice = S.apply_rulings(json_copy(once), self.FAMS, {("DC-F-0001", "python"): "no such API"})
        self.assertEqual(once, twice)
        back = S.apply_rulings(json_copy(once), self.FAMS, {})
        self.assertEqual(back, self.rows())

    def test_unknown_class_is_an_error(self):
        with self.assertRaises(S.Fail):
            S.apply_rulings(self.rows(), self.FAMS, {("DC-F-9999", "python"): "no such API"})

    def test_file_shape(self):
        import tempfile, json
        def load(rulings):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, dir=os.path.dirname(S.NA_PATH)) as f:
                json.dump({"about": "", "rulings": rulings}, f)
            try:
                return S.load_rulings(f.name)
            finally:
                os.unlink(f.name)
        self.assertEqual(load([{"class": "C", "families": ["go", "python"], "reason": "r"}]),
                         {("C", "go"): "r", ("C", "python"): "r"})
        for bad in ([{"class": "C", "families": ["cobol"], "reason": "r"}],
                    [{"class": "C", "families": ["go"], "reason": ""}],
                    [{"class": "C", "families": ["go"], "reason": "two\nlines"}],
                    [{"class": "C", "families": ["go"], "reason": "see stellar/go#12"}],
                    [{"class": "C", "families": ["go"], "reason": "r"}, {"class": "C", "families": ["go"], "reason": "s"}]):
            with self.assertRaises(S.Fail, msg=bad):
                load(bad)


def json_copy(x):
    import json
    return json.loads(json.dumps(x))


class Committed(unittest.TestCase):
    """The committed matrix keeps the known upstream defects apart."""

    def test_separate_rows(self):
        if not os.path.exists(S.JSON_PATH):
            self.skipTest("no committed sibling matrix")
        d = S.R.load(S.JSON_PATH)
        owner = {}
        for c in d["classes"]:
            for e in c["entries"]:
                owner.setdefault(e, c["id"])
        named = [
            "cap-0038/pool-issuers-order-by-bytes-not-strkey",
            "classic/api-offer-id-encoding.id-negative",
            "cap-0046/scval-map-keys-collide-u32-symbol",
            "xdr-strict/api-transaction-parse-trailing-bytes.one-byte-in-final-quantum",
        ]
        rows = [owner.get(e) for e in named]
        self.assertNotIn(None, rows)
        self.assertEqual(len(set(rows)), len(rows), rows)
        self.assertEqual(S.cheap_check(), [])


if __name__ == "__main__":
    unittest.main()
