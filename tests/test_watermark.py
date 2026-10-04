"""End-to-end and unit tests for the export watermark module."""

from __future__ import annotations

import copy
import json
import random
import tempfile
import unittest

from maskhub.console.errors import error_response
from maskhub.console.http import Request
from maskhub.console.routes import build_router
from maskhub.console.runtime import build_runtime
from maskhub.store.kvstore import RecordStore
from maskhub.watermark.core import (
    EmbedStats,
    compute_checksum,
    embed_rows,
    score_rows,
    write_bit,
)
from maskhub.watermark.profile import ColumnMark, WatermarkProfile
from maskhub.watermark.report import seal, verify_document

PROFILE_DICT = {
    "dataset": "orders",
    "primary_key": "order_id",
    "carrier_mod": 4,
    "min_carriers": 30,
    "columns": [
        {"name": "amount", "kind": "numeric", "minimum": 0, "maximum": 100000},
        {"name": "quantity", "kind": "numeric", "minimum": 0},
        {"name": "discount", "kind": "numeric", "minimum": 0, "maximum": 1},
        {"name": "channel", "kind": "category", "pairs": {"线上": "在线"}},
    ],
    "checksum": {
        "name": "row_crc",
        "algorithm": "crc32",
        "columns": ["order_id", "amount", "quantity", "discount", "channel"],
    },
}


def make_profile() -> WatermarkProfile:
    profile = WatermarkProfile.from_dict(PROFILE_DICT)
    assert profile is not None
    return profile


def make_rows(count: int = 1200, seed: int = 42) -> list[dict[str, str]]:
    rng = random.Random(seed)
    profile = make_profile()
    assert profile.checksum is not None
    rows = []
    for index in range(count):
        row = {
            "order_id": f"SO{index:06d}",
            "amount": f"{rng.uniform(1, 9999):.2f}",
            "quantity": str(rng.randint(1, 50)),
            "discount": f"{rng.uniform(0, 0.3):.2f}",
            "channel": rng.choice(["线上", "线下", "电话"]),
        }
        row["row_crc"] = compute_checksum(profile.checksum, row)
        rows.append(row)
    return rows


def mutate_cells(rows: list[dict[str, str]], fraction: float, seed: int) -> None:
    rng = random.Random(seed)
    for row in rows:
        if rng.random() < fraction:
            row["amount"] = f"{float(row['amount']) + rng.choice([-1, 1]) * 0.37:.2f}"
        if rng.random() < fraction:
            row["quantity"] = str(max(0, int(row["quantity"]) + rng.choice([-1, 1])))


class WatermarkCase(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = make_profile()
        self.rows = make_rows()
        self.key_a = b"batch-key-A" * 2
        self.key_b = b"batch-key-B" * 2

    def embed(self, key: bytes) -> list[dict[str, str]]:
        rows = copy.deepcopy(self.rows)
        embed_rows(rows, self.profile, key)
        return rows


class EmbeddingTest(WatermarkCase):
    def test_roundtrip_scores_perfect_match(self) -> None:
        marked = self.embed(self.key_a)
        score = score_rows(marked, self.profile, self.key_a)
        self.assertGreater(score.carriers, 100)
        self.assertEqual(score.matches, score.carriers)
        self.assertLess(score.p_value, 1e-30)

    def test_embed_is_deterministic_and_idempotent(self) -> None:
        first = self.embed(self.key_a)
        second = copy.deepcopy(first)
        stats = embed_rows(second, self.profile, self.key_a)
        self.assertEqual(first, second)
        self.assertEqual(stats.cells_changed, 0)

    def test_row_order_is_irrelevant(self) -> None:
        marked = self.embed(self.key_a)
        shuffled = copy.deepcopy(marked)
        random.Random(7).shuffle(shuffled)
        self.assertEqual(
            score_rows(marked, self.profile, self.key_a),
            score_rows(shuffled, self.profile, self.key_a),
        )

    def test_survives_row_deletion(self) -> None:
        marked = self.embed(self.key_a)
        kept = [row for row in marked if random.Random(9).random() > 0.15]
        score = score_rows(kept, self.profile, self.key_a)
        self.assertGreater(score.carriers, 100)
        self.assertLess(score.p_value, 1e-30)

    def test_survives_cell_mutation(self) -> None:
        marked = self.embed(self.key_a)
        mutate_cells(marked, 0.05, seed=11)
        score = score_rows(marked, self.profile, self.key_a)
        self.assertGreater(score.match_rate, 0.9)
        self.assertLess(score.p_value, 1e-30)

    def test_survives_combined_attack(self) -> None:
        marked = self.embed(self.key_a)
        random.Random(13).shuffle(marked)
        kept = [row for row in marked if random.Random(14).random() > 0.10]
        mutate_cells(kept, 0.03, seed=15)
        score = score_rows(kept, self.profile, self.key_a)
        self.assertLess(score.p_value, 1e-30)

    def test_two_batches_do_not_overwrite_each_other(self) -> None:
        marked_a = self.embed(self.key_a)
        marked_b = self.embed(self.key_b)
        score_aa = score_rows(marked_a, self.profile, self.key_a)
        score_ab = score_rows(marked_a, self.profile, self.key_b)
        score_bb = score_rows(marked_b, self.profile, self.key_b)
        score_ba = score_rows(marked_b, self.profile, self.key_a)
        self.assertLess(score_aa.p_value, 1e-30)
        self.assertLess(score_bb.p_value, 1e-30)
        self.assertGreater(score_ab.p_value, 1e-3)
        self.assertGreater(score_ba.p_value, 1e-3)

    def test_unmarked_data_is_not_significant(self) -> None:
        score = score_rows(self.rows, self.profile, self.key_a)
        self.assertGreater(score.p_value, 1e-3)

    def test_format_and_checksums_stay_valid(self) -> None:
        marked = self.embed(self.key_a)
        assert self.profile.checksum is not None
        self.assertEqual(len(marked), len(self.rows))
        self.assertEqual(
            [row["order_id"] for row in marked],
            [row["order_id"] for row in self.rows],
        )
        for row in marked:
            self.assertEqual(
                row["row_crc"], compute_checksum(self.profile.checksum, row)
            )
            self.assertEqual(len(row["amount"].split(".")[1]), 2)
            self.assertEqual(len(row["discount"].split(".")[1]), 2)
            self.assertGreaterEqual(float(row["amount"]), 0)
            self.assertLessEqual(float(row["discount"]), 1)
            self.assertGreaterEqual(int(row["quantity"]), 0)
            self.assertIn(row["channel"], {"线上", "在线", "线下", "电话"})

    def test_marks_stay_inside_markable_columns(self) -> None:
        marked = self.embed(self.key_a)
        markable = {column.name for column in self.profile.columns}
        markable.add(self.profile.checksum.name)  # type: ignore[union-attr]
        for before, after in zip(self.rows, marked):
            for name, value in before.items():
                if name not in markable:
                    self.assertEqual(value, after[name])


class CellConstraintTest(unittest.TestCase):
    def test_numeric_bit_preserves_decimals(self) -> None:
        column = ColumnMark(name="v", kind="numeric")
        self.assertEqual(write_bit(column, "12.30", 1), "12.31")
        self.assertEqual(write_bit(column, "12.31", 1), "12.31")
        self.assertEqual(write_bit(column, "7", 1), "7")
        self.assertEqual(write_bit(column, "8", 1), "9")

    def test_numeric_bit_respects_bounds(self) -> None:
        column = ColumnMark(name="v", kind="numeric", minimum=0, maximum=0)
        self.assertIsNone(write_bit(column, "0", 1))
        floored = ColumnMark(name="v", kind="numeric", minimum=0)
        self.assertEqual(write_bit(floored, "0", 1), "1")

    def test_numeric_bit_respects_relative_tolerance(self) -> None:
        column = ColumnMark(name="v", kind="numeric", rel_tol=1e-6)
        self.assertIsNone(write_bit(column, "10000", 1))
        allowed = ColumnMark(name="v", kind="numeric", rel_tol=0.01)
        self.assertEqual(write_bit(allowed, "10000", 1), "10001")

    def test_unparseable_cells_are_left_alone(self) -> None:
        column = ColumnMark(name="v", kind="numeric")
        self.assertIsNone(write_bit(column, "N/A", 1))
        self.assertIsNone(write_bit(column, "", 1))

    def test_category_bit_swaps_synonyms(self) -> None:
        column = ColumnMark(name="c", kind="category", pairs={"线上": "在线"})
        self.assertEqual(write_bit(column, "线上", 1), "在线")
        self.assertEqual(write_bit(column, "在线", 0), "线上")
        self.assertEqual(write_bit(column, "线上", 0), "线上")
        self.assertIsNone(write_bit(column, "线下", 1))


class ReportSealTest(unittest.TestCase):
    def test_seal_verify_and_tamper(self) -> None:
        key = b"report-key" * 3
        body = {"report_id": "wr1", "verdict": "命中", "p": 1e-9}
        document = seal(body, key)
        self.assertTrue(verify_document(document, key))
        tampered = json.loads(json.dumps(document))
        tampered["body"]["verdict"] = "无显著匹配"
        self.assertFalse(verify_document(tampered, key))
        self.assertFalse(verify_document(document, b"other-key" * 3))


class ConsoleFlowTest(unittest.TestCase):
    """Full flow through the HTTP router: register, export, leak, detect."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        store = RecordStore(self._tmp.name)
        store.load()
        self.runtime = build_runtime(store)
        self.router = build_router(self.runtime)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def call(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload else b""
        try:
            response = self.router.dispatch(
                Request(method=method, path=path, query={}, headers={}, body=body)
            )
        except Exception as exc:  # mirror the server boundary
            response = error_response(exc)
        return response.status, json.loads(response.payload.decode("utf-8"))

    def register_dataset(self) -> None:
        status, _ = self.call(
            "POST",
            "/sources",
            {"identifier": "warehouse", "kind": "rdbms", "endpoint": "db://1"},
        )
        self.assertEqual(status, 200)
        status, _ = self.call(
            "POST",
            "/datasets",
            {
                "identifier": "orders",
                "source": "warehouse",
                "owner": "data-team",
                "fields": [{"name": "amount", "sensitivity": "public"}],
            },
        )
        self.assertEqual(status, 200)
        status, _ = self.call("POST", "/watermark/profile", PROFILE_DICT)
        self.assertEqual(status, 200)

    def test_export_then_detect_leaked_copy(self) -> None:
        self.register_dataset()
        rows = make_rows(1500)

        exports = {}
        for recipient in ("甲方-仓储", "乙方-物流"):
            status, payload = self.call(
                "POST",
                "/watermark/export",
                {"dataset": "orders", "recipient": recipient, "rows": rows},
            )
            self.assertEqual(status, 200)
            exports[recipient] = payload

        # 乙方副本疑似泄露：调序 + 删 10% 行 + 改 3% 单元格
        leaked = copy.deepcopy(exports["乙方-物流"]["rows"])
        random.Random(21).shuffle(leaked)
        leaked = [row for row in leaked if random.Random(22).random() > 0.10]
        mutate_cells(leaked, 0.03, seed=23)

        status, report = self.call(
            "POST", "/watermark/detect", {"dataset": "orders", "rows": leaked}
        )
        self.assertEqual(status, 200)
        body = report["body"]
        self.assertEqual(body["verdict"], "命中")
        self.assertEqual(
            body["hit_batch_id"], exports["乙方-物流"]["batch"]["batch_id"]
        )
        self.assertEqual(body["hit_confidence"], "极高")
        hit = body["candidates"][0]
        self.assertEqual(hit["recipient"], "乙方-物流")

        # 报告可通过验签；脱敏版不含接收方且验签仍通过
        status, check = self.call(
            "POST",
            "/watermark/report/verify",
            {"report_id": body["report_id"]},
        )
        self.assertTrue(check["valid"])
        status, redacted = self.call(
            "POST", "/watermark/report/redact", {"report_id": body["report_id"]}
        )
        self.assertEqual(status, 200)
        recipients = json.dumps(redacted["body"], ensure_ascii=False)
        self.assertNotIn("乙方-物流", recipients)
        self.assertNotIn("甲方-仓储", recipients)
        status, check = self.call(
            "POST", "/watermark/report/verify", {"report": redacted}
        )
        self.assertTrue(check["valid"])

    def test_detect_rejects_unknown_dataset(self) -> None:
        self.register_dataset()
        status, _ = self.call(
            "POST", "/watermark/detect", {"dataset": "ghost", "rows": make_rows(5)}
        )
        self.assertEqual(status, 404)

    def test_pristine_data_has_no_match(self) -> None:
        self.register_dataset()
        rows = make_rows(1500)
        status, _ = self.call(
            "POST",
            "/watermark/export",
            {"dataset": "orders", "recipient": "甲方-仓储", "rows": rows},
        )
        self.assertEqual(status, 200)
        status, report = self.call(
            "POST", "/watermark/detect", {"dataset": "orders", "rows": rows}
        )
        self.assertEqual(report["body"]["verdict"], "无显著匹配")


if __name__ == "__main__":
    unittest.main()
