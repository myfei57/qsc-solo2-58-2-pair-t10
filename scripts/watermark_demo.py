"""端到端演示：外发水印的嵌入、泄露还原与证据报告。

运行：python3 scripts/watermark_demo.py
"""

from __future__ import annotations

import copy
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from maskhub.console.errors import error_response
from maskhub.console.http import Request
from maskhub.console.routes import build_router
from maskhub.console.runtime import build_runtime
from maskhub.store.kvstore import RecordStore
from maskhub.watermark.core import compute_checksum

PROFILE = {
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


def make_orders(count: int = 1500, seed: int = 7) -> list[dict[str, str]]:
    rng = random.Random(seed)
    rows = []
    for index in range(count):
        row = {
            "order_id": f"SO{index:06d}",
            "amount": f"{rng.uniform(1, 9999):.2f}",
            "quantity": str(rng.randint(1, 50)),
            "discount": f"{rng.uniform(0, 0.3):.2f}",
            "channel": rng.choice(["线上", "线下", "电话"]),
        }
        rows.append(row)
    return rows


class Demo:
    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        store = RecordStore(self._tmp.name)
        store.load()
        self.runtime = build_runtime(store)
        self.router = build_router(self.runtime)

    def call(self, method: str, path: str, payload: dict | None = None) -> dict:
        body = json.dumps(payload, ensure_ascii=False).encode() if payload else b""
        try:
            response = self.router.dispatch(
                Request(method=method, path=path, query={}, headers={}, body=body)
            )
        except Exception as exc:
            response = error_response(exc)
        result = json.loads(response.payload.decode())
        if response.status != 200:
            raise SystemExit(f"{method} {path} 失败: {result}")
        return result


def section(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(2, 60 - len(title) * 2))


def main() -> None:
    demo = Demo()

    section("1. 登记数据集与水印档案")
    demo.call("POST", "/sources", {"identifier": "warehouse", "kind": "rdbms", "endpoint": "db://1"})
    demo.call("POST", "/datasets", {
        "identifier": "orders", "source": "warehouse", "owner": "data-team",
        "fields": [{"name": "amount", "sensitivity": "public"}],
    })
    demo.call("POST", "/watermark/profile", PROFILE)
    print("数据集 orders 已登记，水印档案：4 个可标记列，行校验列 row_crc")

    section("2. 同一份母版数据两次外发（各自嵌入独立水印）")
    master = make_orders()
    checksum_spec = PROFILE["checksum"]
    for row in master:
        row["row_crc"] = compute_checksum(
            demo.runtime.profiles.get("orders").checksum, row  # type: ignore[arg-type]
        )
    exports = {}
    for recipient in ("甲方-仓储", "乙方-物流"):
        result = demo.call("POST", "/watermark/export", {
            "dataset": "orders", "recipient": recipient, "rows": master,
        })
        batch = result["batch"]
        stats = result["stats"]
        exports[recipient] = result
        profile = demo.runtime.profiles.get("orders")
        bad_crc = sum(
            1 for row in result["rows"]
            if row["row_crc"] != compute_checksum(profile.checksum, row)  # type: ignore[arg-type]
        )
        print(
            f"  {recipient}: 批次 {batch['batch_id']}，载体 {stats['carriers']} 行，"
            f"改写 {stats['cells_changed']} 个单元格，行校验异常 {bad_crc} 个"
        )
    changed_a = sum(
        1 for before, after in zip(master, exports["甲方-仓储"]["rows"]) if before != after
    )
    print(f"  甲方副本与母版相比仅 {changed_a}/{len(master)} 行有细微改动（末位级别）")

    section("3. 模拟泄露：乙方副本被调序、删行、篡改后流出")
    leaked = copy.deepcopy(exports["乙方-物流"]["rows"])
    random.Random(99).shuffle(leaked)
    drop_rng = random.Random(98)
    leaked = [row for row in leaked if drop_rng.random() > 0.10]
    rng = random.Random(97)
    tampered = 0
    for row in leaked:
        if rng.random() < 0.03:
            row["amount"] = f"{float(row['amount']) + rng.uniform(-0.9, 0.9):.2f}"
            tampered += 1
    print(f"  泄露副本：剩余 {len(leaked)} 行（删 10%），篡改 amount 单元格 {tampered} 个，行序打乱")

    section("4. 对泄露副本做水印还原")
    report = demo.call("POST", "/watermark/detect", {"dataset": "orders", "rows": leaked})
    body = report["body"]
    print(f"  结论：{body['verdict']}（置信度{body['hit_confidence']}）")
    print(f"  陈述：{body['statement']}")
    print("  候选排名：")
    for item in body["candidates"]:
        print(
            f"    批次 {item['batch_id']}（{item['recipient']}）"
            f" 命中 {item['matches']}/{item['carriers']}，p={item['p_value']:.2e}"
        )

    section("5. 对照：未外发的母版数据不应命中任何批次")
    control = demo.call("POST", "/watermark/detect", {"dataset": "orders", "rows": master})
    print(f"  结论：{control['body']['verdict']}")
    print(f"  陈述：{control['body']['statement']}")

    section("6. 证据报告：验签 + 对外脱敏版")
    check = demo.call("POST", "/watermark/report/verify", {"report_id": body["report_id"]})
    print(f"  内部报告 {body['report_id']} 验签：{'通过' if check['valid'] else '失败'}")
    redacted = demo.call("POST", "/watermark/report/redact", {"report_id": body["report_id"]})
    rid = redacted["body"]["report_id"]
    check = demo.call("POST", "/watermark/report/verify", {"report_id": rid})
    leaked_names = json.dumps(redacted["body"], ensure_ascii=False)
    assert "乙方-物流" not in leaked_names and "甲方-仓储" not in leaked_names
    print(f"  对外报告 {rid} 验签：{'通过' if check['valid'] else '失败'}，接收方已脱敏")
    print(f"\n演示数据目录：{demo._tmp.name}（含登记簿、批次记录、签名报告、审计日志）")


if __name__ == "__main__":
    main()
