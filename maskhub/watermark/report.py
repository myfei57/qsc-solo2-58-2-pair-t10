"""Signed evidence reports for watermark recovery conclusions.

A report states which export batch a suspect copy matches, with the
carrier/match counts, the random-coincidence probability (binomial
p-value) and a confidence label, plus the suspect file's digest so the
archive is bound to the exact evidence.  Reports are sealed with an
HMAC under a derived signing key, so any later tampering is detectable
and the conclusion can be re-verified at audit time.

The statement never names the recipient; the recipient appears only in
the internal candidate list.  ``redact_document`` produces an external
copy with recipients stripped, re-sealed so its integrity still checks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass

from maskhub.errors import NotFound
from maskhub.store.kvstore import RecordStore

PREFIX = "wmreport."
ALGORITHM = "HMAC-SHA256(canonical-json body)"
TOP_CANDIDATES = 5

P_HIT = 1e-4
P_HIGH = 1e-6
P_MEDIUM = 1e-2

VERDICT_HIT = "命中"
VERDICT_NONE = "无显著匹配"
VERDICT_THIN = "样本不足"
VERDICT_EMPTY = "无候选批次"


@dataclass(frozen=True)
class CandidateScore:
    batch_id: str
    recipient: str
    created_at: str
    carriers: int
    matches: int
    match_rate: float
    p_value: float
    confidence: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def confidence_label(p_value: float, carriers: int, min_carriers: int) -> str:
    if carriers < min_carriers:
        return "样本不足"
    if p_value < P_HIGH:
        return "极高"
    if p_value < P_HIT:
        return "高"
    if p_value < P_MEDIUM:
        return "中"
    return "不显著"


def build_body(
    report_id: str,
    generated_at: str,
    dataset: str,
    suspect_sha256: str,
    suspect_rows: int,
    candidates: list[CandidateScore],
    min_carriers: int,
) -> dict[str, object]:
    ranked = sorted(candidates, key=lambda item: item.p_value)
    best = ranked[0] if ranked else None
    verdict, hit_batch_id, hit_confidence = _verdict(best, min_carriers)
    statement = _statement(verdict, best, ranked, min_carriers)
    return {
        "report_id": report_id,
        "generated_at": generated_at,
        "dataset": dataset,
        "suspect": {"sha256": suspect_sha256, "rows": suspect_rows},
        "parameters": {"min_carriers": min_carriers, "p_hit": P_HIT},
        "candidates_tested": len(ranked),
        "candidates": [item.as_dict() for item in ranked[:TOP_CANDIDATES]],
        "verdict": verdict,
        "hit_batch_id": hit_batch_id,
        "hit_confidence": hit_confidence,
        "statement": statement,
        "redacted": False,
    }


def _verdict(
    best: CandidateScore | None, min_carriers: int
) -> tuple[str, str, str]:
    if best is None:
        return VERDICT_EMPTY, "", ""
    if best.carriers < min_carriers:
        return VERDICT_THIN, "", "样本不足"
    if best.p_value < P_HIT:
        return VERDICT_HIT, best.batch_id, best.confidence
    return VERDICT_NONE, "", best.confidence


def _statement(
    verdict: str,
    best: CandidateScore | None,
    ranked: list[CandidateScore],
    min_carriers: int,
) -> str:
    if best is None:
        return "登记簿中没有可比对的外发批次，无法出具结论。"
    if verdict == VERDICT_THIN:
        return (
            f"检材中可识别的水印载体仅 {best.carriers} 个"
            f"（要求不少于 {min_carriers} 个），证据力不足，需补充更多数据行。"
        )
    if verdict == VERDICT_NONE:
        return (
            f"检材与登记簿中 {len(ranked)} 个外发批次均无显著水印匹配"
            f"（最优随机巧合概率 p={best.p_value:.2e}），"
            "无法认定其源自本案登记的外发。"
        )
    statement = (
        f"检材与批次 {best.batch_id}（导出于 {best.created_at}）的水印指纹匹配："
        f"载体 {best.carriers} 个，命中 {best.matches} 个"
        f"（{best.match_rate:.1%}），随机巧合概率 p={best.p_value:.2e}，"
        f"置信度{best.confidence}。"
    )
    if len(ranked) > 1 and ranked[1].p_value < P_MEDIUM:
        statement += "注意：次优批次亦达到显著水平，建议结合导出日志复核。"
    return statement


# ---------------------------------------------------------------------------
# sealing / verification / redaction
# ---------------------------------------------------------------------------


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def sign_body(body: dict[str, object], key: bytes) -> str:
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()


def seal(body: dict[str, object], key: bytes) -> dict[str, object]:
    return {"algorithm": ALGORITHM, "body": body, "signature": sign_body(body, key)}


def verify_document(document: object, key: bytes) -> bool:
    if not isinstance(document, dict):
        return False
    body = document.get("body")
    signature = document.get("signature")
    if not isinstance(body, dict) or not isinstance(signature, str):
        return False
    return hmac.compare_digest(sign_body(body, key), signature)


def redact_document(
    document: dict[str, object], report_id: str, generated_at: str, key: bytes
) -> dict[str, object]:
    """External copy: recipients stripped, re-sealed under the same key."""
    body = document.get("body")
    if not isinstance(body, dict):
        raise ValueError("report document has no body")
    redacted_body = json.loads(canonical(body))
    redacted_body["report_id"] = report_id
    redacted_body["generated_at"] = generated_at
    redacted_body["redacted"] = True
    redacted_body["redacted_from"] = body.get("report_id", "")
    for candidate in redacted_body.get("candidates", []):
        if isinstance(candidate, dict):
            candidate["recipient"] = "***"
    return seal(redacted_body, key)


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------


def report_key(report_id: str) -> str:
    return PREFIX + report_id


class ReportRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def save(self, report_id: str, document: dict[str, object]) -> None:
        self._store.put_json(report_key(report_id), document)

    def get(self, report_id: str) -> dict[str, object]:
        document = self._store.get_json(report_key(report_id))
        if not isinstance(document, dict):
            raise NotFound(f"unknown evidence report {report_id}")
        return document

    def all(self) -> list[dict[str, object]]:
        from maskhub.store.query import keys_with_prefix

        return [
            self.get(key[len(PREFIX):])
            for key in keys_with_prefix(self._store, PREFIX)
        ]
