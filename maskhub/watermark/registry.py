"""Private registry and sealed evidence reports for watermark batches."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from maskhub.errors import Conflict, NotFound
from maskhub.store.kvstore import RecordStore
from maskhub.store.query import keys_with_prefix
from maskhub.watermark import BatchRecord, DetectionResult, canonical_json, detect_watermark

BATCH_PREFIX = "watermark.batch."
REPORT_PREFIX = "watermark.report."
DEFAULT_KEY_ENV = "MASKHUB_WATERMARK_KEY"
LOGGER = logging.getLogger("maskhub.watermark")


@dataclass(frozen=True)
class SignedReport:
    report: dict[str, Any]
    signature_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {"report": self.report, "signature_sha256": self.signature_sha256}


class WatermarkRegistry:
    def __init__(self, store: RecordStore, signing_key: bytes | str | None = None) -> None:
        self._store = store
        self._signing_key = _coerce_key(signing_key)

    def save(self, record: BatchRecord) -> BatchRecord:
        key = batch_key(record.batch_id)
        if self._store.has(key):
            raise Conflict(f"watermark batch {record.batch_id} already exists")
        self._store.put_json(key, record.as_dict())
        return record

    def find(self, batch_id: str) -> BatchRecord | None:
        return BatchRecord.from_dict(self._store.get_json(batch_key(batch_id)))

    def get(self, batch_id: str) -> BatchRecord:
        record = self.find(batch_id)
        if record is None:
            raise NotFound(f"unknown watermark batch {batch_id}")
        return record

    def all(self) -> list[BatchRecord]:
        records = []
        for key in keys_with_prefix(self._store, BATCH_PREFIX):
            record = BatchRecord.from_dict(self._store.get_json(key))
            if record is not None:
                records.append(record)
        records.sort(key=lambda item: (item.created_at, item.batch_id))
        return records

    def list_public(self) -> list[dict[str, Any]]:
        return [record.public_dict() for record in self.all()]

    def detect(
        self,
        rows: list[dict[str, Any]],
        *,
        dataset: str | None = None,
        case_id: str | None = None,
        analyst: str = "",
        save: bool = False,
    ) -> SignedReport:
        records = self.all()
        if dataset is not None:
            records = [record for record in records if record.dataset == dataset]
        result = detect_watermark(rows, records)
        report_id = case_id or secrets.token_hex(16)
        report = {
            "case_id": report_id,
            "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "analyst": analyst,
            "scope": {"dataset": dataset, "batches_tested": result.tested_batches},
            "conclusion": result.as_dict(),
            "recipient": None,
        }
        signed = self.sign(report)
        if save:
            self._store.put_json(report_key(report_id), signed.as_dict())
        return signed

    def sign(self, report: dict[str, Any]) -> SignedReport:
        payload = canonical_json(report).encode("utf-8")
        signature = hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()
        return SignedReport(report=report, signature_sha256=signature)

    def verify(self, signed: SignedReport | dict[str, Any]) -> bool:
        if isinstance(signed, SignedReport):
            candidate = signed
        else:
            if not isinstance(signed, dict):
                return False
            report = signed.get("report")
            signature = signed.get("signature_sha256")
            if not isinstance(report, dict) or not isinstance(signature, str):
                return False
            candidate = SignedReport(report=report, signature_sha256=signature)
        expected = self.sign(candidate.report).signature_sha256
        return hmac.compare_digest(expected, candidate.signature_sha256)


def batch_key(batch_id: str) -> str:
    return BATCH_PREFIX + batch_id


def report_key(case_id: str) -> str:
    return REPORT_PREFIX + case_id


def _coerce_key(key: bytes | str | None) -> bytes:
    if key is None:
        import os

        raw = os.environ.get(DEFAULT_KEY_ENV, "")
        if raw:
            key = raw
        else:
            # Development fallback.  Production should provide a stable key in
            # the environment or a managed secret store.
            LOGGER.warning("MASKHUB_WATERMARK_KEY is not set; generated an ephemeral evidence key")
            key = secrets.token_bytes(32)
    if isinstance(key, str):
        try:
            value = bytes.fromhex(key.strip())
        except ValueError as exc:
            raise ValueError("watermark signing key must be 64 hex characters") from exc
    else:
        value = key
    if len(value) != 32:
        raise ValueError("watermark signing key must be 32 bytes")
    return value
