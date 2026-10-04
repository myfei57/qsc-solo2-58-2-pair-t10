"""Watermark endpoints: profiles, export embedding, leak recovery, evidence."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from maskhub.console.http import Request, Response
from maskhub.console.validation import optional_text, require_text
from maskhub.errors import InvalidRequest, NotFound
from maskhub.watermark.batch import ExportBatch
from maskhub.watermark.core import embed_rows, score_rows
from maskhub.watermark.profile import WatermarkProfile
from maskhub.watermark.report import (
    CandidateScore,
    build_body,
    confidence_label,
    redact_document,
    seal,
    verify_document,
)


def save_profile(runtime, request: Request) -> Response:
    profile = WatermarkProfile.from_dict(request.json_object())
    if profile is None:
        raise InvalidRequest("invalid watermark profile")
    runtime.datasets.get(profile.dataset)
    runtime.profiles.save(profile)
    runtime.journal.append("watermark.profile", profile.dataset)
    return Response.json(200, profile.as_dict())


def list_profiles(runtime, request: Request) -> Response:
    profiles = [profile.as_dict() for profile in runtime.profiles.all()]
    return Response.json(200, {"count": len(profiles), "profiles": profiles})


def export_dataset(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    recipient = require_text(payload, "recipient")
    note = optional_text(payload, "note")
    runtime.datasets.get(dataset)
    profile = runtime.profiles.get(dataset)
    rows = _rows_from(payload)

    batch_id = "wm" + secrets.token_hex(6)
    watermarked = [dict(row) for row in rows]
    stats = embed_rows(watermarked, profile, runtime.keyring.batch_key(batch_id))
    batch = ExportBatch(
        batch_id=batch_id,
        dataset=dataset,
        recipient=recipient,
        created_at=_now(),
        rows=stats.rows,
        carriers=stats.carriers,
        cells_changed=stats.cells_changed,
        source_sha256=_rows_digest(rows),
        output_sha256=_rows_digest(watermarked),
        note=note,
    )
    runtime.batches.save(batch)
    runtime.journal.append("watermark.export", batch_id, f"{dataset} -> {recipient}")
    return Response.json(
        200, {"batch": batch.as_dict(), "stats": stats.as_dict(), "rows": watermarked}
    )


def detect_leak(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset = require_text(payload, "dataset")
    profile = runtime.profiles.get(dataset)
    rows = _rows_from(payload)

    batches = runtime.batches.by_dataset(dataset)
    only = optional_text(payload, "batch_id")
    if only:
        batches = [batch for batch in batches if batch.batch_id == only]
        if not batches:
            raise NotFound(f"unknown export batch {only}")
    if not batches:
        raise NotFound(f"no export batches for dataset {dataset!r}")

    candidates = []
    for batch in batches:
        score = score_rows(rows, profile, runtime.keyring.batch_key(batch.batch_id))
        candidates.append(
            CandidateScore(
                batch_id=batch.batch_id,
                recipient=batch.recipient,
                created_at=batch.created_at,
                carriers=score.carriers,
                matches=score.matches,
                match_rate=round(score.match_rate, 6),
                p_value=score.p_value,
                confidence=confidence_label(
                    score.p_value, score.carriers, profile.min_carriers
                ),
            )
        )

    report_id = "wr" + secrets.token_hex(6)
    body = build_body(
        report_id=report_id,
        generated_at=_now(),
        dataset=dataset,
        suspect_sha256=_rows_digest(rows),
        suspect_rows=len(rows),
        candidates=candidates,
        min_carriers=profile.min_carriers,
    )
    document = seal(body, runtime.keyring.report_key())
    runtime.reports.save(report_id, document)
    runtime.journal.append(
        "watermark.detect", report_id, f"{dataset} verdict={body['verdict']}"
    )
    return Response.json(200, document)


def list_batches(runtime, request: Request) -> Response:
    dataset = request.query_one("dataset")
    batches = (
        runtime.batches.by_dataset(dataset) if dataset else runtime.batches.all()
    )
    return Response.json(
        200, {"count": len(batches), "batches": [b.as_dict() for b in batches]}
    )


def get_report(runtime, request: Request) -> Response:
    report_id = request.query_one("report_id", "") or ""
    return Response.json(200, runtime.reports.get(report_id))


def redact_report(runtime, request: Request) -> Response:
    payload = request.json_object()
    report_id = require_text(payload, "report_id")
    document = runtime.reports.get(report_id)
    new_id = "wr" + secrets.token_hex(6)
    redacted = redact_document(document, new_id, _now(), runtime.keyring.report_key())
    runtime.reports.save(new_id, redacted)
    runtime.journal.append("watermark.redact", new_id, f"from {report_id}")
    return Response.json(200, redacted)


def verify_report(runtime, request: Request) -> Response:
    payload = request.json_object()
    report_id = optional_text(payload, "report_id")
    if report_id:
        document: Any = runtime.reports.get(report_id)
    else:
        document = payload.get("report")
        if not isinstance(document, dict):
            raise InvalidRequest("report_id or a report document is required")
    valid = verify_document(document, runtime.keyring.report_key())
    body = document.get("body", {}) if isinstance(document, dict) else {}
    return Response.json(
        200, {"valid": valid, "report_id": body.get("report_id", "")}
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _rows_from(payload: dict[str, Any]) -> list[dict[str, str]]:
    raw = payload.get("rows")
    if not isinstance(raw, list) or not raw:
        raise InvalidRequest("rows must be a non-empty list")
    rows: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise InvalidRequest("each row must be an object")
        rows.append({str(key): _cell_text(value) for key, value in item.items()})
    return rows


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _rows_digest(rows: list[dict[str, str]]) -> str:
    canonical = json.dumps(
        rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
