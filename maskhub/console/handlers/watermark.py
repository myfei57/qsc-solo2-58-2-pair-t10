"""Watermark export and recovery endpoints."""

from __future__ import annotations

from typing import Any

from maskhub.console.http import Request, Response
from maskhub.console.validation import optional_text, require_text, require_text_list
from maskhub.errors import InvalidRequest
from maskhub.watermark import CarrierField, prepare_export


def prepare(runtime, request: Request) -> Response:
    payload = request.json_object()
    rows = _require_rows(payload.get("rows"))
    dataset = require_text(payload, "dataset")
    anchors = tuple(require_text_list(payload, "anchor_fields"))
    carriers = _parse_carriers(payload.get("carriers"))
    protected = _parse_protected_slots(payload.get("protected_slots"))

    prepared = prepare_export(
        rows,
        dataset=dataset,
        anchor_fields=anchors,
        carriers=carriers,
        batch_id=optional_text(payload, "batch_id") or None,
        protected_slots=protected,
    )
    runtime.watermarks.save(prepared.record)
    runtime.journal.append(
        "watermark.export",
        prepared.record.batch_id,
        f"dataset={dataset}; cells={prepared.changed_cells}",
    )
    return Response.json(
        200,
        {
            "batch_id": prepared.record.batch_id,
            "rows": prepared.rows,
            "output_sha256": prepared.output_sha256,
            "input_sha256": prepared.record.input_sha256,
            "changed_cells": prepared.changed_cells,
            "slot_count": len(prepared.record.slots),
        },
    )


def batches(runtime, request: Request) -> Response:
    items = runtime.watermarks.list_public()
    return Response.json(200, {"count": len(items), "batches": items})


def detect(runtime, request: Request) -> Response:
    payload = request.json_object()
    rows = _require_rows(payload.get("rows"))
    dataset = optional_text(payload, "dataset") or None
    case_id = optional_text(payload, "case_id") or None
    analyst = optional_text(payload, "analyst")
    save = bool(payload.get("save", False))
    signed = runtime.watermarks.detect(
        rows,
        dataset=dataset,
        case_id=case_id,
        analyst=analyst,
        save=save,
    )
    runtime.journal.append(
        "watermark.detect",
        case_id or signed.report["case_id"],
        f"status={signed.report['conclusion']['status']}; analyst={analyst}",
    )
    return Response.json(200, signed.as_dict())


def _require_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or any(not isinstance(row, dict) for row in value):
        raise InvalidRequest("rows must be a non-empty list of objects")
    return value


def _parse_carriers(value: Any) -> tuple[CarrierField, ...]:
    if not isinstance(value, list) or not value:
        raise InvalidRequest("carriers must be a non-empty list")
    try:
        return tuple(CarrierField.from_value(item) for item in value)
    except ValueError as exc:
        raise InvalidRequest(str(exc)) from exc


def _parse_protected_slots(value: Any) -> dict[str, set[str]] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InvalidRequest("protected_slots must be an object")
    protected: dict[str, set[str]] = {}
    for field, keys in value.items():
        if not isinstance(field, str) or not field.strip():
            raise InvalidRequest("protected_slots field names must be strings")
        if not isinstance(keys, list) or any(not isinstance(item, str) for item in keys):
            raise InvalidRequest("protected_slots values must be lists of row keys")
        protected[field.strip()] = set(keys)
    return protected
