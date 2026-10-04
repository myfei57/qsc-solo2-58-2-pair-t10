"""Robust, row-order independent watermarks for tabular exports.

The mark is embedded in tolerable numeric changes chosen by a keyed
pseudo-random function.  Repeatedly observing the same stable row key always
selects the same cell, so shuffling rows does not affect detection.  Every
candidate carries a PRF-selected bit; recovery takes a majority vote and uses
a one-sided binomial score to quantify confidence.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from typing import Any, Literal

from maskhub.errors import InvalidRequest

Confidence = Literal["inconclusive", "weak", "strong", "confirmed"]
MIN_SLOT_COUNT = 24


class WatermarkError(InvalidRequest):
    """Raised when an export cannot carry a usable watermark."""


@dataclass(frozen=True)
class CarrierField:
    """A numeric field and the largest business-acceptable adjustment."""

    name: str
    tolerance: str = "1"
    min_value: str | None = None
    max_value: str | None = None
    slots: int | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("carrier field name is required")
        tolerance = _decimal(self.tolerance, "tolerance")
        if tolerance <= 0:
            raise ValueError("tolerance must be positive")
        if self.slots is not None and self.slots <= 0:
            raise ValueError("slots must be positive")
        minimum = _optional_decimal(self.min_value, "min_value")
        maximum = _optional_decimal(self.max_value, "max_value")
        if minimum is not None and maximum is not None and minimum > maximum:
            raise ValueError("min_value cannot exceed max_value")

    @property
    def quantum(self) -> Decimal:
        # One QIM step.  Nearest correctly-parity lattice point is at most
        # ``tolerance`` away and later edits under half a step are tolerated.
        return _decimal(self.tolerance, "tolerance")

    @property
    def lower(self) -> Decimal | None:
        return _optional_decimal(self.min_value, "min_value")

    @property
    def upper(self) -> Decimal | None:
        return _optional_decimal(self.max_value, "max_value")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_value(cls, value: Any) -> "CarrierField":
        if isinstance(value, CarrierField):
            return value
        if isinstance(value, str):
            return cls(name=value)
        if not isinstance(value, dict):
            raise ValueError("carrier must be a field name or object")
        try:
            return cls(
                name=value["name"],
                tolerance=str(value.get("tolerance", "1")),
                min_value=_none_if_missing(value.get("min_value")),
                max_value=_none_if_missing(value.get("max_value")),
                slots=value.get("slots"),
            )
        except KeyError as exc:
            raise ValueError(f"carrier {exc.args[0]} is required") from exc


@dataclass(frozen=True)
class Slot:
    field: str
    row_key: str
    expected_bit: int
    tolerance: str
    dither: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "Slot | None":
        if not isinstance(payload, dict):
            return None
        field = payload.get("field")
        row_key = payload.get("row_key")
        bit = payload.get("expected_bit")
        tolerance = payload.get("tolerance")
        dither = payload.get("dither")
        if not isinstance(field, str) or not isinstance(row_key, str):
            return None
        if not isinstance(tolerance, str) or not isinstance(dither, str) or bit not in (0, 1):
            return None
        return cls(
            field=field,
            row_key=row_key,
            expected_bit=bit,
            tolerance=tolerance,
            dither=dither,
        )


@dataclass(frozen=True)
class BatchRecord:
    batch_id: str
    dataset: str
    secret: str
    anchor_fields: tuple[str, ...]
    carriers: tuple[CarrierField, ...]
    slots: tuple[Slot, ...]
    input_sha256: str
    created_at: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "dataset": self.dataset,
            "anchor_fields": list(self.anchor_fields),
            "carriers": [carrier.as_dict() for carrier in self.carriers],
            "slot_count": len(self.slots),
            "input_sha256": self.input_sha256,
            "created_at": self.created_at,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "dataset": self.dataset,
            "secret": self.secret,
            "anchor_fields": list(self.anchor_fields),
            "carriers": [carrier.as_dict() for carrier in self.carriers],
            "slots": [slot.as_dict() for slot in self.slots],
            "input_sha256": self.input_sha256,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: object) -> "BatchRecord | None":
        if not isinstance(payload, dict):
            return None
        batch_id = payload.get("batch_id")
        dataset = payload.get("dataset")
        secret = payload.get("secret")
        anchor_fields = payload.get("anchor_fields")
        carriers_payload = payload.get("carriers")
        slots_payload = payload.get("slots")
        input_sha256 = payload.get("input_sha256")
        created_at = payload.get("created_at")
        text_values = (batch_id, dataset, secret, input_sha256, created_at)
        if not all(isinstance(item, str) for item in text_values):
            return None
        if not isinstance(anchor_fields, list) or not isinstance(carriers_payload, list):
            return None
        if not isinstance(slots_payload, list) or not anchor_fields:
            return None
        try:
            anchors = tuple(_require_text(item) for item in anchor_fields)
            carriers = tuple(CarrierField.from_value(item) for item in carriers_payload)
            slots = tuple(
                item for item in (Slot.from_dict(raw) for raw in slots_payload) if item is not None
            )
            if len(slots) != len(slots_payload) or not carriers:
                return None
            return cls(
                batch_id=batch_id,
                dataset=dataset,
                secret=secret,
                anchor_fields=anchors,
                carriers=carriers,
                slots=slots,
                input_sha256=input_sha256,
                created_at=created_at,
            )
        except (ValueError, InvalidOperation):
            return None


@dataclass(frozen=True)
class PreparedBatch:
    record: BatchRecord
    rows: list[dict[str, Any]]
    output_sha256: str
    changed_cells: int


@dataclass(frozen=True)
class BatchMatch:
    batch_id: str
    dataset: str
    confidence: Confidence
    agreement: float
    successes: int
    observations: int
    capacity: int
    missing_rows: int
    p_value: float | None
    adjusted_p_value: float | None
    z_score: float | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionResult:
    status: Confidence
    candidate_count: int
    tested_batches: int
    matches: list[BatchMatch]
    input_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "candidate_count": self.candidate_count,
            "tested_batches": self.tested_batches,
            "matches": [match.as_dict() for match in self.matches],
            "input_sha256": self.input_sha256,
        }


def canonical_sha256(rows: list[dict[str, Any]]) -> str:
    """Hash row content independently of row order and dict insertion order."""

    digests = [
        hashlib.sha256(
            canonical_json(sorted(row.items(), key=lambda item: str(item[0]))).encode("utf-8")
        ).digest()
        for row in rows
    ]
    digests.sort()
    return hashlib.sha256(b"".join(digests)).hexdigest()


def canonical_json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def prepare_export(
    rows: list[dict[str, Any]],
    *,
    dataset: str,
    anchor_fields: list[str] | tuple[str, ...],
    carriers: list[CarrierField | str] | tuple[CarrierField | str, ...],
    batch_id: str | None = None,
    secret: bytes | str | None = None,
    protected_slots: dict[str, set[str]] | None = None,
    created_at: str | None = None,
) -> PreparedBatch:
    """Create a watermarked copy and a private batch record.

    ``protected_slots`` maps field name to row keys already used by marks in
    the same source file.  Independent clean exports do not need it; using it
    permits additive, non-overlapping marks in a chained file.
    """

    from datetime import datetime, timezone

    anchors = _validate_field_names(anchor_fields, "anchor_fields")
    carrier_fields = tuple(CarrierField.from_value(item) for item in carriers)
    if not carrier_fields:
        raise WatermarkError("at least one carrier field is required")
    carrier_names = {carrier.name for carrier in carrier_fields}
    if carrier_names.intersection(anchors):
        raise WatermarkError("anchor fields cannot also be carrier fields")
    _validate_rows(rows, anchors, carrier_names)

    secret_bytes = _coerce_secret(secret)
    record_id = (batch_id or secrets.token_hex(16)).strip()
    if not record_id:
        raise WatermarkError("batch id is required")
    timestamp = created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    input_digest = canonical_sha256(rows)

    anchor_seen: set[str] = set()
    anchor_duplicate: set[str] = set()
    for row in rows:
        key = row_key(row, anchors)
        if key is None:
            continue
        if key in anchor_seen:
            anchor_duplicate.add(key)
        anchor_seen.add(key)

    selected: list[Slot] = []
    changed = 0
    output = [dict(row) for row in rows]
    protected = protected_slots or {}

    for carrier in carrier_fields:
        field_protected = protected.get(carrier.name, set())
        candidates: list[tuple[bytes, str, int, Decimal | None]] = []
        for index, row in enumerate(rows):
            key = row_key(row, anchors)
            if key is None or key in anchor_duplicate or key in field_protected:
                continue
            value = numeric_cell(row.get(carrier.name))
            if value is None or not _within_bounds(value, carrier):
                continue
            score = _mac(secret_bytes, b"slot", dataset, record_id, carrier.name, key, str(index))
            candidates.append((score, key, index, value))
        candidates.sort(key=lambda item: item[0])

        target = carrier.slots
        if target is None:
            target = max(MIN_SLOT_COUNT, len(candidates) // 4)
        target = min(target, len(candidates))
        if target <= 0:
            raise WatermarkError(f"carrier {carrier.name!r} has no usable cells")

        field_slots: list[Slot] = []
        for _score, key, index, _value in candidates:
            if len(field_slots) >= target:
                break
            bit = int.from_bytes(
                _mac(secret_bytes, b"bit", dataset, record_id, carrier.name, key, str(index)),
                "big",
            ) & 1
            dither = _dither(
                secret_bytes,
                dataset,
                record_id,
                carrier.name,
                key,
                str(index),
                quantum=carrier.quantum,
            )
            row = output[index]
            encoded, did_change = encode_bit(
                row[carrier.name],
                bit,
                carrier.quantum,
                _decimal(carrier.tolerance, "tolerance"),
                dither,
            )
            if encoded is None:
                continue
            row[carrier.name] = encoded
            field_slots.append(
                Slot(
                    field=carrier.name,
                    row_key=key,
                    expected_bit=bit,
                    tolerance=carrier.tolerance,
                    dither=str(dither),
                )
            )
            changed += int(did_change)

        if len(field_slots) < min(MIN_SLOT_COUNT, len(candidates)):
            raise WatermarkError(
                f"carrier {carrier.name!r} only provides {len(field_slots)} usable cells"
            )
        selected.extend(field_slots)

    if len(selected) < MIN_SLOT_COUNT:
        raise WatermarkError(f"watermark needs at least {MIN_SLOT_COUNT} usable cells")

    record = BatchRecord(
        batch_id=record_id,
        dataset=dataset,
        secret=secret_bytes.hex(),
        anchor_fields=anchors,
        carriers=carrier_fields,
        slots=tuple(selected),
        input_sha256=input_digest,
        created_at=timestamp,
    )
    return PreparedBatch(
        record=record,
        rows=output,
        output_sha256=canonical_sha256(output),
        changed_cells=changed,
    )


def detect_watermark(
    rows: list[dict[str, Any]],
    records: list[BatchRecord],
    *,
    candidate_multiplier: int | None = None,
) -> DetectionResult:
    """Score all private batch records and return statistically ranked matches."""

    input_digest = canonical_sha256(rows)
    tests = candidate_multiplier if candidate_multiplier is not None else max(1, len(records))
    matches: list[BatchMatch] = []

    for record in records:
        rows_by_key: dict[str, dict[str, Any]] = {}
        duplicate: set[str] = set()
        for row in rows:
            key = row_key(row, record.anchor_fields)
            if key is None:
                continue
            if key in rows_by_key:
                duplicate.add(key)
            rows_by_key[key] = row

        carrier_by_name = {carrier.name: carrier for carrier in record.carriers}
        successes = 0
        observations = 0
        missing = 0
        for slot in record.slots:
            if slot.row_key in duplicate:
                continue
            row = rows_by_key.get(slot.row_key)
            if row is None:
                missing += 1
                continue
            carrier = carrier_by_name.get(slot.field)
            if carrier is None:
                missing += 1
                continue
            value = numeric_cell(row.get(slot.field))
            if value is None:
                missing += 1
                continue
            if extract_bit(value, carrier.quantum, Decimal(slot.dither)) == slot.expected_bit:
                successes += 1
            observations += 1

        if observations < MIN_SLOT_COUNT:
            continue
        p_value = binomial_tail(successes, observations)
        z_score = (successes - observations * 0.5) / (observations ** 0.5 / 2)
        adjusted = min(1.0, p_value * tests)
        agreement = successes / observations
        confidence = _confidence(observations, agreement, adjusted)
        if confidence == "inconclusive":
            continue
        matches.append(
            BatchMatch(
                batch_id=record.batch_id,
                dataset=record.dataset,
                confidence=confidence,
                agreement=round(agreement, 6),
                successes=successes,
                observations=observations,
                capacity=len(record.slots),
                missing_rows=missing,
                p_value=p_value,
                adjusted_p_value=adjusted,
                z_score=round(z_score, 3),
            )
        )

    matches.sort(
        key=lambda item: (
            {"confirmed": 3, "strong": 2, "weak": 1}[item.confidence],
            item.agreement,
            item.observations,
        ),
        reverse=True,
    )
    status = matches[0].confidence if matches else "inconclusive"
    return DetectionResult(
        status=status,
        candidate_count=len(matches),
        tested_batches=len(records),
        matches=matches,
        input_sha256=input_digest,
    )


def row_key(row: dict[str, Any], fields: tuple[str, ...]) -> str | None:
    parts: list[str] = []
    for name in fields:
        if name not in row:
            return None
        value = row[name]
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        parts.append(canonical_json(value))
    return "\x1f".join(parts)


def numeric_cell(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        number = Decimal(str(value))
        return number if number.is_finite() else None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            number = Decimal(text)
        except InvalidOperation:
            return None
        return number if number.is_finite() else None
    return None


def encode_bit(
    original: Any,
    bit: int,
    quantum: Decimal,
    tolerance: Decimal | None = None,
    dither: Decimal | None = None,
) -> tuple[Any, bool] | tuple[None, bool]:
    """Secret-dithered quantization-index modulation."""

    value = numeric_cell(original)
    if value is None or bit not in (0, 1):
        return None, False
    if tolerance is None:
        tolerance = quantum
    if dither is None:
        dither = Decimal(0)
    if not -quantum < dither < quantum:
        return None, False

    shifted = value - dither
    index = int((shifted / quantum).to_integral_value(rounding=ROUND_HALF_EVEN))
    if index % 2 != bit:
        candidates = (index + 1, index - 1)

        def distance(candidate: int) -> tuple[Decimal, int]:
            candidate_value = Decimal(candidate) * quantum + dither
            return abs(candidate_value - value), candidate

        index = min(candidates, key=distance)
    rounded = Decimal(index) * quantum + dither
    if abs(rounded - value) > tolerance:
        return None, False
    return _coerce_output(original, value, rounded), rounded != value


def extract_bit(value: Decimal | Any, quantum: Decimal, dither: Decimal | None = None) -> int:
    numeric = numeric_cell(value)
    if numeric is None:
        raise ValueError("value is not finite numeric")
    offset = Decimal(0) if dither is None else dither
    index = int(((numeric - offset) / quantum).to_integral_value(rounding=ROUND_HALF_EVEN))
    return index % 2


def binomial_tail(successes: int, trials: int) -> float:
    """One-sided probability P(X >= successes) for a fair binomial X."""

    if trials <= 0 or successes <= 0:
        return 1.0
    if successes <= trials // 2:
        return 1.0
    if successes > trials:
        return 0.0
    # A normal continuity correction is adequate for the trial sizes used
    # here and avoids thousands of Decimal exponentiations.
    mean = trials * 0.5
    variance = trials * 0.25
    z = (successes - 0.5 - mean) / (variance ** 0.5)
    return max(0.0, min(1.0, _normal_sf(z)))


def _confidence(observations: int, agreement: float, adjusted_p: float) -> Confidence:
    if observations >= 64 and agreement >= 0.70 and adjusted_p <= 1e-6:
        return "confirmed"
    if observations >= 40 and agreement >= 0.65 and adjusted_p <= 1e-3:
        return "strong"
    if observations >= MIN_SLOT_COUNT and agreement >= 0.60 and adjusted_p <= 0.05:
        return "weak"
    return "inconclusive"


def _normal_sf(z: float) -> float:
    return 0.5 * _erfc(z / (2 ** 0.5))


def _erfc(x: float) -> float:
    import math

    return math.erfc(x)


def _mac(secret: bytes, tag: bytes, *parts: str) -> bytes:
    chunks = [tag]
    chunks.extend(part.encode("utf-8") for part in parts)
    return hmac.new(secret, b"\x00".join(chunks), hashlib.sha256).digest()


def _dither(secret: bytes, *parts: str, quantum: Decimal) -> Decimal:
    raw = int.from_bytes(_mac(secret, b"dither", *parts), "big")
    scale = 2 ** 256
    return quantum * (Decimal(raw) / Decimal(scale) * 2 - 1)


def _coerce_secret(secret: bytes | str | None) -> bytes:
    if secret is None:
        return secrets.token_bytes(32)
    if isinstance(secret, bytes):
        raw = secret
    else:
        try:
            raw = bytes.fromhex(secret.strip())
        except ValueError as exc:
            raise WatermarkError("secret must be 32 bytes or 64 hex characters") from exc
    if len(raw) != 32:
        raise WatermarkError("secret must be 32 bytes or 64 hex characters")
    return raw


def _validate_field_names(values: list[str] | tuple[str, ...], label: str) -> tuple[str, ...]:
    if not values:
        raise WatermarkError(f"{label} must not be empty")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise WatermarkError(f"{label} entries must be non-empty strings")
        result.append(value.strip())
    if len(set(result)) != len(result):
        raise WatermarkError(f"{label} contains duplicate fields")
    return tuple(result)


def _validate_rows(rows: Any, anchors: tuple[str, ...], carrier_names: set[str]) -> None:
    if not isinstance(rows, list) or not rows:
        raise WatermarkError("rows must be a non-empty list")
    if any(not isinstance(row, dict) for row in rows):
        raise WatermarkError("every row must be an object")
    missing_anchor = sorted({name for name in anchors for row in rows if name not in row})
    if missing_anchor:
        raise WatermarkError(f"missing anchor field(s): {', '.join(missing_anchor)}")
    missing_carrier = sorted(
        {name for name in carrier_names for row in rows if name not in row}
    )
    if missing_carrier:
        raise WatermarkError(f"missing carrier field(s): {', '.join(missing_carrier)}")


def _within_bounds(value: Decimal, carrier: CarrierField) -> bool:
    if carrier.lower is not None and value < carrier.lower:
        return False
    if carrier.upper is not None and value > carrier.upper:
        return False
    return True


def _coerce_output(original: Any, original_value: Decimal, encoded: Decimal) -> Any:
    if isinstance(original, int):
        integral = encoded.to_integral_value(rounding=ROUND_HALF_EVEN)
        if integral == encoded:
            return int(integral)
    if isinstance(original, str):
        places = max(_decimal_places(original_value), _decimal_places(encoded))
        return f"{encoded:.{places}f}"
    # JSON numbers use float.  Typical carrier tolerances (cents, units) are
    # far coarser than the resulting representation error.
    return float(encoded)


def _decimal_places(value: Decimal) -> int:
    return max(0, -value.as_tuple().exponent)


def _decimal(value: Any, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not result.is_finite():
        raise ValueError(f"{label} must be finite")
    return result


def _optional_decimal(value: str | float | int | Decimal | None, label: str) -> Decimal | None:
    if value is None:
        return None
    return _decimal(value, label)


def _none_if_missing(value: Any) -> str | None:
    return None if value is None else str(value)


def _require_text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("field name must be a non-empty string")
    return value.strip()
