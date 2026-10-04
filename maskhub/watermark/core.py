"""Embedding and recovery of statistical export watermarks.

The watermark carries no payload at all.  For one export batch, a row is
a *carrier* when ``HMAC(batch_key, primary_key)`` selects it, and each
carrier rewrites one markable cell so the cell encodes one expected bit
(LSB of a numeric value, or the choice inside a category synonym pair).

Because row identity comes from the primary key, reordering rows changes
nothing.  Recovery scores a suspect copy against every registered batch
and applies a binomial test: under the null hypothesis (the copy does not
carry this batch's marks) a carrier cell matches the expected bit with
probability 1/2, so a strong excess of matches is attributable to one
batch with a quantifiable p-value.  Deleted rows shrink the carrier
count, flipped cells cost a few matches, and added rows only dilute the
rate towards 1/2 — the test degrades gracefully instead of breaking.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import zlib
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation

from maskhub.watermark.profile import (
    CATEGORY,
    NUMERIC,
    ChecksumSpec,
    ColumnMark,
    WatermarkProfile,
)

Row = dict[str, str]

_LN2 = math.log(2.0)


def row_token(batch_key: bytes, primary_key: str) -> int:
    """Order-independent row identity derived under the batch key."""
    digest = hmac.new(
        batch_key, b"row:" + primary_key.encode("utf-8"), hashlib.sha256
    ).digest()
    return int.from_bytes(digest[:8], "big")


def is_carrier(token: int, carrier_mod: int) -> bool:
    return token % carrier_mod == 0


def expected_bit(token: int) -> int:
    return (token >> 8) & 1


def column_index(token: int, count: int) -> int:
    return (token >> 16) % count


def compute_checksum(spec: ChecksumSpec, row: Row) -> str:
    joined = "|".join(row.get(name, "") for name in spec.columns)
    if spec.algorithm == "crc32":
        return f"{zlib.crc32(joined.encode('utf-8')) & 0xFFFFFFFF:08x}"
    raise ValueError(f"unsupported checksum algorithm {spec.algorithm!r}")


# ---------------------------------------------------------------------------
# cell-level bit I/O
# ---------------------------------------------------------------------------


def read_bit(column: ColumnMark, text: str) -> int | None:
    """Bit carried by a cell, or None when the cell cannot be read."""
    if column.kind == NUMERIC:
        return _read_numeric_bit(text)
    return _read_category_bit(column, text)


def write_bit(column: ColumnMark, text: str, bit: int) -> str | None:
    """Cell text carrying ``bit``; None when constraints forbid marking."""
    if column.kind == NUMERIC:
        return _write_numeric_bit(column, text, bit)
    return _write_category_bit(column, text, bit)


def _quantize(text: str) -> tuple[int, int] | None:
    """(integer, scale) of a decimal literal, keeping its own precision."""
    stripped = text.strip()
    if not stripped:
        return None
    try:
        value = Decimal(stripped)
    except InvalidOperation:
        return None
    if not value.is_finite():
        return None
    exponent = value.as_tuple().exponent
    scale = -exponent if exponent < 0 else 0
    return int(value.scaleb(scale)), scale


def _read_numeric_bit(text: str) -> int | None:
    parsed = _quantize(text)
    if parsed is None:
        return None
    quant, _ = parsed
    return quant & 1


def _write_numeric_bit(column: ColumnMark, text: str, bit: int) -> str | None:
    parsed = _quantize(text)
    if parsed is None:
        return None
    quant, scale = parsed
    if quant & 1 == bit:
        return text
    original = Decimal(text.strip())
    for candidate in (quant + 1, quant - 1):
        value = Decimal(candidate).scaleb(-scale)
        if column.minimum is not None and value < Decimal(str(column.minimum)):
            continue
        if column.maximum is not None and value > Decimal(str(column.maximum)):
            continue
        if column.abs_tol is not None and abs(value - original) > Decimal(
            str(column.abs_tol)
        ):
            continue
        if (
            column.rel_tol is not None
            and original != 0
            and abs(value - original) > abs(original) * Decimal(str(column.rel_tol))
        ):
            continue
        return format(value, f".{scale}f")
    return None


def _read_category_bit(column: ColumnMark, text: str) -> int | None:
    value = text.strip()
    for canonical, alternate in column.pairs.items():
        if value == canonical:
            return 0
        if value == alternate:
            return 1
    return None


def _write_category_bit(column: ColumnMark, text: str, bit: int) -> str | None:
    value = text.strip()
    for canonical, alternate in column.pairs.items():
        if value == canonical:
            return text if bit == 0 else alternate
        if value == alternate:
            return text if bit == 1 else canonical
    return None


# ---------------------------------------------------------------------------
# embedding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmbedStats:
    rows: int
    carriers: int
    cells_changed: int
    cells_already_ok: int
    cells_skipped: int

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


def embed_rows(
    rows: list[Row], profile: WatermarkProfile, batch_key: bytes
) -> EmbedStats:
    """Rewrite carrier cells in place; returns what happened.

    Deterministic for a given (rows, profile, batch_key): re-embedding the
    same batch is a no-op, and a different batch picks different carriers,
    so repeated exports of one dataset never overwrite each other.
    """
    carriers = changed = already = skipped = 0
    for row in rows:
        token = row_token(batch_key, row.get(profile.primary_key, ""))
        if not is_carrier(token, profile.carrier_mod):
            continue
        carriers += 1
        column = profile.columns[column_index(token, len(profile.columns))]
        bit = expected_bit(token)
        current = row.get(column.name, "")
        updated = write_bit(column, current, bit)
        if updated is None:
            skipped += 1
            continue
        if updated == current:
            already += 1
            continue
        row[column.name] = updated
        changed += 1
        if profile.checksum is not None:
            row[profile.checksum.name] = compute_checksum(profile.checksum, row)
    return EmbedStats(
        rows=len(rows),
        carriers=carriers,
        cells_changed=changed,
        cells_already_ok=already,
        cells_skipped=skipped,
    )


# ---------------------------------------------------------------------------
# recovery
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Score:
    carriers: int
    matches: int
    match_rate: float
    p_value: float

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def score_rows(rows: list[Row], profile: WatermarkProfile, batch_key: bytes) -> Score:
    """How well a suspect copy matches one batch's expected marks."""
    carriers = matches = 0
    for row in rows:
        token = row_token(batch_key, row.get(profile.primary_key, ""))
        if not is_carrier(token, profile.carrier_mod):
            continue
        column = profile.columns[column_index(token, len(profile.columns))]
        bit = read_bit(column, row.get(column.name, ""))
        if bit is None:
            continue  # cell blanked or corrupted: treated as erased, not as a miss
        carriers += 1
        if bit == expected_bit(token):
            matches += 1
    return Score(
        carriers=carriers,
        matches=matches,
        match_rate=(matches / carriers) if carriers else 0.0,
        p_value=binomial_sf(matches, carriers),
    )


def binomial_sf(k: int, n: int) -> float:
    """P[X >= k] for X ~ Bin(n, 1/2): the random-coincidence probability."""
    if n <= 0 or k <= 0:
        return 1.0
    if k > n:
        return 0.0
    log_terms = [
        math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) - n * _LN2
        for i in range(k, n + 1)
    ]
    peak = max(log_terms)
    return min(1.0, math.exp(peak) * sum(math.exp(term - peak) for term in log_terms))
