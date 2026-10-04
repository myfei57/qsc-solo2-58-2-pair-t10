"""Watermark profile: which columns may carry marks, and under what limits.

A profile is the contract shared by embedding and recovery.  It declares
the primary key (row identity, so marks survive reordering), the markable
columns together with the constraints that keep marked values valid, and
an optional row checksum column that must be recomputed whenever a cell
is rewritten.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from maskhub.errors import NotFound
from maskhub.store.kvstore import RecordStore

PREFIX = "wmprofile."

NUMERIC = "numeric"
CATEGORY = "category"
KINDS = (NUMERIC, CATEGORY)

DEFAULT_CARRIER_MOD = 4
DEFAULT_MIN_CARRIERS = 30


@dataclass(frozen=True)
class ColumnMark:
    """One markable column and the constraints its values must keep."""

    name: str
    kind: str
    minimum: float | None = None
    maximum: float | None = None
    abs_tol: float | None = None
    rel_tol: float | None = None
    pairs: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("column name is required")
        if self.kind not in KINDS:
            raise ValueError(f"unsupported column kind {self.kind!r}")
        if self.kind == CATEGORY:
            if not self.pairs:
                raise ValueError("category column requires synonym pairs")
            if set(self.pairs) & set(self.pairs.values()):
                raise ValueError("synonym pairs must be disjoint")
        if self.kind == NUMERIC and self.pairs:
            raise ValueError("numeric column cannot declare synonym pairs")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("minimum exceeds maximum")

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "ColumnMark | None":
        if not isinstance(payload, dict):
            return None
        try:
            return cls(
                name=_text(payload, "name"),
                kind=_text(payload, "kind"),
                minimum=_number(payload, "minimum"),
                maximum=_number(payload, "maximum"),
                abs_tol=_number(payload, "abs_tol"),
                rel_tol=_number(payload, "rel_tol"),
                pairs=_pairs(payload),
            )
        except (TypeError, ValueError):
            return None


@dataclass(frozen=True)
class ChecksumSpec:
    """Row-level checksum column recomputed after a cell is marked."""

    name: str
    columns: tuple[str, ...]
    algorithm: str = "crc32"

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("checksum column name is required")
        if not self.columns:
            raise ValueError("checksum must cover at least one column")
        if self.algorithm != "crc32":
            raise ValueError(f"unsupported checksum algorithm {self.algorithm!r}")

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "columns": list(self.columns),
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, payload: object) -> "ChecksumSpec | None":
        if not isinstance(payload, dict):
            return None
        name = payload.get("name")
        columns = payload.get("columns")
        algorithm = payload.get("algorithm", "crc32")
        if not isinstance(name, str) or not isinstance(algorithm, str):
            return None
        if not isinstance(columns, list) or not all(isinstance(c, str) for c in columns):
            return None
        try:
            return cls(name=name, columns=tuple(columns), algorithm=algorithm)
        except ValueError:
            return None


@dataclass(frozen=True)
class WatermarkProfile:
    """Full marking contract for one dataset."""

    dataset: str
    primary_key: str
    columns: tuple[ColumnMark, ...]
    checksum: ChecksumSpec | None = None
    carrier_mod: int = DEFAULT_CARRIER_MOD
    min_carriers: int = DEFAULT_MIN_CARRIERS

    def __post_init__(self) -> None:
        if not self.dataset.strip():
            raise ValueError("dataset is required")
        if not self.primary_key.strip():
            raise ValueError("primary key is required")
        if not self.columns:
            raise ValueError("at least one markable column is required")
        if self.carrier_mod < 2:
            raise ValueError("carrier_mod must be at least 2")
        if self.min_carriers < 1:
            raise ValueError("min_carriers must be positive")
        names = [column.name for column in self.columns]
        if len(set(names)) != len(names):
            raise ValueError("duplicate markable column")
        if self.checksum is not None and self.checksum.name in names:
            raise ValueError("checksum column cannot be markable")

    def column(self, name: str) -> ColumnMark | None:
        for column in self.columns:
            if column.name == name:
                return column
        return None

    def as_dict(self) -> dict[str, object]:
        return {
            "dataset": self.dataset,
            "primary_key": self.primary_key,
            "columns": [column.as_dict() for column in self.columns],
            "checksum": self.checksum.as_dict() if self.checksum else None,
            "carrier_mod": self.carrier_mod,
            "min_carriers": self.min_carriers,
        }

    @classmethod
    def from_dict(cls, payload: object) -> "WatermarkProfile | None":
        if not isinstance(payload, dict):
            return None
        dataset = payload.get("dataset")
        primary_key = payload.get("primary_key")
        raw_columns = payload.get("columns")
        if not isinstance(dataset, str) or not isinstance(primary_key, str):
            return None
        if not isinstance(raw_columns, list) or not raw_columns:
            return None
        columns = tuple(
            item for item in (ColumnMark.from_dict(raw) for raw in raw_columns) if item
        )
        if len(columns) != len(raw_columns):
            return None
        raw_checksum = payload.get("checksum")
        checksum = ChecksumSpec.from_dict(raw_checksum) if raw_checksum else None
        if raw_checksum and checksum is None:
            return None
        carrier_mod = payload.get("carrier_mod", DEFAULT_CARRIER_MOD)
        min_carriers = payload.get("min_carriers", DEFAULT_MIN_CARRIERS)
        if isinstance(carrier_mod, bool) or not isinstance(carrier_mod, int):
            return None
        if isinstance(min_carriers, bool) or not isinstance(min_carriers, int):
            return None
        try:
            return cls(
                dataset=dataset,
                primary_key=primary_key,
                columns=columns,
                checksum=checksum,
                carrier_mod=carrier_mod,
                min_carriers=min_carriers,
            )
        except ValueError:
            return None


def profile_key(dataset: str) -> str:
    return PREFIX + dataset


class ProfileRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def save(self, profile: WatermarkProfile) -> WatermarkProfile:
        self._store.put_json(profile_key(profile.dataset), profile.as_dict())
        return profile

    def find(self, dataset: str) -> WatermarkProfile | None:
        return WatermarkProfile.from_dict(self._store.get_json(profile_key(dataset)))

    def get(self, dataset: str) -> WatermarkProfile:
        profile = self.find(dataset)
        if profile is None:
            raise NotFound(f"no watermark profile for dataset {dataset!r}")
        return profile

    def all(self) -> list[WatermarkProfile]:
        from maskhub.store.query import keys_with_prefix

        return [
            self.get(key[len(PREFIX):])
            for key in keys_with_prefix(self._store, PREFIX)
        ]


def _text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _number(payload: dict[str, object], key: str) -> float | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number")
    return float(value)


def _pairs(payload: dict[str, object]) -> dict[str, str]:
    value = payload.get("pairs", {})
    if not isinstance(value, dict):
        raise ValueError("pairs must be an object")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ValueError("pairs must map strings to strings")
    return dict(value)
