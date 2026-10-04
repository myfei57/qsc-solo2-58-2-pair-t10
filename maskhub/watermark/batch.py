"""Registry of export batches — the internal link from batch to recipient.

The recipient is recorded only here, never inside the exported data, so a
leaked copy cannot reveal on its own who it was handed to.  Attribution
works the other way around: recovery scores the suspect copy against the
batches listed in this registry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from maskhub.errors import Conflict, NotFound
from maskhub.store.kvstore import RecordStore

PREFIX = "wmbatch."


@dataclass(frozen=True)
class ExportBatch:
    batch_id: str
    dataset: str
    recipient: str
    created_at: str
    rows: int
    carriers: int
    cells_changed: int
    source_sha256: str
    output_sha256: str
    note: str = ""

    def __post_init__(self) -> None:
        if not self.batch_id.strip():
            raise ValueError("batch identifier is required")
        if not self.dataset.strip():
            raise ValueError("dataset is required")
        if not self.recipient.strip():
            raise ValueError("recipient is required")

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: object) -> "ExportBatch | None":
        if not isinstance(payload, dict):
            return None
        try:
            return cls(
                batch_id=_text(payload, "batch_id"),
                dataset=_text(payload, "dataset"),
                recipient=_text(payload, "recipient"),
                created_at=_text(payload, "created_at"),
                rows=_count(payload, "rows"),
                carriers=_count(payload, "carriers"),
                cells_changed=_count(payload, "cells_changed"),
                source_sha256=_text(payload, "source_sha256"),
                output_sha256=_text(payload, "output_sha256"),
                note=str(payload.get("note", "")),
            )
        except (TypeError, ValueError):
            return None


def batch_key(batch_id: str) -> str:
    return PREFIX + batch_id


class BatchRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def save(self, batch: ExportBatch) -> ExportBatch:
        if self._store.has(batch_key(batch.batch_id)):
            raise Conflict(f"batch {batch.batch_id} already recorded")
        self._store.put_json(batch_key(batch.batch_id), batch.as_dict())
        return batch

    def find(self, batch_id: str) -> ExportBatch | None:
        return ExportBatch.from_dict(self._store.get_json(batch_key(batch_id)))

    def get(self, batch_id: str) -> ExportBatch:
        batch = self.find(batch_id)
        if batch is None:
            raise NotFound(f"unknown export batch {batch_id}")
        return batch

    def all(self) -> list[ExportBatch]:
        from maskhub.store.query import keys_with_prefix

        return [
            self.get(key[len(PREFIX):])
            for key in keys_with_prefix(self._store, PREFIX)
        ]

    def by_dataset(self, dataset: str) -> list[ExportBatch]:
        return [batch for batch in self.all() if batch.dataset == dataset]


def _text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _count(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return value
