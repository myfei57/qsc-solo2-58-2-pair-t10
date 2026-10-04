"""Composition root for the gateway."""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.audit.journal import Journal
from maskhub.catalog.dataset import DatasetRegistry
from maskhub.policy.registry import PolicyRegistry
from maskhub.rule.registry import RuleRegistry
from maskhub.source.registry import SourceRegistry
from maskhub.store.kvstore import RecordStore
from maskhub.watermark.batch import BatchRegistry
from maskhub.watermark.keys import Keyring
from maskhub.watermark.profile import ProfileRegistry
from maskhub.watermark.report import ReportRegistry


@dataclass
class Runtime:
    store: RecordStore
    journal: Journal
    sources: SourceRegistry
    datasets: DatasetRegistry
    rules: RuleRegistry
    policies: PolicyRegistry
    keyring: Keyring
    profiles: ProfileRegistry
    batches: BatchRegistry
    reports: ReportRegistry


def build_runtime(store: RecordStore) -> Runtime:
    return Runtime(
        store=store,
        journal=Journal(store),
        sources=SourceRegistry(store),
        datasets=DatasetRegistry(store),
        rules=RuleRegistry(store),
        policies=PolicyRegistry(store),
        keyring=Keyring(store),
        profiles=ProfileRegistry(store),
        batches=BatchRegistry(store),
        reports=ReportRegistry(store),
    )
