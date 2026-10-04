"""Master key custody and per-batch key derivation.

Every export batch gets an independent key derived from the master
secret, so two exports of the same dataset pick independent carrier
rows and never overwrite each other's marks.  The master key lives in
the record store next to the other control-plane state; production
deployments should move it into a KMS/HSM and treat the store file as
highly sensitive until then.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from maskhub.store.kvstore import RecordStore

MASTER_KEY = "watermark.master"
MASTER_BYTES = 32


class Keyring:
    """Derives watermark keys from a single master secret."""

    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def master(self) -> bytes:
        raw = self._store.get(MASTER_KEY)
        if raw is None:
            raw = secrets.token_bytes(MASTER_BYTES)
            self._store.put(MASTER_KEY, raw)
        return bytes(raw)

    def batch_key(self, batch_id: str) -> bytes:
        """Key that steers carrier selection for one export batch."""
        return hmac.new(
            self.master(), f"export:{batch_id}".encode("utf-8"), hashlib.sha256
        ).digest()

    def report_key(self) -> bytes:
        """Key that signs evidence reports so archives stay tamper-evident."""
        return hmac.new(self.master(), b"report-signing", hashlib.sha256).digest()
