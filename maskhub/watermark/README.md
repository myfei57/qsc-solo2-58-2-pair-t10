# Export watermarking

The watermark service embeds a private, batch-specific mark in a tabular
export without adding rows or columns.  Detection identifies the export batch
from a leaked copy, while evidence reports deliberately do not contain the
recipient.

## Threats covered

- Rows are reordered: cells are selected from stable business anchor fields,
  not row number.
- Some rows/cells are deleted or modified: each batch uses many independent
  bit observations and majority/binomial scoring.
- The same source data is exported more than once: every batch has an
  independent random ID and 256-bit secret. Prepare each copy from the clean
  master; their marks do not overwrite each other because they live in
  separate output files.
- Chained redistribution: if a previously marked file must be marked again in
  the same physical copy, pass prior slots as `protected_slots` so the new
  mark uses disjoint cells. Both marks can then be detected.
- Evidence tampering: saved reports are HMAC-SHA256 signed over canonical
  JSON.

The implementation uses quantization-index modulation on numeric cells. A
field must have a business-approved `tolerance` (for example `0.01` currency
units), optional bounds, and a stable non-watermarked anchor such as order ID.
Changes remain at or below that tolerance and preserve int / numeric-string
flavor when possible. Column names, row count, schema and encodable value
types are unchanged. Re-export through an explicit serialization layer when a
format-specific file-level checksum must also be regenerated; no invisible
mark can survive a checksum that is verified against the exact original bytes.

## API

### `POST /watermark/prepare`

```json
{
  "dataset": "orders.v1",
  "anchor_fields": ["order_id"],
  "carriers": [
    {"name": "amount", "tolerance": "0.01", "min_value": "0", "slots": 70}
  ],
  "rows": [{"order_id": "A1", "amount": "12.30"}]
}
```

The response contains `batch_id`, watermarked `rows`, hashes, changed cell
count and selected slot count. The private batch record (including secret and
slots) is stored server-side and is not returned. Use 64+ slots for the
`confirmed` tier when enough eligible cells exist.

### `POST /watermark/detect`

```json
{
  "dataset": "orders.v1",
  "case_id": "LEAK-2026-0007",
  "analyst": "investigator",
  "save": true,
  "rows": []
}
```

Reports include:

- matched `batch_id` and dataset;
- `weak`, `strong`, or `confirmed` confidence;
- observed agreement, observations/capacity and missing rows;
- one-sided binomial p-value, Bonferroni-adjusted p-value and z-score;
- source-file SHA-256;
- `recipient: null`.

Recipient linkage belongs in a separate, tightly controlled distribution
ledger. Investigators receive only a batch ID; a separate disclosure process
can resolve that ID if legally authorized. This prevents the watermark service
or detection report itself from revealing who received a copy.

### `GET /watermarks`

Lists non-secret batch metadata and slot counts. Slot locations and secrets are
not exposed.

## Operational requirements

1. Set `MASKHUB_WATERMARK_KEY` to 64 hex characters (32 bytes). Rotating it
   invalidates report signatures; preserve old keys in a managed key archive.
2. Batch records must be encrypted/access-controlled at rest by the deployment
   environment. Secrets and slot locations are needed for detection and would
   let an authorized insider remove a mark.
3. Archive the exact exported bytes, the response hashes, batch ID, export time,
   approval/workflow ID, and separately sealed recipient mapping.
4. Never watermark in place on the master. Generate each external artifact from
   the clean master.
5. Anchor fields must be stable and unique in the export. Missing/duplicate
   anchors are skipped rather than treated as weak evidence.

## Confidence policy

- `weak`: at least 24 observations, agreement >= 0.60, adjusted p <= 0.05.
- `strong`: at least 40 observations, agreement >= 0.65, adjusted p <= 0.001.
- `confirmed`: at least 64 observations, agreement >= 0.70, adjusted p <= 1e-6.
- `inconclusive`: below these thresholds or no candidate.

P-values are evidence of a keyed, non-obvious match; legal weight still depends
on chain-of-custody for the leaked file, protected batch records, and the
distribution ledger.
