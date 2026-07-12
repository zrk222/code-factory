# Privacy Plane Foundation

Merkle selective disclosure is available locally:

```python
from factoryline.privacy import merkle_disclosure, verify_merkle_disclosure

proof = merkle_disclosure(receipt_digests, receipt_digests[0])
assert verify_merkle_disclosure(proof)
```

The CLI can report optional backend status or write the same disclosure:

```powershell
factory privacy status
factory privacy merkle receipt-digests.json --disclose <digest> --out disclosure.json
```

The verifier sees one disclosed digest, its sibling path, and the commitment
root; it does not need the other leaves. This is a commitment and inclusion
proof, not encryption or anonymity.

BBS credentials and zkVM proof-of-policy are import-guarded pilots. When their
reviewed backends are absent, the commands return explicit unavailable status
and never claim a credential or zero-knowledge proof was produced.
