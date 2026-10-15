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

## Optional issue-tracker connections

The source candidate supports per-user Linear OAuth through a public PKCE app.
Access and refresh tokens stay in that user's secure OS credential vault, with
named user/workspace identity pins. CF embeds a public client ID, no client secret
or owner token. Unavailable or plaintext credential backends are rejected.

Explicit issue imports store ticket text locally under `.factory/issues` as
untrusted data. Treat these artifacts as private and exclude them from source
publication. Evidence drafts contain metadata, not raw logs or ticket text;
posting the exact reviewed draft still sends its contents to the chosen tracker.
Local fixtures are not proof of authenticated provider operation. Disconnect
confirms Linear token revocation before deleting the local credential record.

Issue-provider HTTPS uses a per-connection native trust-store context when the
`issues` extra is installed. Certificate and hostname validation stay enabled;
there is no process-wide SSL override or plaintext credential fallback.
