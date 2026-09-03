# Code Factory 0.46.1 — oracle meaning and evidence binding hardening

This patch closes three review findings in the local proof path.

- **Oracle meaning firewall:** a blocking or release rule cannot keep its ID
  while silently changing its statement, source binding, provenance,
  criticality, effect, or gate semantics. Such drift emits
  `E_ORACLE_WEAKENING` and requires review.
- **Faithful proof worklogs:** local review drafts now carry approved
  obligations and forbidden behaviors from the sealed contract's rules.
- **AppForge receipt integrity:** a submission dossier now points to the
  immutable, hash-valid derived Oracle authority receipt that it records. The
  original authority input stays separately traceable by path and byte digest.

All behavior remains local and evidence-only: this version does not operate an
agent, change a candidate, access credentials, submit to Apple, or guarantee a
review result.

## Install

```bash
pip install --upgrade factoryline-code-factory==0.46.1
```
