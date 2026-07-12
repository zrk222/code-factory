# Spec: privacy-plane-foundation

- The system shall construct a deterministic Merkle commitment over evidence
  digests and disclose one leaf with an inclusion path.
- The system shall verify a disclosure without requiring undisclosed leaves.
- The system shall reject an altered leaf or path.
- BBS and zkVM integrations shall be import-guarded and fail closed when a
  reviewed backend is unavailable; a hash shall never be described as a BBS or
  zero-knowledge proof.

