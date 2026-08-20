# Plan: mcp-registry-distribution-v1

Spec: specs/mcp-registry-distribution-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Define the official registry descriptor, ownership marker, and user-facing
   authority documentation for the existing MCP server.
2. Make the patch-release metadata and source distribution agree with the
   descriptor.
3. Add static contract tests and a post-PyPI GitHub OIDC registry publisher.
4. Build, test, inspect the wheel/sdist, validate the registry descriptor, and
   release only after all local gates pass.

## Tasks (atomic - each independently shippable)

- [ ] T1 | slice=. | files=<=4 | verify=`mcp-publisher validate mcp/server.json` | Add the official registry descriptor, PyPI ownership marker, and authority guide.
- [ ] T2 | slice=. | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_mcp.py` | Align the 0.40.0 package, citation, archival, and public release metadata.
- [ ] T3 | slice=. | files=<=4 | verify=`python -m pytest -q tests/test_mcp_registry_distribution.py` | Add the post-PyPI, checksum-verified OIDC registry workflow and its contract tests.
- [ ] T4 | slice=. | files=<=4 | verify=`python -m build; python -m twine check dist/*; python -m pytest -q` | Verify released artifacts and full test suite before tag creation.
