# Agent Oven by Code Factory

This folder contains the isolated product-design boundary for Code Factory Agent Cloud. PR Assurance is the only committed v1 product; the broader template catalog is post-v1 research.

## Source documents

- Product requirements: [`../../docs/CODE_FACTORY_AGENT_CLOUD_PRD.md`](../../docs/CODE_FACTORY_AGENT_CLOUD_PRD.md)
- Template portfolio: [`templates/TEMPLATE_CATALOG.md`](templates/TEMPLATE_CATALOG.md)
- Clean-room surgery protocol: [`CLEAN_ROOM_SURGERY.md`](CLEAN_ROOM_SURGERY.md)
- Clean-room AKU: [`clean-room-surgery.aku.yaml`](clean-room-surgery.aku.yaml)
- Memory fork boundary: [`forks/factory-memory-core/README.md`](forks/factory-memory-core/README.md)
- Trust fork boundary: [`forks/factory-trust-core/README.md`](forks/factory-trust-core/README.md)

## Isolation rule

This product area does not import, edit, or depend on files from a WizeMe application folder. The two proposed layers are implemented as either provenance-reviewed forks or clean-room Code Factory services with independent storage, schemas, versions, keys, tests, and release pipelines.

No WizeMe source code has been copied here. These files define boundaries and requirements only.
