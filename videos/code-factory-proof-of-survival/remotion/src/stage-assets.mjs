import { copyFileSync, mkdirSync } from 'node:fs';

const docs = new URL('../../../../docs/assets/', import.meta.url);
const output = new URL('../public/', import.meta.url);
const assets = [
  'factoryline-logo-480.png',
  'marketplace/graph-ops-dashboard-current.png',
  'marketplace/graph-ops-audit-telemetry-current.png',
];

mkdirSync(output, { recursive: true });
for (const asset of assets) {
  copyFileSync(new URL(asset, docs), new URL(asset.split('/').at(-1), output));
}
