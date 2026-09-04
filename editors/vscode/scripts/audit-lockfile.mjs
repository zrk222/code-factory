// Full production AND build dependency audit. Network/tool failures block release.
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const version = 'v2.5.1';
// Official google/osv-scanner release checksums, pinned rather than trusted at runtime.
export const checksums = {
  linux_x64: ['osv-scanner_linux_amd64', 'f9f25499a2c8cc367b3af45df2ea7eeca7fbccceab9c35079968f4b3652194be'],
  linux_arm64: ['osv-scanner_linux_arm64', '3d0f5aa5a6baa8eb32bcef247388e149ef6030a6634ccae6fa0d62681fb27a6d'],
  win32_x64: ['osv-scanner_windows_amd64.exe', '25e42f5ef6711fd8c0fb45390972205891dd44c6bd02ac93f0f63e8e98d9bfb6'],
  win32_arm64: ['osv-scanner_windows_arm64.exe', '33feb0b210a3e5ea7b338c719defc899f8833d990cdd297bcad4ff1a2586ec8b'],
  darwin_x64: ['osv-scanner_darwin_amd64', '9f89beb6c3d784893cb1cae0a3d56c529bfe91075418c2f9440c45b79654198b'],
  darwin_arm64: ['osv-scanner_darwin_arm64', '75c44d6332f892a1e56286f4105a98ed751ae28d215ca0a8b65cc00d84103054'],
};

export function verifyBinary(bytes, expected) {
  if (createHash('sha256').update(bytes).digest('hex') !== expected) {
    throw new Error('OSV scanner checksum mismatch');
  }
}

export function requireSuccessfulScan(result) {
  if (result.error || result.status !== 0 || result.signal) {
    throw new Error(`Dependency audit blocked: ${result.error?.message ?? result.signal ?? result.status}`);
  }
}

export async function audit() {
  const asset = checksums[`${process.platform}_${process.arch}`];
  if (!asset) throw new Error('Unsupported audit platform; release is blocked');
  const directory = await mkdtemp(join(tmpdir(), 'factory-osv-'));
  try {
    const response = await fetch(`https://github.com/google/osv-scanner/releases/download/${version}/${asset[0]}`, {
      signal: AbortSignal.timeout(60000),
    });
    if (!response.ok) throw new Error(`OSV download failed: HTTP ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    verifyBinary(bytes, asset[1]);
    const executable = join(directory, asset[0]);
    await writeFile(executable, bytes);
    await chmod(executable, 0o700);
    // Explicit empty configuration prevents inherited ignore rules weakening this gate.
    const config = join(directory, 'osv-scanner.toml');
    await writeFile(config, '');
    requireSuccessfulScan(spawnSync(executable, [
      'scan', 'source', '-L', resolve('package-lock.json'), '--config', config,
    ], { stdio: 'inherit', timeout: 180000, shell: false }));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  audit().catch(error => { console.error(error.message); process.exitCode = 1; });
}
