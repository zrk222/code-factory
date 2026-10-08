import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const trackerUrl = 'https://security-tracker.debian.org/tracker/data/json';
// Original HIGH/CRITICAL IDs, report SHA256:
// 43b969f7bd1882b8167458b9a698c0774003acc556bd6fd99ce2a6a8dc5a8ed5
export const targets = Object.freeze([
  'CVE-2023-45853', 'CVE-2025-69720', 'CVE-2025-7458', 'CVE-2026-11822',
  'CVE-2026-11824', 'CVE-2026-16742', 'CVE-2026-41992', 'CVE-2026-53613',
  'CVE-2026-54369', 'CVE-2026-76642', 'CVE-2026-78408', 'CVE-2026-78409',
  'CVE-2026-78410', 'CVE-2026-84782', 'CVE-2026-9538',
]);
export const toolSmokes = Object.freeze({
  'codeql-python-worker': ['/opt/codeql/codeql/codeql', ['version', '--format=json'], '2.27.1'],
  'osv-worker': ['/usr/local/bin/osv-scanner', ['--version'], '2.2.0'],
  'syft-worker': ['/usr/local/bin/syft', ['version'], '1.33.0'],
  'gitleaks-worker': ['/usr/bin/gitleaks', ['version'], '8.28.0'],
  'trivy-worker': ['/usr/local/bin/trivy', ['--version'], '0.68.1'],
  'runtime-worker': ['/usr/local/bin/python', ['-I', '-m', 'coverage', '--version'], '7.16.1'],
  'fuzz-worker': ['/usr/local/bin/python', ['-I', '-c', 'import atheris; from importlib.metadata import version; print(version("atheris"))'], '3.0.0'],
});
export function docker(args, allowed = [0]) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 120000, maxBuffer: 16 * 1024 * 1024 });
  if (result.error || !allowed.includes(result.status)) throw new Error(`docker ${args[0]} failed: ${result.error?.message || result.stderr}`);
  return result;
}
export async function downloadFeed(fetcher = fetch, maxBytes = 128 * 1024 * 1024) {
  const response = await fetcher(trackerUrl, { signal: AbortSignal.timeout(60000), redirect: 'error' });
  if (!response.ok || !response.body) throw new Error(`Tracker HTTP ${response.status}`);
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > maxBytes) throw new Error('Tracker exceeds byte limit');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const feed = JSON.parse(raw.toString('utf8'));
  if (!feed || Array.isArray(feed) || typeof feed !== 'object') throw new Error('Invalid tracker object');
  return { feed, sha256: createHash('sha256').update(raw).digest('hex'), bytes: raw.length };
}
export function parseManifest(text) {
  const packages = text.trim().split('\n').map(line => {
    const fields = line.replace(/\r$/, '').split('\t');
    if (fields.length !== 4 || fields.some(value => !value)) throw new Error('Incomplete source package manifest');
    return Object.fromEntries(['binary', 'version', 'source', 'source_version'].map((key, i) => [key, fields[i]]));
  });
  return packages;
}
export function evaluate(feed, packages, compare, cves = targets) {
  return cves.map(cve => {
    const matches = packages.filter(pkg => feed[pkg.source]?.[cve]).map(pkg => {
      const release = feed[pkg.source][cve]?.releases?.sid;
      const fixed = release?.fixed_version;
      let state = 'UNKNOWN';
      if (release?.status === 'resolved' && typeof fixed === 'string' && fixed.length) {
        state = fixed === '0' || compare(pkg.source_version, fixed) ? 'RESOLVED' : 'UNRESOLVED';
      } else if (release?.status === 'open') state = 'UNRESOLVED';
      return { package: pkg, state, advisory: release ?? null };
    });
    return { cve, state: matches.length && matches.every(match => match.state === 'RESOLVED') ? 'RESOLVED' : 'BLOCKED', packages: matches };
  });
}
export async function verify(image, output, target) {
  const result = { schema: 'factory.worker-cve-regression.v1', observed_at: new Date().toISOString(), image,
    candidate_commit: process.env.GITHUB_SHA ?? null,
    tracker_url: trackerUrl, target_cves: targets, state: 'BLOCKED',
    claim_boundary: 'Only the original 15 HIGH/CRITICAL IDs, Debian source versions and sid records are checked. This is not evidence of absence of all CVEs or supported Trivy OS coverage.' };
  try {
    if (!Object.hasOwn(toolSmokes, target)) throw new Error('Unknown SDK worker target');
    const id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).stdout.trim();
    if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error('Invalid immutable image ID');
    result.image_id = id;
    const run = (entry, args, allowed) => docker(['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=128', '--memory=2g', '--cpus=2', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777', '--entrypoint', entry, id, ...args], allowed);
    const downloaded = await downloadFeed();
    result.tracker_sha256 = downloaded.sha256;
    result.tracker_bytes = downloaded.bytes;
    result.installed_packages = parseManifest(run('dpkg-query', ['-W', '-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n']).stdout);
    result.checks = evaluate(downloaded.feed, result.installed_packages, (installed, fixed) =>
      run('dpkg', ['--compare-versions', installed, 'ge', fixed], [0, 1]).status === 0);
    run('/usr/local/bin/python', ['-I', '-c', 'import ssl,sqlite3,ctypes,bz2,lzma,readline,curses,uuid,factoryline.deep_audit_io; print(ssl.OPENSSL_VERSION)']);
    run('/usr/local/bin/python', ['-I', '-m', 'pip', 'check']);
    result.package_import_smoke = 'PASS';
    const [tool, args, expected] = toolSmokes[target];
    const smoke = run(tool, args);
    const versionOutput = smoke.stdout + smoke.stderr;
    if (!versionOutput.includes(expected)) throw new Error(`Tool version mismatch: expected ${expected}`);
    result.tool_smoke = { target, tool, expected_version: expected, state: 'PASS', output_sha256: createHash('sha256').update(versionOutput).digest('hex') };
    result.state = result.checks.every(check => check.state === 'RESOLVED') ? 'PASS' : 'BLOCKED';
  } catch (error) { result.error = error.message; }
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`);
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [image, output, target] = process.argv.slice(2);
  if (!image || !output || !target) throw new Error('Usage: node scripts/verify_worker_cves.mjs IMAGE OUTPUT SDK_TARGET');
  const result = await verify(image, output, target);
  console.log(JSON.stringify({ state: result.state, image_id: result.image_id, error: result.error }));
  process.exitCode = result.state === 'PASS' ? 0 : 1;
}
