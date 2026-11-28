// Pinned, receipted timing for `factory scan --static-only` (plan milestone M0).
//   node scripts/scan_benchmark.mjs CORPUS_DIR OUT_JSON [--runs N] [--workers N] [--python BIN]
// Every run must produce byte-identical scan JSON. The receipt records the corpus digest,
// line count, host shape, worker count, each wall time, the spread and the output digest.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { cpus, platform } from 'node:os';
import { join, relative } from 'node:path';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');

export function corpusDigest(root) {
  const files = [];
  const visit = dir => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name.endsWith('.py')) files.push(path);
    }
  };
  visit(root);
  const key = path => relative(root, path).split('\\').join('/');
  files.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
  const digest = createHash('sha256');
  let lines = 0;
  for (const path of files) {
    const data = readFileSync(path);
    digest.update(Buffer.concat([Buffer.from(key(path) + '\0'), createHash('sha256').update(data).digest()]));
    lines += data.toString('latin1').split('\n').length - 1;
  }
  return { corpus_sha256: digest.digest('hex'), python_files: files.length, lines };
}

function timedScan(python, root, workers) {
  const code = "import sys; from factoryline.cli import main; sys.argv=['factory','scan','--root',sys.argv[1],'--static-only','--json']; main()";
  const start = process.hrtime.bigint();
  const run = spawnSync(python, ['-c', code, root], { env: { ...process.env, FACTORY_SCAN_WORKERS: String(workers) }, maxBuffer: 256 * 1024 * 1024 });
  const seconds = Number(process.hrtime.bigint() - start) / 1e9;
  if (run.status !== 0) throw new Error(`scan failed with exit ${run.status}: ${String(run.stderr).slice(-400)}`);
  return { seconds, digest: sha(run.stdout) };
}

export function summarize(corpus, workers, results, host) {
  const times = results.map(run => run.seconds).sort((a, b) => a - b);
  const outputs = [...new Set(results.map(run => run.digest))].sort();
  const median = times[Math.floor(times.length / 2)];
  const spread = median ? (times.at(-1) - times[0]) / median : 0;
  const round = (value, places) => Number(value.toFixed(places));
  return { schema: 'factory.scan-benchmark.v1', ...corpus, host, workers,
    runs_seconds: times.map(time => round(time, 3)), median_seconds: round(median, 3), spread: round(spread, 4),
    lines_per_second: median ? Math.round(corpus.lines / median) : null, output_sha256: outputs,
    stable_output: outputs.length === 1, stable_timing: spread <= 0.10 };
}

function main(argv) {
  const [corpus, out, ...rest] = argv;
  const option = (name, fallback) => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : fallback);
  if (!corpus || !out) throw new Error('Usage: node scripts/scan_benchmark.mjs CORPUS_DIR OUT_JSON [--runs N] [--workers N] [--python BIN]');
  const runs = Math.max(1, Number(option('--runs', '3'))), workers = Number(option('--workers', '0'));
  const python = option('--python', process.platform === 'win32' ? 'python' : 'python3');
  const results = Array.from({ length: runs }, () => timedScan(python, corpus, workers));
  const host = { cpus: cpus().length, system: platform(), python };
  const receipt = summarize(corpusDigest(corpus), workers, results, host);
  writeFileSync(out, JSON.stringify(receipt, null, 2) + '\n');
  console.log(JSON.stringify({ median_seconds: receipt.median_seconds, spread: receipt.spread, stable_output: receipt.stable_output, stable_timing: receipt.stable_timing }));
  return receipt.stable_output ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = main(process.argv.slice(2));
