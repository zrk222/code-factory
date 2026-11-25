import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, copyFileSync, readFileSync, writeFileSync, mkdirSync, chmodSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join, dirname } from 'node:path';
import { verifyRuleMutation, verifySourceSinkFlows, verifyFlowControlMatrix, verifyNativeControlFindings,
  javascriptControlManifest, verifyJavascriptControlMatrix, tsxQualificationSuffix,
  appendExtensionControls } from './semgrep_mutation_controls.mjs';

const [image, output = '.factory/semgrep-surface-verification.json'] = process.argv.slice(2);
if (!image) throw new Error('Usage: node scripts/verify_semgrep_surface.mjs IMAGE OUTPUT');
const root = process.cwd();
const profile = JSON.parse(readFileSync('deploy/deep-adapters/profiles/semgrep-pattern-limited.json', 'utf8'));
const rulesPath = 'deploy/deep-adapters/rules/semgrep-pattern-limited.yml';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const receipt = { schema: 'factory.semgrep-surface-controls.v1', state: 'BLOCKED',
  observed_at: new Date().toISOString(), image, source: {},
  claim_boundary: 'Native positive, safe and detector-removal controls for all bundled rules, including explicit unsafe API/configuration candidates across twelve source languages; no general detection-accuracy or interprocedural-coverage claim.' };
// Synthetic native parser/positive/safe controls: one finding per source, no accuracy claim.
const polyglotControls = {
  go: ['go.disabled-tls-verification', 'package controls\nimport "crypto/tls"\nfunc controls(token string) {\nauthorization := "Bearer " + token\n_ = authorization\n// ruleid: go.disabled-tls-verification\n_ = tls.Config{InsecureSkipVerify: true}\n// ok: go.disabled-tls-verification\n_ = tls.Config{InsecureSkipVerify: false}\n}'],
  rs: ['rust.reqwest-disabled-tls-verification', 'fn controls(password: &str) {\nlet _ = password;\n// ruleid: rust.reqwest-disabled-tls-verification\nlet _ = reqwest::Client::builder().danger_accept_invalid_certs(true);\n// ok: rust.reqwest-disabled-tls-verification\nlet _ = reqwest::Client::builder().danger_accept_invalid_certs(false);\n}'],
  java: ['java.disabled-hostname-verification', 'import org.apache.http.conn.ssl.NoopHostnameVerifier;\nclass Controls { void controls(javax.net.ssl.HttpsURLConnection connection) {\n// ruleid: java.disabled-hostname-verification\njavax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);\n// ok: java.disabled-hostname-verification\njavax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> false);\n// ruleid: java.disabled-hostname-verification\nconnection.setHostnameVerifier((host, session) -> true);\n// ruleid: java.disabled-hostname-verification\nObject verifier = NoopHostnameVerifier.INSTANCE;\n}}\nclass TrustAll implements javax.net.ssl.X509TrustManager {\n// ruleid: java.disabled-hostname-verification\npublic void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}\n// ok: java.disabled-hostname-verification\npublic void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) { validate(chain); }\n}'],
  c: ['c.unsafe-gets', 'void controls() { char buffer[64];\n// ruleid: c.unsafe-gets\ngets(buffer);\n// ok: c.unsafe-gets\nfgets(buffer, sizeof(buffer), stdin);\n}'],
  cpp: ['c.unsafe-gets', 'void controls() { char buffer[64];\n// ruleid: c.unsafe-gets\ngets(buffer);\n// ok: c.unsafe-gets\nfgets(buffer, sizeof(buffer), stdin);\n}'],
  cs: ['csharp.disabled-certificate-verification', 'class Controls { void Run() {\n// ruleid: csharp.disabled-certificate-verification\nSystem.Net.ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;\n// ok: csharp.disabled-certificate-verification\nSystem.Net.ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => false;\n}}'],
  rb: ['ruby.disabled-tls-verification', '# ruleid: ruby.disabled-tls-verification\nOpenSSL::SSL::SSLContext.new.verify_mode = OpenSSL::SSL::VERIFY_NONE\n# ok: ruby.disabled-tls-verification\nOpenSSL::SSL::SSLContext.new.verify_mode = OpenSSL::SSL::VERIFY_PEER\n# ruleid: ruby.disabled-tls-verification\nhttp.verify_mode = OpenSSL::SSL::VERIFY_NONE'],
  swift: ['swift.trust-exceptions', readFileSync('deploy/deep-adapters/rules/tests/swift-trust-controls.txt', 'utf8')],
};

// Each annotated sink is an explicit fixture expectation, not an inferred detector.
const flowControls = {
  go: `
func direct(req *http.Request, db *sql.DB) {
// source: go.request-command-injection
value := req.FormValue("command")
// ruleid: go.request-command-injection
exec.Command("sh", "-c", value)
// source: go.request-sql-injection
query := req.FormValue("query")
// ruleid: go.request-sql-injection
db.Query(query)
}
func aliases(req *http.Request, db *sql.DB) {
// source: go.request-command-injection
value := req.FormValue("command")
alias := "echo " + value
// ruleid: go.request-command-injection
exec.Command("/bin/sh", "-c", alias)
// source: go.request-sql-injection
name := req.FormValue("name")
query := "SELECT * FROM users WHERE name='" + name + "'"
// ruleid: go.request-sql-injection
db.Query(query)
// ok: go.request-command-injection
exec.Command("echo", value)
// ok: go.request-command-injection
exec.Command("sh", "-c", "echo fixed")
// ok: go.request-sql-injection
db.Query("SELECT * FROM users WHERE name=?", name)
}
func unrelated(req *LocalRequest, db *LocalDB) {
value := req.FormValue("command")
// ok: go.request-command-injection
exec.Command("sh", "-c", value)
// ok: go.request-sql-injection
db.Query(value)
}
func wrongProvider(req *http.Request, db *LocalDB) {
value := req.FormValue("query")
// ok: go.request-sql-injection
db.Query(value)
}
func frameworks(c *gin.Context, r *http.Request) {
// source: go.request-sql-injection
query := r.URL.Query().Get("q")
// ruleid: go.request-sql-injection
store.db.Query("SELECT * FROM t WHERE q='" + query + "'")
// source: go.request-command-injection
tool := c.Param("tool")
// ruleid: go.request-command-injection
exec.Command(tool)
// ok: go.request-sql-injection
stmt.Exec(query)
}
func typedReceiver(r *http.Request, d *sql.DB) {
// source: go.request-sql-injection
query := r.FormValue("query")
// ruleid: go.request-sql-injection
d.Query(query)
}
`,
  java: readFileSync('deploy/deep-adapters/rules/tests/java-flow-controls.txt', 'utf8'),
  cs: `
class FlowControls {
void Direct(Microsoft.AspNetCore.Http.HttpRequest req) {
// source: csharp.request-command-injection
var value = req.Query["command"];
// ruleid: csharp.request-command-injection
System.Diagnostics.Process.Start("/bin/sh", "-c " + value);
// source: csharp.request-sql-injection
var query = req.Query["query"];
// ruleid: csharp.request-sql-injection
new System.Data.SqlClient.SqlCommand(query, connection);
}
void Aliases(Microsoft.AspNetCore.Http.HttpRequest req) {
// source: csharp.request-command-injection
var value = req.Query["command"];
var alias = "echo " + value;
// ruleid: csharp.request-command-injection
System.Diagnostics.Process.Start("/bin/sh", "-c " + alias);
// source: csharp.request-sql-injection
var name = req.Query["name"];
var query = "SELECT * FROM users WHERE name='" + name + "'";
// ruleid: csharp.request-sql-injection
new System.Data.SqlClient.SqlCommand(query, connection);
// ok: csharp.request-command-injection
System.Diagnostics.Process.Start("echo", value);
// ok: csharp.request-command-injection
System.Diagnostics.Process.Start("/bin/sh", "-c echo fixed");
// ok: csharp.request-sql-injection
var command = new System.Data.SqlClient.SqlCommand("SELECT * FROM users WHERE name=@name", connection);
command.Parameters.AddWithValue("@name", name);
// ok: csharp.request-sql-injection
new Local.SqlCommand(query, connection);
}
void Unrelated(LocalRequest req) {
var value = req.Query["command"];
// ok: csharp.request-command-injection
System.Diagnostics.Process.Start("/bin/sh", "-c " + value);
// ok: csharp.request-sql-injection
new System.Data.SqlClient.SqlCommand(value, connection);
}
}
class UsersController : Controller {
void Classic() {
// source: csharp.request-sql-injection
var name = Request.QueryString["name"];
// ruleid: csharp.request-sql-injection
new System.Data.SqlClient.SqlCommand("SELECT * FROM t WHERE n='" + name + "'", connection);
// source: csharp.request-command-injection
var host = Request.Form["host"];
// ruleid: csharp.request-command-injection
System.Diagnostics.Process.Start("cmd.exe", "/c ping " + host);
}
}
`,
  rb: `
class FlowControls < ActionController::Base
  def direct
    # source: ruby.request-command-injection
    value = params[:command]
    # ruleid: ruby.request-command-injection
    Kernel.system(value)
    # source: ruby.request-sql-injection
    query = params[:query]
    # ruleid: ruby.request-sql-injection
    ActiveRecord::Base.connection.execute(query)
  end
  def aliases
    # source: ruby.request-command-injection
    value = params[:command]
    alias_value = "echo " + value
    # ruleid: ruby.request-command-injection
    Kernel.system(alias_value)
    # source: ruby.request-sql-injection
    name = params[:name]
    query = "SELECT * FROM users WHERE name='" + name + "'"
    # ruleid: ruby.request-sql-injection
    ActiveRecord::Base.connection.execute(query)
    # ok: ruby.request-command-injection
    Kernel.system("echo", value)
    # ok: ruby.request-command-injection
    Kernel.system("echo fixed")
    # ok: ruby.request-sql-injection
    User.where("name = ?", name)
    # ok: ruby.request-sql-injection
    Local::Base.connection.execute(query)
  end
end
class Unrelated
  def run
    value = params[:command]
    # ok: ruby.request-command-injection
    Kernel.system(value)
    # ok: ruby.request-sql-injection
    ActiveRecord::Base.connection.execute(value)
  end
end
class UsersController < ApplicationController
  def show
    # source: ruby.request-sql-injection
    name = params[:name]
    # ruleid: ruby.request-sql-injection, ruby.parameter-sql-text
    User.where("name = '#{name}'")
    # ok: ruby.request-sql-injection
    User.where(name: name)
    # ok: ruby.request-sql-injection
    User.find_by_sql(["SELECT * FROM users WHERE name = ?", name])
    # source: ruby.request-sql-injection
    template = params[:query]
    # ruleid: ruby.request-sql-injection
    User.find_by_sql([template, name])
    # source: ruby.request-command-injection
    host = params.fetch(:host)
    # ruleid: ruby.request-command-injection
    system("ping #{host}")
  end
end
`,
};
function fixtureExpectations(extension, content) {
  const expected = [], sources = new Map();
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index++) {
    const source = lines[index].match(/(?:\/\/|#) source: ([\w.-]+)/);
    if (source) sources.set(source[1], index + 2);
    const annotation = lines[index].match(/(?:\/\/|#) ruleid: ([\w., -]+)/);
    if (!annotation) continue;
    for (const rule of annotation[1].split(',').map(value => value.trim())) {
      expected.push({ rule: `opt.factory.rules.${rule}`, path: `semgrep-pattern-limited.${extension}`,
        line: index + 2, ...(sources.has(rule) ? { source_line: sources.get(rule) } : {}) });
    }
  }
  return expected;
}

function buildFixtures(temp) {
  copyFileSync(rulesPath, join(temp, 'semgrep-pattern-limited.yml'));
  copyFileSync('deploy/deep-adapters/rules/tests/python-controls.txt', join(temp, 'semgrep-pattern-limited.py'));
  for (const extension of ['js', 'ts']) copyFileSync('deploy/deep-adapters/rules/tests/javascript-controls.js', join(temp, `semgrep-pattern-limited.${extension}`));
  writeFileSync(join(temp, 'semgrep-pattern-limited.tsx'),
    readFileSync('deploy/deep-adapters/rules/tests/javascript-controls.js', 'utf8') + tsxQualificationSuffix);
  copyFileSync('deploy/deep-adapters/rules/tests/php-controls.php', join(temp, 'semgrep-pattern-limited.php'));
  for (const [extension, [, content]] of Object.entries(polyglotControls)) {
    writeFileSync(join(temp, `semgrep-pattern-limited.${extension}`), `${content}\n`);
  }
  for (const [extension, content] of Object.entries(flowControls)) {
    const path = join(temp, `semgrep-pattern-limited.${extension}`);
    let original = readFileSync(path, 'utf8');
    if (extension === 'go') original = original.replace('import "crypto/tls"', 'import "crypto/tls"\nimport "net/http"\nimport "os/exec"\nimport "database/sql"');
    writeFileSync(path, `${original}\n${content}\n`);
  }
  appendExtensionControls(temp, 'deploy/deep-adapters/rules/tests', path => readFileSync(path, 'utf8'),
    (path, content) => writeFileSync(path, content));
  fixtureManifest = readdirSync(temp).filter(name => !name.endsWith('.yml')).flatMap(name =>
    fixtureExpectations(name.split('.').at(-1), readFileSync(join(temp, name), 'utf8')));
  javascriptExpected = javascriptControlManifest();
  fixtureManifest = fixtureManifest.map(item => {
    if (!/\.(?:js|ts|tsx)$/.test(item.path)) return item;
    const fixed = javascriptExpected.find(expected => expected.path === item.path &&
      expected.rule === item.rule && expected.line === item.line);
    if (!fixed) throw new Error('Unreviewed JavaScript fixture expectation');
    return fixed;
  });
  verifyJavascriptControlMatrix(fixtureManifest);
  expectedRules = [...new Set(fixtureManifest.map(item => item.rule))].sort();
  configuredRules = [...readFileSync(rulesPath, 'utf8').matchAll(/^  - id: (.+)$/gm)].map(match => `opt.factory.rules.${match[1]}`).sort();
  const safeCounts = {};
  for (const content of Object.values(flowControls)) {
    for (const [, rule] of content.matchAll(/(?:\/\/|#) ok: ([\w.-]+)/g)) {
      const key = `opt.factory.rules.${rule}`;
      safeCounts[key] = (safeCounts[key] ?? 0) + 1;
    }
  }
  verifyFlowControlMatrix(fixtureManifest, safeCounts, configuredRules);
  if (JSON.stringify(expectedRules) !== JSON.stringify(configuredRules)) throw new Error('Configured rule missing explicit fixture expectation');
  return fixtureManifest;
}

let fixtureManifest = [], javascriptExpected = [], expectedRules = [], configuredRules = [];
// `--fixtures-only DIR` writes the exact native fixture inputs and their
// manifest without Docker, so rule authors can check them before CI.
if (image === '--fixtures-only') {
  mkdirSync(output, { recursive: true });
  const built = buildFixtures(output);
  writeFileSync(join(output, 'fixture-manifest.json'), `${JSON.stringify(built, null, 1)}\n`);
  process.exit(0);
}

const temp = mkdtempSync(join(tmpdir(), 'cf-semgrep-surface-'));
function docker(args) {
  const run = spawnSync('docker', args, { encoding: 'utf8', timeout: 120000, maxBuffer: 16 * 1024 * 1024 });
  if (run.error || run.status !== 0) throw new Error(`Docker control failed: ${run.error?.message ?? run.stderr}`);
  return run.stdout;
}
try {
  for (const path of [rulesPath, 'deploy/deep-adapters/profiles/semgrep-pattern-limited.json',
    'deploy/deep-adapters/rules/tests/python-controls.txt', 'deploy/deep-adapters/rules/tests/javascript-controls.js',
    'deploy/deep-adapters/rules/tests/tsx-controls.txt', 'deploy/deep-adapters/rules/tests/php-controls.php',
    'deploy/deep-adapters/rules/tests/java-flow-controls.txt',
    'deploy/deep-adapters/rules/tests/swift-trust-controls.txt',
    'scripts/verify_semgrep_surface.mjs', 'scripts/semgrep_mutation_controls.mjs',
    'deploy/deep-adapters/Dockerfile', 'factoryline/deep_audit_attestation.py',
    'factoryline/deep_audit_loop.py', 'factoryline/deep_audit_sarif.py', 'factoryline/audit_taxonomy.py']) {
    receipt.source[path] = hash(readFileSync(path));
  }
  if (receipt.source[rulesPath] !== profile.ruleset_sha256) throw new Error('Ruleset hash differs from profile');
  const id = docker(['image', 'inspect', image, '--format', '{{.Id}}']).trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(id)) throw new Error('Invalid immutable image ID');
  receipt.image_id = id;
  const base = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true', '--pids-limit=128', '--memory=2g', '--cpus=2',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777', '-e', 'HOME=/tmp', '-e', 'SEMGREP_SETTINGS_FILE=/tmp/settings.yml'];
  const bundled = JSON.parse(docker([...base, '--entrypoint', '/bin/cat', id, '/opt/factory/adapter-profile.json']));
  receipt.tool_version = docker([...base, '--entrypoint', profile.version_argv[0], id, ...profile.version_argv.slice(1)]).trim();
  if (receipt.tool_version !== profile.tool_version) throw new Error('Native executable version differs from profile');
  if (JSON.stringify(bundled) !== JSON.stringify(profile)) throw new Error('Image profile differs from candidate');
  const bundledRules = docker([...base, '--entrypoint', '/bin/cat', id, '/opt/factory/rules/semgrep-pattern-limited.yml']);
  if (hash(Buffer.from(bundledRules)) !== profile.ruleset_sha256) throw new Error('Image rules differ from candidate');
  fixtureManifest = buildFixtures(temp);
  receipt.fixture_manifest = fixtureManifest;
  // mkdtempSync defaults to 0700. The hardened image runs Semgrep as a
  // non-root user, so make only these synthetic, read-only test inputs
  // traversable before mounting the directory with Docker's readonly option.
  chmodSync(temp, 0o755);
  for (const name of readdirSync(temp)) chmodSync(join(temp, name), 0o644);
  const controls = docker([...base, '--mount', `type=bind,source=${temp},target=/src,readonly`,
    '--entrypoint', profile.commands[0].argv[0], id, '--test', '--json', '--disable-version-check', '--disable-nosem', '/src']);
  receipt.controls = JSON.parse(controls);
  const tested = Object.values(receipt.controls.results ?? {}).flatMap(result => Object.entries(result.checks ?? {}));
  if (tested.length !== expectedRules.length || tested.some(([, check]) => check.passed !== true || check.errors?.length)) {
    throw new Error('Incomplete or failing rule controls');
  }
  if (receipt.controls.config_missing_tests?.length || receipt.controls.config_with_errors?.length) {
    throw new Error('Missing or invalid rule controls');
  }
  receipt.controls_sha256 = hash(Buffer.from(controls));
  // Exercise suppression only after annotation testing: Semgrep's test runner
  // interprets nosemgrep comments differently from production scan output.
  const annotated = [];
  for (const extension of ['py', 'js', 'ts', 'tsx', 'php']) {
    const fixture = join(temp, `semgrep-pattern-limited.${extension}`);
    const content = readFileSync(fixture, 'utf8');
    const vulnerableCall = ['child_process.', 'exec', '(alias);'].join('');
    const suppressed = extension === 'py'
      ? content.replace('os.system(alias)', 'os.system(alias)  # nosemgrep: python.request-command-injection')
      : extension === 'php'
      ? content.replace("system($_GET['cmd']);", "system($_GET['cmd']); // nosemgrep: php.request-command-injection")
      : content.replace(vulnerableCall, vulnerableCall + ' // nosemgrep: javascript.request-command-injection');
    if (suppressed === content) throw new Error('Missing suppression control');
    const lines = suppressed.split(/\r?\n/);
    const line = lines.findIndex(value => value.includes('nosemgrep:')) + 1;
    annotated.push(`opt.factory.rules.${extension === 'py' ? 'python' : extension === 'php' ? 'php' : 'javascript'}.request-command-injection|semgrep-pattern-limited.${extension}|${line}`);
    writeFileSync(fixture, suppressed);
  }
  const argv = profile.commands[0].argv.slice(1);
  const reportIndex = argv.indexOf('--sarif-output');
  if (reportIndex < 0 || argv[reportIndex + 1] !== '{report}') throw new Error('Unexpected SARIF profile');
  argv.splice(reportIndex, 2, '--sarif');
  const native = docker([...base, '--mount', `type=bind,source=${temp},target=/src,readonly`,
    '--entrypoint', profile.commands[0].argv[0], id, ...argv.map(value => value === '{source}' ? '/src' : value)]);
  const sarif = JSON.parse(native);
  const driver = sarif.runs?.[0]?.tool?.driver;
  if (sarif.runs?.length !== 1 || driver?.name !== 'Opengrep OSS' ||
      driver.semanticVersion !== receipt.tool_version) throw new Error('Native report driver/version differs from pinned OpenGrep');
  receipt.native_driver = driver.name;
  mkdirSync(dirname(resolve(root, output)), { recursive: true });
  writeFileSync(`${output}.sarif`, native);
  const findings = (sarif.runs ?? []).flatMap(run => run.results ?? []);
  const disabled = verifyNativeControlFindings(sarif, fixtureManifest);
  const disabledKeys = disabled.logical_keys;
  const active = results => results.filter(result => !(result.suppressions ?? []).some(suppression => suppression.status !== 'rejected'));
  // Semgrep retains inSource metadata even with --disable-nosem. The worker
  // consumes all results from this profile; only the enabled scan excludes it.
  if (annotated.some(key => !disabledKeys.includes(key))) {
    throw new Error('Disabled suppression omitted an annotated control finding');
  }
  if (!argv.includes('--disable-nosem')) throw new Error('Production profile must disable inline suppression');
  const enabled = docker([...base, '--mount', `type=bind,source=${temp},target=/src,readonly`,
    '--entrypoint', profile.commands[0].argv[0], id,
    ...argv.filter(value => value !== '--disable-nosem').map(value => value === '{source}' ? '/src' : value)]);
  writeFileSync(`${output}.suppression-enabled.sarif`, enabled);
  const manifestKey = item => `${item.rule}|${item.path}|${item.line}`;
  const enabledReport = JSON.parse(enabled);
  for (const run of enabledReport.runs ?? []) {
    if (Array.isArray(run.results)) run.results = active(run.results);
  }
  const enabledControls = verifyNativeControlFindings(enabledReport,
    fixtureManifest.filter(item => !annotated.includes(manifestKey(item))));
  const polyglotExpected = fixtureManifest.filter(item => Object.keys(polyglotControls).includes(item.path.split('.').at(-1))).map(manifestKey).sort();
  const polyglotObserved = disabledKeys.filter(key => Object.keys(polyglotControls).some(extension => key.includes(`|semgrep-pattern-limited.${extension}|`)));
  if (JSON.stringify(polyglotObserved) !== JSON.stringify(polyglotExpected)) throw new Error('Polyglot exact native findings differ');
  receipt.polyglot_controls = { state: 'PASS', expected: polyglotExpected, scope: 'Pattern-limited candidates; synthetic controls, no precision or interprocedural claim.' };
  const sourceHashes = Object.fromEntries(readdirSync(temp).filter(name => !name.endsWith('.yml'))
    .map(name => [name, hash(readFileSync(join(temp, name)))]));
  receipt.source_sink_controls = verifySourceSinkFlows(sarif, fixtureManifest, sourceHashes);
  receipt.tsx_qualification = { state: 'PASS', baseline_javascript_findings_per_extension: 7,
    expected_tsx_findings: 9, source_sha256: sourceHashes['semgrep-pattern-limited.tsx'],
    expected: javascriptExpected.filter(item => item.path.endsWith('.tsx')) };
  // Use the existing production normalizer against retained native bytes and actual
  // fixture hashes. Python rechecks source/report bytes before and after ingestion.
  const roundtrip = spawnSync('python', ['-c', `
import json, sys
from pathlib import Path
from factoryline.deep_audit_sarif import normalize_sarif, _native_sarif_metadata, _native_sarif_paths
from factoryline.deep_audit_io import sha256_bytes
from factoryline.runtime_audit_common import RuntimeAuditError
root=Path(sys.argv[1]); profile=json.loads(sys.argv[2]); hashes=json.loads(sys.argv[3])
assert all(sha256_bytes((root / name).read_bytes()) == digest for name, digest in hashes.items())
raw=json.loads(sys.stdin.read())
report=_native_sarif_paths(_native_sarif_metadata(raw, profile, [{"executionSuccessful": True}]), hashes)
path=root/'native-control.sarif'
path.write_text(json.dumps(report), encoding='utf-8')
analyzer={"id":"semgrep-surface", "driver":"Opengrep OSS", "version":profile["tool_version"]}
normalized=normalize_sarif(root, {"path":path.name,"sha256":sha256_bytes(path.read_bytes())}, analyzer, hashes)
binding={"path":path.name,"sha256":sha256_bytes(path.read_bytes())}
for bad in ({**hashes, next(iter(hashes)): "0"*64}, {key:value for key,value in hashes.items() if not key.endswith('.go')}, {key:value for key,value in hashes.items() if not key.endswith('.tsx')}):
 try:
  normalize_sarif(root, binding, analyzer, bad)
 except RuntimeAuditError:
  pass
 else:
  raise AssertionError("changed source hash or missing language binding accepted")
assert all(sha256_bytes((root / name).read_bytes()) == digest for name, digest in hashes.items())
for finding in normalized["findings"]:
 for flow in finding["flows"]:
  for step in flow:
   assert step["source_sha256"] == hashes[step["path"]]
print(json.dumps(normalized))
`, temp, JSON.stringify(profile), JSON.stringify(sourceHashes)],
    { input: native, encoding: 'utf8', timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
  if (roundtrip.error || roundtrip.status !== 0) throw new Error(`Native normalization failed: ${roundtrip.error?.message ?? roundtrip.stderr}`);
  const normalized = JSON.parse(roundtrip.stdout);
  for (const expected of fixtureManifest.filter(item => item.source_line !== undefined)) {
    const finding = normalized.findings.find(item => item.rule_id === expected.rule &&
      item.locations[0].path === expected.path && item.locations[0].start_line === expected.line);
    if (!finding?.flows.some(steps => steps[0].start_line === expected.source_line &&
        steps.at(-1).start_line === expected.line)) throw new Error('Normalized source/sink trace differs');
  }
  writeFileSync(`${output}.normalized.json`, `${JSON.stringify(normalized, null, 2)}\n`);
  receipt.normalized_trace_sha256 = hash(Buffer.from(roundtrip.stdout));
  // Exercise the shipped Python/per-rule transport, not just the tool's SARIF.
  const execution = docker([...base, '--mount', `type=bind,source=${temp},target=/src,readonly`,
    '--entrypoint', '/usr/local/bin/python', id, '-I', '-c', `
import base64, json, tempfile, time
from pathlib import Path
from factoryline.deep_audit_io import _semgrep_rule_inventory, _semgrep_rule_runs, verify_semgrep_rule_execution
profile=json.loads(Path('/opt/factory/adapter-profile.json').read_text())
config=Path('/opt/factory/rules/semgrep-pattern-limited.yml').read_bytes()
sources=json.loads(__import__('sys').argv[1])
lane={**profile, 'rule_ids':json.loads(__import__('sys').argv[2]), 'timeout_seconds':90}
rules, inventory=_semgrep_rule_inventory(config, lane)
with tempfile.TemporaryDirectory(prefix='factory-native-') as scratch:
 evidence=_semgrep_rule_runs(profile, lane, Path('/src'), Path(scratch), rules, time.monotonic())
 evidence['ruleset_base64']=base64.b64encode(config).decode('ascii')
 checked=verify_semgrep_rule_execution(evidence, lane, sources, json.loads(Path('/src/native-control.sarif').read_text()))
 print(json.dumps({'verified':checked, 'evidence':evidence}))
`, JSON.stringify(sourceHashes), JSON.stringify(receipt.native_rule_ids ?? configuredRules.map(rule => rule.replace('opt.factory.rules.', '')))]);
  const nativeExecution = JSON.parse(execution);
  if (nativeExecution.verified.state !== 'VERIFIED' || nativeExecution.verified.findings !== findings.length ||
      nativeExecution.verified.rules.length !== expectedRules.length) throw new Error('Native per-rule transport differs');
  receipt.native_rule_execution_sha256 = hash(Buffer.from(execution));
  receipt.native_rule_execution = nativeExecution.verified;
  writeFileSync(`${output}.rule-execution.json`, execution);
  receipt.native_findings = findings.length;
  receipt.native_logical_controls = disabledKeys.length;
  receipt.inline_suppression_control = 'PASS';
  receipt.suppression_control = { annotated_findings: annotated.sort(), disabled_report_findings: disabled.raw_findings,
    enabled_unsuppressed_findings: enabledControls.raw_findings, enabled_sarif_sha256: hash(Buffer.from(enabled)) };
  receipt.native_rule_ids = [...new Set(findings.map(result => result.ruleId))].sort();
  receipt.native_sarif_sha256 = hash(Buffer.from(native));
  receipt.native_dataflow_findings = findings.filter(result => result.codeFlows?.length).length;
  receipt.dataflow_trace_state = receipt.native_dataflow_findings > 0 ? 'OBSERVED' : 'NOT_MEASURED';
  if (receipt.native_rule_ids.length !== expectedRules.length) throw new Error('Native profile omitted rules');
  receipt.detector_mutations = [];
  for (const ruleId of receipt.native_rule_ids) {
    const mutationArgv = [...argv.filter(value => value !== '{source}'),
      '--exclude-rule', ruleId, '/src'];
    const raw = docker([...base, '--mount', `type=bind,source=${temp},target=/src,readonly`,
      '--entrypoint', profile.commands[0].argv[0], id, ...mutationArgv]);
    const control = verifyRuleMutation(sarif, JSON.parse(raw), ruleId);
    const path = `${output}.mutation-${receipt.detector_mutations.length}.sarif`;
    writeFileSync(path, raw);
    receipt.detector_mutations.push({ ...control, report: path,
      native_sarif_sha256: hash(Buffer.from(raw)),
      argv_sha256: hash(Buffer.from(JSON.stringify(mutationArgv))) });
  }
  if (receipt.detector_mutations.length !== receipt.native_rule_ids.length) {
    throw new Error('Enabled rule mutation controls incomplete');
  }
  receipt.state = 'PASS';
} catch (error) {
  receipt.error = error.message;
  receipt.error_stack = error.stack;
} finally {
  // Only the exact temporary directory created by this process is removed.
  rmSync(temp, { recursive: true, force: true });
  mkdirSync(dirname(resolve(root, output)), { recursive: true });
  writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`);
}
console.log(JSON.stringify({ state: receipt.state, image_id: receipt.image_id, error: receipt.error }));
process.exitCode = receipt.state === 'PASS' ? 0 : 1;
