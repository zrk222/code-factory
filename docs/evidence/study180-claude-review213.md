# Claude blinded review notes (Study180, 47 packets)

Reviewer: Claude (configured model claude-sonnet-5-5, 'Claude Sonnet 5.5'); AI labeler, blinded; serving model may differ from the configured identifier
Submitted (UTC): 2026-10-22T03:28:44Z
Prior exposure: none in this session to these repositories/commits; no prior labels, runs, scanner lanes, scores, or other submissions were accessed. Only review/ and targets/ in the bundle were read; no target code was executed, imported or installed.

## Labelling conventions
- Primitive is judged on the claim's wording. For HARDCODED_SECRET, 'credential-like material' means the assigned value, so plain placeholders ("not complete", a value that only echoes its own setting name) and public URLs are primitive FP. Under a purely syntactic reading ('credential-named binding receives a string literal') these 8 packets would be primitive TP: S180-002, 013, 015, 025, 027, 028, 031, 033.
- Actionable requires a defect plus supported severity in real context; test/demo/doc fixtures, maintainer build scripts and constants are FP. UNCLEAR is used where a real-looking weakness exists but deployment reach or an external dependency is not in the frozen source. No packet is labelled actionable TP; that is a result, not a target.
- No replacements or exclusions. These are AI labels, not human validation.

## Counts
Primitive: TP 39, FP 8, UNCLEAR 0
Actionable: TP 0, FP 42, UNCLEAR 5

## Per packet
### S180-001
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/conftest.py:31, tests/conftest.py:13, app/config/test.py:9-12
- rationale: Primitive: GUEST_PASSWORD = '123456x' is a static password literal. Actionable FP: test fixture; tests run against the in-memory SQLite TestConfig (app/config/test.py:12) per conftest.py:4,13, isolated from any real system.

### S180-002
- primitive: FP; actionable: FP; severity supported: NO
- evidence: docs/extensions/settings.py:15
- rationale: Primitive FP: BITLY_API_KEY is assigned a placeholder that echoes its own setting name, not credential material (a purely syntactic reading would call it TP). Actionable FP: docs example settings; no real key.

### S180-003
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/helpers.py:90, tests/helpers.py:85
- rationale: Primitive: os.system(quit_cmd) at line 90. Actionable FP: test helper; quit_cmd = cmd + ' --quit' where cmd is the test's own `px --verbose --port=<int> {flags}` string (helpers.py:114-123). Inputs are test constants/ports, no untrusted source.

### S180-004
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tools.py:263, tools.py:261
- rationale: Primitive: subprocess.check_output(..., shell=True) is present. Actionable FP: constant command `brew --prefix openssl`, darwin-only branch of the maintainer build script (nuitka()); no variable input. shell=True is unnecessary but harmless; an argv list is optional hygiene, not a security fix.

### S180-005
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/test_user.py:39, tests/test_user.py:38-46
- rationale: Primitive: new_password = 'z0o9x8w7' is a literal password. Actionable FP: local test variable for a change-password round trip against the in-memory test app.

### S180-006
- primitive: TP; actionable: FP; severity supported: NO
- evidence: demo/settings.py:19, demo/settings.py:1,6, README.rst:60
- rationale: Primitive: SECRET_KEY is a real-looking static literal. Actionable FP (moderate confidence): the file is explicitly 'Settings for Zinnia Demo' with DEBUG = True and a sqlite demo.db; it configures a demonstration project, and nothing shows the key protecting real user data or being reused by real deployments.
- uncertainty: Residual: README.rst:60 points to an online demo; if that site uses this exact key its sessions are forgeable, but the demo holds no sensitive data in the source I have.

### S180-007
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/helpers.py:148, tests/helpers.py:141-146
- rationale: Primitive: os.system(cmd) at line 148. Actionable FP: test helper; cmd is built by the tests plus a config path under pytest tmp_path; no untrusted input.

### S180-008
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:436
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: pip wheel with `dist` from get_paths() (tools.py:111-126: os name, machine, __version__).

### S180-009
- primitive: TP; actionable: FP; severity supported: NO
- evidence: app/config/test.py:9-12, tests/test_plugin_loader.py:9,20
- rationale: Primitive: SECRET_KEY literal is present. Actionable FP: class TestConfig; the adjacent comment states a test-only fixed key not used in any real environment; sqlite:// in-memory; loaded only by the test suite (test_plugin_loader.py:20, conftest.py:13).

### S180-010
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:218
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: `twine check wheel/*` constant plus sys.executable.

### S180-011
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:371
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: pip uninstall with `executable` = dist/python.exe built by the script.

### S180-012
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:502
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: docker build string; `wheels-dir` is the only external value (tools.py:480-486, get_argval) and is supplied by the maintainer/CI as a constant artifact path (build.yml:301).

### S180-013
- primitive: FP; actionable: FP; severity supported: NO
- evidence: app/plugin/oss/config.py:2, app/plugin/oss/app/controller.py:75-76
- rationale: Primitive FP: `access_key_secret = "not complete"` assigns a plain placeholder string, not credential-like material; the real value must be supplied by the deployer (controllers read it via lin_config.get_config). (Under a purely syntactic reading, 'credential-named binding receives a string literal', this would be primitive TP; I label on the claim's wording, 'credential-like material'.) Actionable FP: no secret is committed.

### S180-014
- primitive: TP; actionable: FP; severity supported: NO
- evidence: zinnia/tests/implementations/settings.py:8, zinnia/tests/implementations/settings.py:12-13
- rationale: Primitive: SECRET_KEY = 'secret-key' literal. Actionable FP: test-implementation settings (weak SHA1 hasher at lines 12-13 confirms test-only intent); dummy key.

### S180-015
- primitive: FP; actionable: FP; severity supported: NO
- evidence: app/plugin/qiniu/config.py:2, app/plugin/qiniu/config.py:1-3
- rationale: Primitive FP: `secret_key = "not complete"` assigns a plain placeholder string, not credential-like material; the real value must be supplied by the deployer (controllers read it via lin_config.get_config). (Under a purely syntactic reading, 'credential-named binding receives a string literal', this would be primitive TP; I label on the claim's wording, 'credential-like material'.) Actionable FP: no secret is committed.

### S180-016
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:99
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: constant string `ldd /bin/ls | grep musl > /dev/null`; the pipe is why a shell is used; no variable input.

### S180-017
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/conftest.py:29, tests/conftest.py:129, app/config/test.py:12
- rationale: Primitive: ROOT_PASSWORD = '123456' is a static password literal. Actionable FP: test-only fixture for an in-memory database (conftest.py:4,13; app/config/test.py:12); not a real credential.

### S180-018
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:213
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: `-m build ... --installer=uv` with sys.executable.

### S180-019
- primitive: TP; actionable: FP; severity supported: NO
- evidence: docs/extensions/settings.py:11
- rationale: Primitive: SECRET_KEY = 'secret-key' is a literal Django secret key. Actionable FP: settings for the documentation/extension example (docs/extensions/settings.py); dummy value; no deployment or real credential.

### S180-020
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:273
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: constant `upx --best --force-macos px`.

### S180-021
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/test_kerberos.py:1273, tests/test_kerberos.py:1268-1275
- rationale: Primitive: KRB_PASSWORD = 'testpassword123'. Actionable FP: password for a throwaway MIT KDC created in a local Docker test container (section M, lines 1268-1275); test-only credential for TEST.LOCAL.

### S180-022
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/test_network.py:43, tests/test_network.py:46
- rationale: Primitive: os.system(quit_cmd). Actionable FP: quit_cmd = f"px --port={port} --quit" with an integer test port; test code only.

### S180-023
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/test_config.py:266-270
- rationale: Primitive: subprocess.run(cmd, shell=True). Actionable FP: test code; cmd is px_bin plus flags generated by generate_config() inside the test; no untrusted input; the shell is how the test launches the px binary.

### S180-024
- primitive: TP; actionable: UNCLEAR; severity supported: UNCLEAR
- evidence: mysite/settings.py:24, mysite/settings.py:27-29, README.md (Deployment section)
- rationale: Primitive: SECRET_KEY is a committed static key. This is the application's main settings.py (not a test/demo path) and the README links a production deployment guide, so a deployer copying this file would ship a public signing key. But DEBUG=True and ALLOWED_HOSTS=[] show development settings, the project is a tutorial app, and nothing in the source shows a live deployment using this key, so CRITICAL is not established.
- uncertainty: Missing evidence: whether any production deployment uses this key (and whether the linked tutorial overrides it via environment variables). Repair if actionable: read SECRET_KEY from the environment, fail closed when absent, and rotate the exposed key.

### S180-025
- primitive: FP; actionable: FP; severity supported: NO
- evidence: docs/extensions/settings.py:13
- rationale: Primitive FP: TYPEPAD_SECRET_API_KEY is assigned a placeholder that echoes its own setting name, not credential material (a purely syntactic reading would call it TP). Actionable FP: docs example settings; no real key.

### S180-026
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:516
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: docker build with __version__ tags.

### S180-027
- primitive: FP; actionable: FP; severity supported: NO
- evidence: app/plugin/cos/config.py:2, app/plugin/cos/app/controller.py:115
- rationale: Primitive FP: `access_key_secret = "not complete"` assigns a plain placeholder string, not credential-like material; the real value must be supplied by the deployer (controllers read it via lin_config.get_config). (Under a purely syntactic reading, 'credential-named binding receives a string literal', this would be primitive TP; I label on the claim's wording, 'credential-like material'.) Actionable FP: no secret is committed.

### S180-028
- primitive: FP; actionable: FP; severity supported: NO
- evidence: docs/extensions/settings.py:17
- rationale: Primitive FP: MOLLOM_PRIVATE_KEY is assigned a placeholder that echoes its own setting name, not credential material (a purely syntactic reading would call it TP). Actionable FP: docs example settings; no real key.

### S180-029
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:368
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: pip install px-proxy --no-index with script-built paths.

### S180-030
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/fixtures.py:218, tests/fixtures.py:48,227,231
- rationale: Primitive: PARAMS_PASSWORD = '12345'. Actionable FP: pytest fixture value injected via monkeypatch env/test keyring; no real credential.

### S180-031
- primitive: FP; actionable: FP; severity supported: NO
- evidence: docs/extensions/settings.py:12
- rationale: Primitive FP: AKISMET_SECRET_API_KEY is assigned a placeholder that echoes its own setting name, not credential material (a purely syntactic reading would call it TP). Actionable FP: docs example settings; no real key.

### S180-032
- primitive: TP; actionable: FP; severity supported: NO
- evidence: tests/helpers.py:123, tests/helpers.py:114-118
- rationale: Primitive: subprocess.Popen(cmd, shell=True). Actionable FP: test helper launching `px --verbose --port=... {flags}` where flags are supplied by tests; no untrusted input.

### S180-033
- primitive: FP; actionable: FP; severity supported: NO
- evidence: pypress/views/account.py:38, pypress/views/account.py:132-133,163-165
- rationale: Primitive FP: ACCESS_TOKEN_URL = 'https://api.twitter.com/oauth/access_token' is a public OAuth endpoint, not credential material; the consumer key and secret are read from app config (account.py:132-133, 163-165). Actionable FP: public protocol constant.

### S180-034
- primitive: TP; actionable: UNCLEAR; severity supported: UNCLEAR
- evidence: app/config.py:20-21, app/config.py:40, README.md:335, app/dependencies.py:10,57-60
- rationale: Primitive: JWT_SECRET: str = 'change-this-secret' is a functional default signing secret (HS256, config.py:21). It is overridable via env/.env and the README marks it required; config.py shows no startup check rejecting the default. app/services/auth/jwt_handler.py, which would show how create_access_token/verify_token consume it, is absent from the frozen target, so I cannot confirm the default is used for signing or validated elsewhere.
- uncertainty: Missing evidence: the jwt_handler implementation (absent from the frozen tree) and production deployment configuration (infra/). If the default can silently sign production tokens this is actionable (repair: no default; fail startup unless set to >=32 random bytes outside DEV).

### S180-035
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:523
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: `docker push {t}` where t derives from a constant tag and __version__.

### S180-036
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:457
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: `auditwheel repair --strip {whl}` where whl comes from glob over the script's own wheel directory (tools.py:445-457); a hostile filename would need prior write access to the build dir.

### S180-037
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:234
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: nuitka build; flags constant, outdir from get_paths().

### S180-038
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:298
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: `{executable} get-pip.py`; executable is sys.executable or the script-built python.exe. (Separate, unclaimed note: get-pip.py is fetched over HTTPS and executed; that is a supply-chain pattern, not the claimed shell injection.).

### S180-039
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:275
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: constant `upx --best px`.

### S180-040
- primitive: TP; actionable: UNCLEAR; severity supported: UNCLEAR
- evidence: daphne/testing.py:210-211, daphne/testing.py:247-248, daphne/testing.py:256-257
- rationale: Primitive: pickle.load on a file opened at cls.setup_storage = os.path.join(tempfile.gettempdir(), 'setup.testio'), a fixed predictable name in the shared temp dir, created with default permissions (no 0600, no ownership check, no exclusive create). On a multi-user host a local attacker could pre-create or swap the file between save_setup and load_setup and pickle.load would run attacker code as the test runner. A real weak pattern, but the module is a testing helper (daphne.testing) and exploitation needs a shared host with a hostile local user; claimed HIGH is not established.
- uncertainty: Missing evidence: any non-test or shared-host usage, and the project's CI temp-dir configuration. HIGH is not supported by source alone; LOW to MEDIUM is plausible. If deemed actionable: use tempfile.mkdtemp/NamedTemporaryFile with 0600, or serialize with json instead of pickle.

### S180-041
- primitive: TP; actionable: UNCLEAR; severity supported: UNCLEAR
- evidence: daphne/testing.py:211, daphne/testing.py:267-268, daphne/testing.py:284-285
- rationale: Same pattern as S180-040 for result_storage = tempfile.gettempdir()/'result.testio': pickle.load at line 285 of a fixed-name file in the shared temp directory, written by the same process (save_result/save_exception, lines 262-277) with no protection against replacement. Testing helper; multi-user local attacker required; HIGH not established.
- uncertainty: Same missing evidence as S180-040. Repair if actionable: private temp directory with 0600 files, or json instead of pickle.

### S180-042
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:420
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: constant `upx --best python3*.dll libcrypto*.dll` (shell used for glob expansion).

### S180-043
- primitive: TP; actionable: FP; severity supported: NO
- evidence: app/cli/plugin/init.py:154, app/cli/plugin/init.py:61-69, app/cli/plugin/init.py:201-203
- rationale: Primitive: subprocess.check_call(cmd, shell=True). Actionable FP on this evidence: cmd = 'pip install -r ' + <app root>/plugin/<name>/requirements.txt (init.py:61,69) where <name> comes from `input()` in the interactive developer CLI init() (init.py:201-203). The only 'attacker' is the operator at the terminal, who already has a shell. Unquoted-path handling is robustness, not a security boundary.
- uncertainty: Residual: the plugin name is not validated, so metacharacters would be interpreted; no evidence the init command is exposed beyond a local operator.

### S180-044
- primitive: TP; actionable: FP; severity supported: NO
- evidence: catsky/rebang 1/chartnet/requests/packages/urllib3/packages/six.py:327, six.py:306-332
- rationale: Primitive: exec(...) is invoked at line 327. Actionable FP: this is the Python 2 branch (`else:` of `if PY3`) of the vendored six library's public exec_ helper; the exec'd text is the constant `exec code in globs, locs`, and the only in-file caller passes a constant function definition (lines 330-332). Vendored third-party code (old requests/urllib3 copy); executes no untrusted input; exec_ is intentionally an eval primitive. Outdated vendored libraries are a separate, unclaimed concern.

### S180-045
- primitive: TP; actionable: UNCLEAR; severity supported: UNCLEAR
- evidence: docker/server/server.py:9,13-14, easyauth/server.py:198,221,531, docker/server/docker_run.MD
- rationale: Primitive: AUTH_SECRET falls back to the literal 'abcd1234' when the env var is unset. In the deployable Docker server entrypoint this silently uses a publicly known value, and docker_run.MD's first example omits AUTH_SECRET. But the value is only stored in os.environ['RPC_SECRET'] and passed as server_secret to the websocket RPC endpoint /ws/easyauth (server.py:198,221); tokens are verified with RS256 and a private key (server.py:531), not with this secret. What the RPC endpoint exposes depends on the external easyrpc library, which is not in the frozen source.
- uncertainty: Missing evidence: the privileges reachable through /ws/easyauth with the RPC secret and whether it is exposed. CRITICAL not established. Repair if actionable: require AUTH_SECRET (exit if unset) or generate a random per-process value.

### S180-046
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:509
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: `docker push {t}` with constant tag + __version__.

### S180-047
- primitive: TP; actionable: FP; severity supported: NO
- evidence: genotrance/px tools.py:270
- rationale: Primitive: os.system/shell invocation is present at the cited line. Actionable FP: tools.py is the maintainer build/release script (invoked only via `python tools.py --wheel/--nuitka/--embed/--docker/...`, per docs/build.md and .github/workflows/build.yml:42,265,301 with constant arguments). The command strings are built from sys.executable, __version__ (pyproject), repo-derived paths, or constants; no network, user-data or privilege-boundary input reaches them. The invoker already has a shell. No security defect a maintainer must fix; at most an unquoted-path robustness nit. Specific: constant `upx --best px.exe python3*.dll libcrypto*.dll`.

