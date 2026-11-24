from pathlib import Path

from factoryline.parameter_reach import findings_from_opengrep, main, reach


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _line(root: Path, name: str, needle: str) -> int:
    lines = (root / name).read_text(encoding="utf-8").splitlines()
    return next(i for i, line in enumerate(lines, 1) if needle in line)


def _one(root, name, needle, source, rule="python.parameter-shell-command"):
    line = _line(root, name, needle)
    return reach(root, [{"rule": rule, "path": name, "line": line, "source": source}])[
        0
    ]


def test_route_parameter_reaches_helper_sink_through_two_calls(tmp_path):
    _write(
        tmp_path,
        {
            "app/tools.py": "import os\n\ndef _archive(name):\n    os.system('tar czf out.tgz ' + name)\n\n"
            "def archive(label):\n    _archive(label + '.d')\n",
            "app/views.py": "from flask import Flask, request\nfrom .tools import archive\napp = Flask(__name__)\n\n"
            "@app.route('/a')\ndef view():\n    archive(request.args.get('label'))\n",
        },
    )
    row = _one(tmp_path, "app/tools.py", "os.system", "name")
    assert row["reach"] == "entry_reached"
    assert row["reach_chain"][0] == "request.args in app.views:view"
    assert any(
        "app.tools:archive calls app.tools:_archive" in step
        for step in row["reach_chain"]
    )


def test_mcp_tool_and_cli_entry_parameters_are_untrusted(tmp_path):
    _write(
        tmp_path,
        {
            "srv.py": "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n"
            "@mcp.tool()\ndef grep(pattern):\n    subprocess.run('grep ' + pattern, shell=True)\n",
            "cli.py": "import argparse, os\n\ndef _run(target):\n    os.system('ping ' + target)\n\n"
            "def main():\n    parser = argparse.ArgumentParser()\n    args = parser.parse_args()\n    _run(args.host)\n",
        },
    )
    assert (
        _one(tmp_path, "srv.py", "subprocess.run", "pattern")["reach"]
        == "entry_reached"
    )
    cli = _one(tmp_path, "cli.py", "os.system", "target")
    assert cli["reach"] == "entry_reached" and cli["reach_chain"][0].startswith(
        "cli argument args.host"
    )


def test_private_helper_called_only_with_constants_or_sanitized_values(tmp_path):
    _write(
        tmp_path,
        {
            "jobs.py": "import os, shlex\nTARGET = 'build'\n\ndef _make(goal):\n    os.system('make ' + goal)\n\n"
            "def build():\n    _make('all')\n    _make(TARGET)\n\ndef user(goal):\n    _make(shlex.quote(goal))\n",
        },
    )
    assert (
        _one(tmp_path, "jobs.py", "os.system", "goal")["reach"]
        == "callers_constant_only"
    )


def test_public_function_without_untrusted_callers_stays_library_surface(tmp_path):
    _write(
        tmp_path,
        {
            "lib.py": "import os\n\ndef convert(path):\n    os.system('convert ' + path)\n"
        },
    )
    assert _one(tmp_path, "lib.py", "os.system", "path")["reach"] == "public_api"


def test_unknown_argument_flow_is_not_demoted(tmp_path):
    _write(
        tmp_path,
        {
            "jobs.py": "import os\n\ndef _make(goal):\n    os.system('make ' + goal)\n\n"
            "def build(items):\n    for item in items:\n        _make(item)\n    _make(*items)\n",
        },
    )
    row = _one(tmp_path, "jobs.py", "os.system", "goal")
    assert row["reach"] == "unresolved"


def test_self_method_calls_and_keyword_arguments_resolve(tmp_path):
    _write(
        tmp_path,
        {
            "svc.py": "import os\nfrom flask import request\n\nclass Service:\n    def _run(self, value):\n"
            "        os.system('echo ' + value)\n\n    def handle(self):\n"
            "        self._run(value=request.form['v'])\n",
        },
    )
    assert _one(tmp_path, "svc.py", "os.system", "value")["reach"] == "entry_reached"


def test_opengrep_adapter_and_cli(tmp_path, capsys):
    _write(
        tmp_path,
        {
            "lib.py": "import os\n\ndef convert(path):\n    os.system('convert ' + path)\n"
        },
    )
    report = {
        "results": [
            {
                "check_id": "opt.factory.rules.python.parameter-shell-command",
                "path": str(tmp_path / "lib.py"),
                "start": {"line": 4},
                "extra": {"dataflow_trace": {"taint_source": ["CliLoc", [{}, "path"]]}},
            },
            {
                "check_id": "opt.factory.rules.python.parameter-path-join-without-containment",
                "path": str(tmp_path / "lib.py"),
                "start": {"line": 4},
                "extra": {"metavars": {"$P": {"abstract_content": "path"}}},
            },
            {
                "check_id": "opt.factory.rules.python.request-sql-injection",
                "path": "x.py",
                "start": {"line": 1},
                "extra": {},
            },
        ]
    }
    rows = findings_from_opengrep(report, str(tmp_path))
    assert rows == [
        {
            "rule": "python.parameter-shell-command",
            "path": "lib.py",
            "line": 4,
            "source": "path",
        },
        {
            "rule": "python.parameter-path-join-without-containment",
            "path": "lib.py",
            "line": 4,
            "source": "path",
        },
    ]
    (tmp_path / "og.json").write_text(
        __import__("json").dumps(report), encoding="utf-8"
    )
    assert (
        main(["--root", str(tmp_path), "--opengrep-json", str(tmp_path / "og.json")])
        == 0
    )
    assert '"public_api": 2' in capsys.readouterr().out


def test_mcp_module_tool_classes_and_argument_dicts_are_entries(tmp_path):
    _write(
        tmp_path,
        {
            "pkg/recipes.py": "from pathlib import Path\nROOT = Path('/r')\n\ndef load_recipe(recipe_name):\n"
            "    return (ROOT / f'{recipe_name}.yaml').read_text()\n",
            "pkg/mcp/handler.py": "from ..recipes import load_recipe\n\nasync def call_tool(name, arguments):\n"
            "    return load_recipe(arguments.get('recipe_name'))\n",
            "pkg/mcp/tools.py": "import os\n\nclass ToolRegistry:\n    async def run(self, target):\n"
            "        os.system('ping ' + target)\n\n    def _helper(self, value):\n        os.system(value)\n",
            "pkg/other.py": "def call_tool(arguments):\n    return arguments.get('x')\n",
        },
    )
    recipe = _one(
        tmp_path,
        "pkg/recipes.py",
        "read_text",
        "recipe_name",
        "python.parameter-path-join-without-containment",
    )
    assert recipe["reach"] == "entry_reached" and recipe["reach_chain"][0].startswith(
        "MCP tool arguments"
    )
    assert (
        _one(tmp_path, "pkg/mcp/tools.py", "'ping '", "target")["reach"]
        == "entry_reached"
    )
    assert (
        _one(tmp_path, "pkg/mcp/tools.py", "os.system(value)", "value")["reach"]
        != "entry_reached"
    )


def _tiers(root):
    from factoryline.review_audits import security_scan

    report = security_scan(root, cache_enabled=False)
    return {
        (row["raw_finding"]["code"], row["raw_finding"]["line"]): (
            row["tier"],
            row["evidence"],
        )
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"].startswith("SECURITY_")
    }


def test_audit_promotes_command_sink_reached_from_a_route(tmp_path):
    _write(
        tmp_path,
        {
            "tools.py": "import os, shlex\n\ndef archive(name):\n    os.system('tar czf o.tgz ' + name)\n\n"
            "def quoted(name):\n    os.system('tar czf o.tgz ' + shlex.quote(name))\n\n"
            "def offline(name):\n    os.system('tar czf o.tgz ' + name)\n",
            "web.py": "from flask import Flask, request\nfrom tools import archive, quoted\napp = Flask(__name__)\n\n"
            "@app.route('/a')\ndef view():\n    archive(request.args.get('n'))\n    quoted(request.args.get('n'))\n",
        },
    )
    tiers = _tiers(tmp_path)
    assert tiers[("SECURITY_OS_COMMAND", 4)] == (
        "SUPPORTED_DEFECT",
        "source_bound_entry_reach",
    )
    assert tiers[("SECURITY_OS_COMMAND", 7)][0] == "NEEDS_CONTEXT"
    assert tiers[("SECURITY_OS_COMMAND", 10)][0] == "NEEDS_CONTEXT"


def test_audit_keeps_needs_context_without_an_untrusted_caller(tmp_path):
    _write(
        tmp_path,
        {
            "tools.py": "import os\n\ndef archive(name):\n    os.system('tar czf o.tgz ' + name)\n",
            "jobs.py": "from tools import archive\n\ndef nightly():\n    archive('backup')\n",
        },
    )
    assert _tiers(tmp_path)[("SECURITY_OS_COMMAND", 4)][0] == "NEEDS_CONTEXT"
