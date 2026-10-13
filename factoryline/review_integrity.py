"""Three fail-closed senior-review controls: intent/diff, freshness, and policy ownership."""

from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
import ast
from pathlib import Path
from typing import Any
from .revenueforge import AUTHORITY, RevenueForgeError


def _name(node: ast.AST | None) -> str:
    return ast.unparse(node) if node is not None else ""


def _resolve(node: ast.AST | None, aliases: dict[str, str]) -> str:
    name = _name(node)
    head, dot, tail = name.partition(".")
    return aliases.get(head, head) + dot + tail


def _targets(stmt: ast.AST) -> list[str]:
    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
    return [
        n.id
        for t in targets
        for n in ast.walk(t)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
    ]


def _true_arg(call: ast.AST, key: str) -> bool:
    return isinstance(call, ast.Call) and any(
        k.arg == key and isinstance(k.value, ast.Constant) and k.value.value is True
        for k in call.keywords
    )


def mock_patch_dict_slot(
    receiver,
    root,
    assertion,
    aliases,
    nodes,
    constructors,
    normalize,
    rebound,
    effective,
    root_name,
):
    while isinstance(receiver, ast.Attribute):
        receiver = receiver.value
    if (
        not isinstance(receiver, ast.Subscript)
        or root_name(receiver.value, None, {}) != root
        or not isinstance(receiver.slice, ast.Constant)
    ):
        return False
    context = _patch_dict_context(root, assertion, aliases, nodes, normalize, rebound)
    return context is not None and _literal_mock_slot(
        root,
        receiver.slice.value,
        context,
        assertion,
        aliases,
        nodes,
        constructors,
        normalize,
        rebound,
        effective,
    )


def _patch_dict_context(root, assertion, aliases, nodes, normalize, rebound):
    ancestors = getattr(assertion, "_oracle_ancestors", ())
    for node in nodes:
        if not isinstance(node, ast.With) or not any(
            parent is node for parent, _ in ancestors
        ):
            continue
        for item in node.items:
            call = item.context_expr
            if (
                not isinstance(call, ast.Call)
                or normalize(call, aliases) != "unittest.mock.patch.dict"
                or len(call.args) not in {1, 2}
                or call.keywords
                or not isinstance(call.args[-1], ast.Name)
                or call.args[-1].id != root
                or rebound(nodes, root, call.lineno, assertion.lineno)
            ):
                continue
            return call
    return None


def _literal_mock_slot(
    root,
    key,
    context,
    assertion,
    aliases,
    nodes,
    constructors,
    normalize,
    rebound,
    effective,
):
    for statement in nodes:
        if not isinstance(statement, ast.Assign) or statement.lineno >= context.lineno:
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == root
            for target in statement.targets
        ):
            continue
        if not isinstance(statement.value, ast.Dict) or not effective(
            statement, aliases
        ):
            return False
        if rebound(nodes, root, statement.lineno, assertion.lineno):
            return False
        if not _mapping_use_is_confined(root, statement, context, assertion, nodes):
            return False
        keys = [
            node.value
            for node in statement.value.keys
            if isinstance(node, ast.Constant)
        ]
        if len(keys) != len(statement.value.keys) or len(set(keys)) != len(keys):
            return False
        return any(
            isinstance(key_node, ast.Constant)
            and key_node.value == key
            and isinstance(value, ast.Call)
            and normalize(value, aliases) in constructors
            for key_node, value in zip(statement.value.keys, statement.value.values)
        )
    return False


def _mapping_use_is_confined(root, statement, context, assertion, nodes):
    allowed = context.args[-1] if context.args else None
    start = (statement.end_lineno, statement.end_col_offset)
    end = (assertion.lineno, assertion.col_offset)
    return not any(
        isinstance(node, ast.Name)
        and node.id == root
        and isinstance(node.ctx, ast.Load)
        and start < (node.lineno, node.col_offset) < end
        and node is not allowed
        for item in nodes
        for node in ast.walk(item)
    )


def _fixture_name(fn: ast.AST, aliases: dict[str, str]) -> str | None:
    for dec in getattr(fn, "decorator_list", ()):
        call = dec if isinstance(dec, ast.Call) else None
        if _resolve(call.func if call else dec, aliases) in {
            "pytest.fixture",
            "_pytest.fixture",
        }:
            return (
                next(
                    (
                        k.value.value
                        for k in (call.keywords if call else ())
                        if k.arg == "name"
                        and isinstance(k.value, ast.Constant)
                        and isinstance(k.value.value, str)
                    ),
                    None,
                )
                or fn.name
            )
    return None


def _fixture_step(
    stmt: ast.AST, app: str | None, testing: bool, aliases: dict
) -> tuple[str | None, bool]:
    if (
        app
        and isinstance(stmt, (ast.If, ast.Try, ast.For, ast.While, ast.With))
        and _mutated(ast.Module(body=[stmt], type_ignores=[]), {app})
    ):
        return app, False
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        value, names = stmt.value, _targets(stmt)
        if (
            isinstance(value, ast.Call)
            and _resolve(value.func, aliases) == "flask.Flask"
        ):
            return names[0] if len(names) == 1 else None, False
        if app and app in names:
            return None, False
        if app and any(
            _name(t).endswith((".testing", ".config['TESTING']", '.config["TESTING"]'))
            and _name(t).rsplit(".", 1)[0] == app
            for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
        ):
            return app, isinstance(value, ast.Constant) and value.value is True
    if (
        isinstance(stmt, ast.Expr)
        and app is not None
        and isinstance(stmt.value, ast.Call)
        and _name(stmt.value.func) == app + ".config.update"
    ):
        if stmt.value.args or any(
            keyword.arg is None for keyword in stmt.value.keywords
        ):
            return app, False
        setting = next(
            (k.value for k in stmt.value.keywords if k.arg == "TESTING"), None
        )
        if setting is not None:
            return app, isinstance(setting, ast.Constant) and setting.value is True
    return app, testing


def _fixture_terminal(
    stmt: ast.AST, app: str | None, testing: bool, aliases: dict
) -> bool | None:
    if isinstance(stmt, ast.Return):
        value = stmt.value
    elif isinstance(stmt, ast.Expr) and isinstance(
        stmt.value, (ast.Yield, ast.YieldFrom)
    ):
        value = stmt.value.value
    else:
        return None
    if value is None:
        return False
    return testing if isinstance(value, ast.Name) and value.id == app else False


def _fixture_testing(fn: ast.AST, aliases: dict[str, str]) -> bool:
    shadowed = {
        item.arg for item in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    }
    aliases = {name: value for name, value in aliases.items() if name not in shadowed}
    app, testing = None, False
    for stmt in getattr(fn, "body", ()):
        app, testing = _fixture_step(stmt, app, testing, aliases)
        result = _fixture_terminal(stmt, app, testing, aliases)
        if result is not None:
            return result
    return False


def flask_fixture_apps(tree: ast.AST, aliases: dict[str, str]) -> dict[str, bool]:
    """Summarize testing-enabled Flask fixture source; does not prove runtime execution."""
    return {
        name: _fixture_testing(fn, aliases)
        for fn in getattr(tree, "body", ())
        if (name := _fixture_name(fn, aliases))
    }


def _test_nodes(test: ast.AST):
    stack = list(getattr(test, "body", ()))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            stack.extend(ast.iter_child_nodes(node))


def _mutated(test: ast.AST, apps: set[str]) -> bool:
    for n in _test_nodes(test):
        if (
            isinstance(n, ast.Name)
            and n.id in apps
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ):
            return True
        if (
            isinstance(n, ast.Attribute)
            and _name(n.value).split(".", 1)[0] in apps
            and (
                isinstance(n.ctx, (ast.Store, ast.Del))
                or n.attr in {"config", "testing"}
            )
        ):
            return True
        if (
            isinstance(n, ast.Call)
            and n.args
            and isinstance(n.args[0], ast.Name)
            and n.args[0].id in apps
            and _resolve(n.func, {}) in {"setattr", "delattr"}
        ):
            return True
    return False


def _route(fn: ast.AST, aliases: dict[str, str], apps: set[str], effective):
    if len(fn.decorator_list) != 1:
        return None
    dec = fn.decorator_list[0]
    if (
        not isinstance(dec, ast.Call)
        or len(dec.args) != 1
        or dec.keywords
        or not isinstance(dec.func, ast.Attribute)
    ):
        return None
    path = dec.args[0]
    if (
        dec.func.attr != "route"
        or _name(dec.func.value) not in apps
        or not isinstance(path, ast.Constant)
        or not isinstance(path.value, str)
        or any(ch in path.value for ch in "<>")
        or not effective(dec, aliases)
    ):
        return None
    return path.value


def _flask_routes(test: ast.AST, aliases: dict, apps: set[str], effective) -> dict:
    routes = {}
    for fn in (
        n
        for n in ast.walk(test)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        path = _route(fn, aliases, apps, effective)
        if path is not None:
            routes.setdefault(path, []).append(fn)
    return routes


def _flask_clients(
    test: ast.AST, apps: set[str], effective, aliases: dict
) -> tuple[dict, set]:
    clients, bad, other = {}, set(), set()
    for stmt in _test_nodes(test):
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            continue
        value, targets = stmt.value, _targets(stmt)
        if len(targets) != 1:
            other.update(targets)
            continue
        app = (
            value.func.value.id
            if isinstance(value, ast.Call)
            and not value.args
            and not value.keywords
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "test_client"
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id in apps
            and effective(value, aliases)
            else None
        )
        target = targets[0]
        if app:
            if target in clients and clients[target] != app:
                bad.add(target)
            clients[target] = app
        else:
            other.add(target)
    return clients, bad | (other & clients.keys())


def _literal_client_get(call, clients, bad):
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr != "get" or len(call.args) != 1 or call.keywords:
        return False
    if not isinstance(call.func.value, ast.Name):
        return False
    return call.func.value.id in clients and call.func.value.id not in bad


def _effective_get_path(call, clients, bad, aliases, effective):
    if not _literal_client_get(call, clients, bad):
        return None
    path = call.args[0]
    if not isinstance(path, ast.Constant) or not isinstance(path.value, str):
        return None
    return path.value if effective(call, aliases) else None


def _dispatch_root(node):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _flask_dispatch_mutated(test, apps, clients):
    roots = apps | set(clients)
    for node in _test_nodes(test):
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            if (
                isinstance(node.ctx, (ast.Store, ast.Del))
                and _dispatch_root(node) in roots
            ):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if _dispatch_root(node.func) in apps and node.func.attr not in {
                "route",
                "test_client",
            }:
                return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            if isinstance(node.value, (ast.Attribute, ast.Subscript)):
                if _dispatch_root(node.value) in roots:
                    return True
    return False


def flask_invoked_callbacks(
    test: ast.AST,
    aliases: dict[str, str],
    apps: set[str],
    strong_callback_names: set[str],
    effective,
) -> set[str]:
    """Credit only local literal routes reached by an effective exact GET on a proven app.

    This bounded AST summary does not prove Flask runtime dispatch.
    """
    if not apps or _mutated(test, apps):
        return set()
    routes = _flask_routes(test, aliases, apps, effective)
    clients, bad = _flask_clients(test, apps, effective, aliases)
    if _flask_dispatch_mutated(test, apps, clients):
        return set()
    invoked = set()
    for call in _test_nodes(test):
        path = _effective_get_path(call, clients, bad, aliases, effective)
        if path is None:
            continue
        callbacks = routes.get(path, ())
        if (
            len(callbacks) == 1
            and callbacks[0].name in strong_callback_names
            and callbacks[0].lineno < call.lineno
        ):
            invoked.add(callbacks[0].name)
    return invoked


def _virtual_default(value, defaults):
    if not isinstance(value, ast.IfExp) or not isinstance(value.test, ast.Compare):
        return None
    test = value.test
    if len(test.ops) != 1 or not isinstance(test.ops[0], ast.Is):
        return None
    if len(test.comparators) != 1 or not isinstance(test.comparators[0], ast.Constant):
        return None
    if test.comparators[0].value is not None or _name(test.left) not in defaults:
        return None
    if _name(value.orelse) != _name(test.left):
        return None
    name = _name(value.body)
    return name.removeprefix("self.") if name.startswith("self.") else None


def _virtual_init_supported(init, invoke):
    if init is None or invoke is None:
        return False
    if init.decorator_list or invoke.decorator_list:
        return False
    if init.args.vararg or init.args.kwarg or init.args.kwonlyargs:
        return False
    return not any(
        not isinstance(item, (ast.Assign, ast.AnnAssign, ast.Pass))
        for item in init.body
    )


def _virtual_init_bindings(init, defaults):
    bindings, invalid = {}, set()
    for node in ast.walk(init):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            continue
        targets = (
            node.targets
            if isinstance(node, (ast.Assign, ast.Delete))
            else [node.target]
        )
        for target in targets:
            name = _name(target)
            if not name.startswith("self."):
                continue
            if (
                name in bindings
                or not isinstance(node, ast.Assign)
                or node not in init.body
            ):
                invalid.add(name)
            bindings[name] = _virtual_default(getattr(node, "value", None), defaults)
    return bindings, invalid


def virtual_dispatch_defaults(methods, aliases, effective):
    """Summarize an omitted-argument virtual method binding, never execute it."""
    init, invoke = methods.get("__init__"), methods.get("__call__")
    if not _virtual_init_supported(init, invoke):
        return {}
    arguments = [*init.args.posonlyargs, *init.args.args][1:]
    defaults = {
        item.arg
        for item, value in zip(
            arguments[-len(init.args.defaults) :], init.args.defaults
        )
        if isinstance(value, ast.Constant) and value.value is None
    }
    required = len(arguments) - len(init.args.defaults)
    bindings, invalid = _virtual_init_bindings(init, defaults)
    invalid.update(_virtual_binding_mutations(methods, bindings))
    resolved = _awaited_virtual_bindings(
        invoke, bindings, invalid, methods, aliases, effective
    )
    guards = _virtual_scope_guards(invoke)
    return (
        {"methods": sorted(resolved), "required_arguments": required, "guards": guards}
        if resolved and guards is not None
        else {}
    )


def _virtual_scope_guards(invoke):
    guards = []
    for item in invoke.body:
        if not isinstance(item, ast.If) or not any(
            isinstance(n, ast.Return) for n in item.body
        ):
            continue
        test = item.test
        if (
            not isinstance(test, ast.Compare)
            or len(test.ops) != 1
            or not isinstance(test.ops[0], ast.NotEq)
        ):
            return None
        left = test.left
        if not isinstance(left, ast.Subscript) or not isinstance(left.value, ast.Name):
            return None
        if (
            not isinstance(left.slice, ast.Constant)
            or len(test.comparators) != 1
            or not isinstance(test.comparators[0], ast.Constant)
            or not isinstance(left.slice.value, str)
            or type(test.comparators[0].value) not in (str, int, bool, type(None))
        ):
            return None
        parameters = [
            arg.arg for arg in [*invoke.args.posonlyargs, *invoke.args.args][1:]
        ]
        if left.value.id not in parameters:
            return None
        guards.append(
            {
                "index": parameters.index(left.value.id),
                "parameter": left.value.id,
                "key": left.slice.value,
                "value": test.comparators[0].value,
            }
        )
    return guards


def _virtual_binding_mutations(methods, bindings):
    return {
        _name(node)
        for name, method in methods.items()
        if name != "__init__"
        for node in ast.walk(method)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and _name(node) in bindings
    }


def _awaited_virtual_bindings(invoke, bindings, invalid, methods, aliases, effective):
    resolved = set()
    for node in _test_nodes(invoke):
        if not isinstance(node, ast.Await) or not isinstance(node.value, ast.Call):
            continue
        name = _name(node.value.func)
        method = bindings.get(name)
        if name not in invalid and method in methods and effective(node.value, aliases):
            resolved.add(method)
    return resolved


def _sha(v: object) -> str:
    return hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    p = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        p.relative_to(root)
    except ValueError as e:
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_PATH_REJECTED", "paths must remain inside the workspace"
        ) from e
    try:
        v = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_INPUT_INVALID", "inputs must be JSON objects"
        ) from e
    if not isinstance(v, dict):
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_INPUT_INVALID", "inputs must be JSON objects"
        )
    return v, p


def _write(root: Path, path: Path, core: dict[str, Any]) -> dict[str, Any]:
    target = path.resolve() if path.is_absolute() else (root / path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    result = {**core, "receipt_sha256": _sha(core)}
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".receipt.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {**result, "path": target.relative_to(root).as_posix()}


def _base(
    kind: str, ok: bool, findings: list[str], sources: dict[str, str]
) -> dict[str, Any]:
    return {
        "schema": f"factory.review-integrity.{kind}-receipt.v1",
        "marker": f"REVIEW_{kind.upper()}_READY"
        if ok
        else f"REVIEW_{kind.upper()}_BLOCKED",
        "ok": ok,
        "findings": findings,
        "sources": sources,
        "authority": {
            **AUTHORITY,
            "execution": False,
            "release": False,
            "policy_override": False,
        },
        "claim_boundary": "Local deterministic metadata validation only; not semantic code understanding, environment execution, signature verification, or release approval.",
    }


def _instant(value: object) -> datetime | None:
    """Parse a timezone-aware ISO-8601 instant or return None for ambiguous timestamp input."""
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _validate_intent_contract(contract: dict[str, Any]) -> None:
    if (
        set(contract) != {"schema", "approved_paths", "forbidden_terms", "approval"}
        or contract.get("schema") != "factory.intent-diff-contract.v1"
        or not isinstance(contract.get("approved_paths"), list)
    ):
        raise RevenueForgeError(
            "INTENT_DIFF_CONTRACT_INVALID",
            "contract needs approved_paths, forbidden_terms, and human/trusted approval",
        )


def _validate_diff_manifest(manifest: dict[str, Any]) -> None:
    if (
        set(manifest)
        != {"schema", "base_sha", "head_sha", "changed_paths", "added_text"}
        or manifest.get("schema") != "factory.diff-manifest.v1"
        or not isinstance(manifest.get("changed_paths"), list)
        or not isinstance(manifest.get("added_text"), str)
    ):
        raise RevenueForgeError(
            "INTENT_DIFF_MANIFEST_INVALID", "diff manifest must be explicit and bounded"
        )


def _intent_authority_findings(contract: dict[str, Any]) -> list[str]:
    approval = contract["approval"]
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        return ["E_INTENT_AUTHORITY_MISSING"]
    return []


def _scope_allows_path(path: object, approved_paths: list[Any]) -> bool:
    if not isinstance(path, str):
        return False
    return any(
        scope == "." or path == scope or path.startswith(scope.rstrip("/") + "/")
        for scope in approved_paths
    )


def _intent_scope_findings(
    contract: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    findings: list[str] = []
    for path in manifest["changed_paths"]:
        if not _scope_allows_path(path, contract["approved_paths"]):
            findings.append("E_INTENT_SCOPE_DRIFT:" + str(path))
    return findings


def _forbidden_term_findings(
    contract: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    added_text = manifest["added_text"].lower()
    return [
        "E_INTENT_FORBIDDEN_BEHAVIOR:" + term
        for term in contract.get("forbidden_terms", [])
        if isinstance(term, str) and term and term.lower() in added_text
    ]


def _intent_diff_core(
    root: Path,
    contract_path: Path,
    diff_path: Path,
    contract: dict[str, Any],
    manifest: dict[str, Any],
    findings: list[str],
) -> dict[str, Any]:
    core = _base(
        "intent_diff",
        not findings,
        findings,
        {
            "contract": contract_path.relative_to(root).as_posix(),
            "diff": diff_path.relative_to(root).as_posix(),
        },
    )
    core.update(
        {
            "action_summary": "Compare a declared diff against human-approved scope and forbidden behaviors before review promotion.",
            "base_sha": manifest["base_sha"],
            "head_sha": manifest["head_sha"],
            "repair_plan": [
                "Remove or separately approve the out-of-scope path or forbidden behavior."
                for _ in findings
            ],
        }
    )
    return core


def verify_intent_diff(
    root: Path, contract_path: Path, diff_path: Path, out: Path
) -> dict[str, Any]:
    """Fail closed when a declared change exceeds approved intent or forbidden behavior."""
    root = Path(root).resolve()
    c, cp = _read(root, contract_path)
    d, dp = _read(root, diff_path)
    _validate_intent_contract(c)
    find = _intent_authority_findings(c)
    _validate_diff_manifest(d)
    find.extend(_intent_scope_findings(c, d))
    find.extend(_forbidden_term_findings(c, d))
    core = _intent_diff_core(root, cp, dp, c, d, find)
    return _write(root, out, core)


def _validate_freshness_manifest(manifest: dict[str, Any]) -> None:
    if (
        set(manifest)
        != {"schema", "current_commit", "environment_sha256", "now", "receipts"}
        or manifest.get("schema") != "factory.receipt-freshness-manifest.v1"
        or not isinstance(manifest.get("receipts"), list)
    ):
        raise RevenueForgeError(
            "RECEIPT_FRESHNESS_MANIFEST_INVALID",
            "manifest needs current commit, environment digest, time, and receipts",
        )


def _freshness_metadata_valid(receipt: object) -> bool:
    return isinstance(receipt, dict) and set(receipt) == {
        "id",
        "commit",
        "environment_sha256",
        "expires_at",
        "nonce",
    }


def _freshness_expired(receipt: dict[str, Any], manifest: dict[str, Any]) -> bool:
    expires_at, manifest_now = (
        _instant(receipt["expires_at"]),
        _instant(manifest["now"]),
    )
    current_now = datetime.now(timezone.utc)
    reference_now = (
        max(current_now, manifest_now) if manifest_now is not None else current_now
    )
    return (
        not isinstance(receipt["nonce"], str)
        or not receipt["nonce"]
        or expires_at is None
        or manifest_now is None
        or expires_at <= reference_now
    )


def _freshness_receipt_findings(
    receipt: object, manifest: dict[str, Any], seen: set[Any]
) -> list[str]:
    if not _freshness_metadata_valid(receipt):
        return ["E_RECEIPT_METADATA_LOOSE"]
    if receipt["id"] in seen:
        return ["E_RECEIPT_REPLAY:" + str(receipt["id"])]
    seen.add(receipt["id"])
    findings = []
    if receipt["commit"] != manifest["current_commit"]:
        findings.append("E_RECEIPT_STALE_COMMIT:" + str(receipt["id"]))
    if receipt["environment_sha256"] != manifest["environment_sha256"]:
        findings.append("E_RECEIPT_ENVIRONMENT_DRIFT:" + str(receipt["id"]))
    if _freshness_expired(receipt, manifest):
        findings.append("E_RECEIPT_EXPIRED:" + str(receipt["id"]))
    return findings


def _freshness_core(
    root: Path, path: Path, manifest: dict[str, Any], findings: list[str]
) -> dict[str, Any]:
    core = _base(
        "freshness",
        not findings,
        findings,
        {"manifest": path.relative_to(root).as_posix()},
    )
    core.update(
        {
            "action_summary": "Reject stale, replayed, expired, or environment-mismatched release-critical receipts.",
            "receipt_count": len(manifest["receipts"]),
            "repair_plan": [
                "Re-run the exact gate for the current commit and environment with a new expiry and nonce."
                for _ in findings
            ],
        }
    )
    return core


def verify_receipt_freshness(
    root: Path, manifest_path: Path, out: Path
) -> dict[str, Any]:
    """Reject release receipts that are stale, replayed, expired, or environment mismatched."""
    root = Path(root).resolve()
    manifest, source = _read(root, manifest_path)
    _validate_freshness_manifest(manifest)
    seen: set[Any] = set()
    findings = []
    for receipt in manifest["receipts"]:
        findings.extend(_freshness_receipt_findings(receipt, manifest, seen))
    core = _freshness_core(root, source, manifest, findings)
    return _write(root, out, core)


def _validate_policy_pack(pack: dict[str, Any]) -> None:
    if (
        set(pack) != {"schema", "owner", "version", "approval", "rules"}
        or pack.get("schema") != "factory.team-policy-pack.v1"
        or not isinstance(pack.get("rules"), list)
    ):
        raise RevenueForgeError(
            "TEAM_POLICY_PACK_INVALID", "pack needs human-owned versioned rules"
        )


def _policy_identity_findings(pack: dict[str, Any]) -> list[str]:
    valid = (
        isinstance(pack.get("owner"), str)
        and bool(pack["owner"].strip())
        and isinstance(pack.get("version"), str)
        and bool(pack["version"].strip())
    )
    return [] if valid else ["E_POLICY_OWNER_OR_VERSION_MISSING"]


def _policy_approval_findings(pack: dict[str, Any]) -> list[str]:
    approval = pack.get("approval")
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        return ["E_POLICY_AGENT_OWNED"]
    return []


def _policy_rule_valid(rule: object) -> bool:
    return (
        isinstance(rule, dict)
        and set(rule) == {"id", "requirement", "gate"}
        and all(isinstance(rule[key], str) and rule[key] for key in rule)
    )


def _policy_rule_findings(pack: dict[str, Any]) -> list[str]:
    rules = pack["rules"]
    if not rules or not all(_policy_rule_valid(rule) for rule in rules):
        return ["E_POLICY_RULE_LOOSE"]
    return []


def _policy_core(
    root: Path, path: Path, pack: dict[str, Any], findings: list[str]
) -> dict[str, Any]:
    core = _base(
        "policy_pack",
        not findings,
        findings,
        {"pack": path.relative_to(root).as_posix()},
    )
    core.update(
        {
            "action_summary": "Verify a human-owned, versioned team policy pack before it is selected as a review baseline.",
            "owner": pack.get("owner"),
            "version": pack.get("version"),
            "rule_count": len(pack["rules"]),
            "repair_plan": [
                "Have the designated human/trusted owner approve explicit rule-to-gate mappings."
                for _ in findings
            ],
        }
    )
    return core


def verify_policy_pack(root: Path, pack_path: Path, out: Path) -> dict[str, Any]:
    """Verify that a selected team policy pack is explicit, versioned, and human owned."""
    root = Path(root).resolve()
    p, pp = _read(root, pack_path)
    _validate_policy_pack(p)
    find = _policy_identity_findings(p)
    find.extend(_policy_approval_findings(p))
    find.extend(_policy_rule_findings(p))
    core = _policy_core(root, pp, p, find)
    return _write(root, out, core)
