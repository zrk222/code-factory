"""Source identity controls for the semantic credential role helpers."""

import ast
import hashlib

from factoryline import review_audits, review_integrity
from factoryline.credential_role_bindings import matches_fact
from factoryline.credential_role_class_binding import class_attribute, effective_method
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.credential_role_setting_boundary import setting_boundary_nodes


def _index(tmp_path, texts):
    trees, sources, inventory = {}, {}, {}
    for relative, source in texts.items():
        path = tmp_path / relative
        raw = source.encode()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        review_integrity.bind_security_call_scopes(tree)
        trees[path] = tree
        sources[path] = raw
        inventory[path] = digest
    return SourceSnapshotIndex(tmp_path, trees, sources, inventory), trees


def _find_fact(index, path, tree, member):
    node = next(
        row
        for row in ast.walk(tree)
        if isinstance(row, (ast.Assign, ast.AnnAssign))
        and getattr(row, "value", None) is not None
        and isinstance(row.value, ast.Constant)
        and isinstance(row.value.value, str)
        and any(
            isinstance(target, ast.Name) and target.id == member
            for target in (row.targets if isinstance(row, ast.Assign) else [row.target])
        )
    )
    return declaration_fact(index, path, node)


def test_parameter_and_local_import_shadows_do_not_match_module_value(tmp_path):
    source = (
        "TOKEN = 'public'\n"
        "def parameter(TOKEN):\n    return requests.get(TOKEN)\n"
        "def imported():\n    from other import TOKEN\n    return requests.get(TOKEN)\n"
    )
    index, trees = _index(tmp_path, {"mod.py": source})
    path, tree = next(iter(trees.items()))
    fact = _find_fact(index, path, tree, "TOKEN")
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    argument = calls[0].args[0]
    assert not matches_fact(fact, path, argument, index, {path: {}}, {}, review_audits)
    argument = calls[1].args[0]
    assert not matches_fact(
        fact,
        path,
        argument,
        index,
        {path: {"TOKEN": (tmp_path / "other.py", "TOKEN")}},
        {},
        review_audits,
    )


def test_local_constant_has_local_role_and_cannot_claim_module_source(tmp_path):
    index, trees = _index(
        tmp_path,
        {
            "mod.py": "def make():\n    TOKEN = 'local'\n    return requests.get(TOKEN)\n"
        },
    )
    path, tree = next(iter(trees.items()))
    fact = _find_fact(index, path, tree, "TOKEN")
    use = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "TOKEN"
        and isinstance(node.ctx, ast.Load)
    )
    assert fact.owner == "<local:make>"
    assert fact.source_role == "local_literal"
    assert not matches_fact(fact, path, use, index, {path: {}}, {}, review_audits)


def test_nested_function_self_parameter_is_not_outer_instance(tmp_path):
    source = (
        "class API:\n    URL = 'https://example.test'\n"
        "    def send(self):\n"
        "        def nested(self):\n            return requests.get(self.URL)\n"
    )
    index, trees = _index(tmp_path, {"api.py": source})
    path, tree = next(iter(trees.items()))
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    fact = _find_fact(index, path, tree, "URL")
    use = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "URL"
    )
    aliases = {path: review_audits._module_security_aliases(tree)}
    assert not matches_fact(
        fact, path, use, index, aliases, {(path, "API"): owner}, review_audits
    )


def test_conditional_and_decorated_method_bindings_are_unknown(tmp_path):
    tree = ast.parse(
        "class Base:\n    def read(self): pass\n"
        "class Conditional(Base):\n    if enabled:\n        def read(self): pass\n"
        "class Decorated:\n    @wrapper\n    def read(self): pass\n"
        "class Reassigned:\n    read = replacement\n"
    )
    base, conditional, decorated, reassigned = tree.body
    assert (
        effective_method(
            [(None, "Conditional", conditional), (None, "Base", base)], "read"
        )
        is None
    )
    assert effective_method([(None, "Decorated", decorated)], "read") is None
    assert effective_method([(None, "Reassigned", reassigned)], "read") is None
    assert class_attribute([(None, "Conditional", conditional)], "read") is None


def _setting_snapshots(
    tmp_path,
    *,
    hook="return getattr(_app_settings, name)",
    setting_call="return get_setting(self.prefix + name, dflt)",
):
    texts = {
        "allauth/socialaccount/app_settings.py": (
            "from allauth.utils import get_setting\n"
            "class AppSettings:\n"
            "    def _setting(self, name, dflt):\n"
            "        from allauth.utils import get_setting\n"
            f"        {setting_call}\n"
            "    @property\n"
            "    def ADAPTER(self):\n"
            "        return self._setting('ADAPTER', 'allauth.socialaccount.adapter.DefaultAdapter')\n"
            "_app_settings = AppSettings('SOCIALACCOUNT_')\n"
            "def __getattr__(name):\n    " + hook + "\n"
        ),
        "allauth/utils.py": (
            "from django.conf import settings\n"
            "from django.utils.module_loading import import_string\n"
            "def import_callable(path_or_callable):\n"
            "    if not callable(path_or_callable):\n"
            "        ret = import_string(path_or_callable)\n"
            "    else:\n        ret = path_or_callable\n"
            "    return ret\n"
            "def get_setting(name, dflt):\n"
            "    getter = getattr(settings, 'ALLAUTH_SETTING_GETTER', lambda name, dflt: getattr(settings, name, dflt))\n"
            "    getter = import_callable(getter)\n"
            "    return getter(name, dflt)\n"
        ),
    }
    return _index(tmp_path, texts)


def test_declared_adapter_setting_requires_getattr_bridge_and_source_transfer(tmp_path):
    index, snapshots = _setting_snapshots(tmp_path)
    settings_path = tmp_path / "allauth/socialaccount/app_settings.py"
    owner = next(
        node for node in snapshots[settings_path].body if isinstance(node, ast.ClassDef)
    )
    aliases = {
        path: review_audits._module_security_aliases(tree)
        for path, tree in snapshots.items()
    }
    rows = setting_boundary_nodes(
        index, snapshots, settings_path, owner, aliases[settings_path]
    )
    assert rows is not None
    assert set(rows) == {
        "module_getattr",
        "settings_instance",
        "setting_method",
        "setting_transfer",
        "get_setting",
    }


def test_changed_module_hook_or_setting_target_cannot_complete_chain(tmp_path):
    index, snapshots = _setting_snapshots(tmp_path, hook="return globals()[name]")
    settings_path = tmp_path / "allauth/socialaccount/app_settings.py"
    owner = snapshots[settings_path].body[1]
    aliases = review_audits._module_security_aliases(snapshots[settings_path])
    assert (
        setting_boundary_nodes(index, snapshots, settings_path, owner, aliases) is None
    )

    index, snapshots = _setting_snapshots(
        tmp_path, setting_call="return self.other(name, dflt)"
    )
    settings_path = tmp_path / "allauth/socialaccount/app_settings.py"
    owner = next(
        node for node in snapshots[settings_path].body if isinstance(node, ast.ClassDef)
    )
    aliases = review_audits._module_security_aliases(snapshots[settings_path])
    assert (
        setting_boundary_nodes(index, snapshots, settings_path, owner, aliases) is None
    )
