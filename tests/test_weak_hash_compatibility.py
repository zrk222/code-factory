import pytest

from factoryline.adoption import run_repo_scan


@pytest.mark.parametrize(
    "arguments,expected_warning",
    [
        ("usedforsecurity=False", False),
        ('**{"usedforsecurity": False}', False),
        ('**{"usedforsecurity": True}', True),
        ("**options", True),
        ("usedforsecurity=False, **options", True),
        ('**{"usedforsecurity": False}, **{"usedforsecurity": False}', True),
        ("**{key: False}", True),
        ('**{"usedforsecurity": flag}', True),
        ('**{"usedforsecurity": False, **options}', True),
        ('**{"usedforsecurity": False, "usedforsecurity": True}', True),
    ],
)
@pytest.mark.parametrize("constructor", ["md5", "new"])
def test_md5_compatibility_keyword_expansion_is_definite(
    tmp_path, arguments, expected_warning, constructor
):
    prefix = "'md5', " if constructor == "new" else ""
    (tmp_path / "hashing.py").write_text(
        "import hashlib\n"
        "def checksum(payload, options, key, flag):\n"
        f"    return hashlib.{constructor}({prefix}payload, {arguments})\n",
        encoding="utf-8",
    )
    result = run_repo_scan(tmp_path)
    codes = [row["code"] for row in result["static_security"]["findings"]]
    assert ("SECURITY_WEAK_HASH" in codes) is expected_warning
