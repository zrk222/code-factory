import ast

import pytest

from factoryline.review_integrity import implementation_completeness_findings


@pytest.mark.parametrize(
    "declaration",
    [
        "import click\n@click.group()",
        "import click as c\n@c.group()",
        "from click import group\n@group()",
    ],
)
def test_registered_click_group_is_a_container(declaration):
    source = declaration + "\ndef cli(): pass\n@cli.command()\ndef child(): return 1\n"
    assert not implementation_completeness_findings("app.py", ast.parse(source), source)


@pytest.mark.parametrize(
    "source",
    [
        "import click\n@click.command()\ndef cli(): pass",
        "import click\n@click.group()\ndef cli(): pass",
        "import click\n@click.group(invoke_without_command=True)\ndef cli(): pass\n@cli.command()\ndef child(): return 1",
        "import click\n@click.group(cls=Custom)\ndef cli(): pass\n@cli.command()\ndef child(): return 1",
        "class Fake: pass\nclick=Fake()\n@click.group()\ndef cli(): pass\n@cli.command()\ndef child(): return 1",
        "import click\n@click.group()\ndef cli(): pass\ncli=other\n@cli.command()\ndef child(): return 1",
        "import click\n@click.group()\ndef cli(): pass\n@cli.command()\ndef child(): pass",
    ],
)
def test_unfinished_or_unverified_bodies_remain_findings(source):
    findings = implementation_completeness_findings("app.py", ast.parse(source), source)
    assert any(f["code"] == "QUALITY_EMPTY_IMPLEMENTATION" for f in findings)


def test_nested_registered_group_with_help_is_a_container():
    source = """import click
@click.group()
def cli(): pass
@cli.group(help="Commands")
def subgroup(): pass
@subgroup.command()
def child(): return 1
"""
    assert not implementation_completeness_findings("app.py", ast.parse(source), source)


@pytest.mark.parametrize("mutation", ["click.group = fake", "cli.command = fake"])
def test_modified_decorator_namespace_is_not_trusted(mutation):
    source = f"""import click
@click.group()
def cli(): pass
{mutation}
@cli.command()
def child(): return 1
"""
    assert implementation_completeness_findings("app.py", ast.parse(source), source)
