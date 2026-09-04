import json
import pytest
from factoryline.knowledge_handoff import create_knowledge_handoff, receive_knowledge_handoff
from factoryline.continuity import ContinuityError
from factoryline.cli import main
from test_engineering_memory import setup
from test_continuity import _principal, PURPOSE, SCOPE


def arguments(root):
    return (root, _principal("reader", ("reader",)), "tenant-a", PURPOSE, SCOPE, "specline", "forgeline")


def test_compact_deterministic_roundtrip(tmp_path):
    setup(tmp_path)
    args = arguments(tmp_path)
    packet = create_knowledge_handoff(*args)
    assert packet == create_knowledge_handoff(*args)
    assert '"summary"' not in json.dumps(packet)
    assert "proof.json" not in json.dumps(packet)
    result = receive_knowledge_handoff(*args, packet)
    assert len(result["memory"]["records"]) == 1
    assert result["authority"] == "none"


@pytest.mark.parametrize("change", ["artifact", "withdraw", "packet", "scope", "route", "sender"])
def test_receiver_rejects_stale_or_misrouted_knowledge(tmp_path, change):
    store = setup(tmp_path)
    args = list(arguments(tmp_path))
    packet = create_knowledge_handoff(*args)
    if change == "artifact":
        (tmp_path / "proof.json").write_text("changed")
    elif change == "withdraw":
        store.withdraw(_principal("reviewer", ("promoter",)), "tenant-a", "one", status="revoked", reason="invalid")
    elif change == "packet":
        packet["authority"] = "release"
    elif change == "scope":
        args[4] = "other"
    elif change == "sender":
        args[5] = "hsf"
    else:
        args[6] = "prestige"
    with pytest.raises(ContinuityError) as error:
        receive_knowledge_handoff(*args, packet)
    assert error.value.code == "E_HANDOFF_STALE_OR_INVALID"


def test_cli_packet_and_receive(tmp_path, capsys):
    setup(tmp_path)
    args = ["evidence-memory", "--root", str(tmp_path), "--tenant", "tenant-a", "--subject", "reader",
            "--purpose", PURPOSE, "--scope", SCOPE, "--sender", "specline", "--receiver", "forgeline"]
    assert main(args) == 0
    packet = capsys.readouterr().out
    (tmp_path / "packet.json").write_text(packet)
    assert main(args + ["--accept", "packet.json"]) == 0
    assert json.loads(capsys.readouterr().out)["authority"] == "none"
    assert main(args[:-2]) == 1
