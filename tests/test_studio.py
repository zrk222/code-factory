from __future__ import annotations

from http.client import HTTPConnection
from pathlib import Path
import json
import threading

import pytest

from factoryline.studio import (
    MAX_BODY_BYTES,
    StudioRequestError,
    create_from_studio,
    create_server,
    make_handler,
    serve_studio,
    studio_status,
)


def test_studio_status_is_exact_and_loopback_only(tmp_path: Path):
    status = studio_status(tmp_path, 4321)
    assert status["marker"] == "STUDIO_STATUS_EXACT"
    assert status["listener"] == {"host": "127.0.0.1", "port": 4321, "production": False}
    assert status["limits"]["overwrite"] is False
    assert status["authority"]["can_deploy"] is False
    assert status["authority"]["can_inject_credentials"] is False


def test_studio_contains_output_and_forbids_promotion(tmp_path: Path):
    result = create_from_studio(tmp_path, {
        "action": "create",
        "target": "worker",
        "prompt": "Build a deterministic inbox worker.",
        "name": "inbox-worker",
    })
    assert result["studio_marker"] == "STUDIO_CONTAINED"
    assert Path(result["out_dir"]).parent == tmp_path.resolve()

    with pytest.raises(StudioRequestError, match="PATH_REJECTED"):
        create_from_studio(tmp_path, {
            "action": "create",
            "target": "worker",
            "prompt": "Build another worker.",
            "name": "../escaped",
        })
    with pytest.raises(StudioRequestError, match="ACTION_FORBIDDEN"):
        create_from_studio(tmp_path, {"action": "publish"})
    assert not (tmp_path.parent / "escaped").exists()


def test_http_surface_requires_session_token_and_enforces_body_limit(tmp_path: Path):
    # Real requests exercise _StudioHandler.do_GET, do_POST, and log_message.
    server, token = create_server(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/api/status")
        response = connection.getresponse()
        assert response.status == 200
        status = json.loads(response.read())
        assert status["listener"]["port"] == server.server_port

        body = json.dumps({"action": "create", "target": "worker", "prompt": "Build a worker.", "name": "http-worker"})
        connection.request("POST", "/api/create", body=body, headers={"Content-Type": "application/json"})
        assert connection.getresponse().status == 403

        connection.request(
            "POST",
            "/api/create",
            body=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": str(MAX_BODY_BYTES + 1), "X-Factory-Studio-Token": token},
        )
        assert connection.getresponse().status == 413
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_handler_binding_and_serve_lifecycle(tmp_path: Path, monkeypatch, capsys):
    handler = make_handler(tmp_path, "session-token")
    assert handler.studio_root == tmp_path
    assert handler.studio_token == "session-token"

    events: list[str] = []

    class FakeServer:
        server_port = 43117

        def serve_forever(self, poll_interval: float) -> None:
            events.append(f"serve:{poll_interval}")

        def server_close(self) -> None:
            events.append("closed")

    monkeypatch.setattr("factoryline.studio.create_server", lambda root, port: (FakeServer(), "token"))
    serve_studio(tmp_path, open_browser=False, on_started=events.append)

    assert "http://127.0.0.1:43117/" in events
    assert events[-1] == "closed"
    assert "Factory Studio: http://127.0.0.1:43117/" in capsys.readouterr().out
