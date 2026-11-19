"""Red team HTTP probe for the local MCP transport (DeepSeek 4.1 report F1-F3).

Self-contained: starts its own server on port 0. Exits non-zero on regression.
"""

import json
import sys
import threading
import http.client
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[2])
sys.path.insert(0, ROOT)
from factoryline.mcp import create_streamable_http_server  # noqa: E402

TOKEN = "B" * 40
PV = "2026-07-28"
_FAILS = []


def boot(origins, port=0):
    srv = create_streamable_http_server(
        Path(ROOT), bearer_token=TOKEN, port=port, allowed_origins=origins
    )
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def post(port, body, hdr=None, origin=None, method="POST", path="/mcp"):
    try:
        m = json.loads(body)["method"]
    except Exception:
        m = "initialize"
    h = {
        "Content-Type": "application/json",
        "Mcp-Method": m,
        "MCP-Protocol-Version": PV,
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {TOKEN}",
    }
    if origin:
        h["Origin"] = origin
    h.update(hdr or {})
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def init_body(method="initialize", params=None):
    p = dict(params or {})
    p["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": PV,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": p})


def check(name, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'} {name}: {got} (want {want})")
    if not ok:
        _FAILS.append(name)


def main():
    print("== F1: allow-origin placeholder resolves to the bound port ==")
    srv, port = boot(("http://127.0.0.1:PORT",))
    check(
        "real origin allowed",
        post(port, init_body(), origin=f"http://127.0.0.1:{port}")[0],
        200,
    )
    check(
        "raw sentinel no longer matches",
        post(port, init_body(), origin="http://127.0.0.1:PORT")[0],
        403,
    )
    check(
        "foreign origin refused",
        post(port, init_body(), origin="http://evil.example")[0],
        403,
    )
    check("no origin allowed", post(port, init_body())[0], 200)
    srv.shutdown()

    print("== F1b: {port} placeholder form ==")
    srv, port = boot(("http://127.0.0.1:{port}",))
    check(
        "{port} resolves",
        post(port, init_body(), origin=f"http://127.0.0.1:{port}")[0],
        200,
    )
    srv.shutdown()

    print("== F1c: empty allowlist still fail-closes on any origin ==")
    srv, port = boot(())
    check(
        "foreign origin refused",
        post(port, init_body(), origin="http://evil.example")[0],
        403,
    )
    srv.shutdown()

    print("== F2: missing metadata has its own marker ==")
    srv, port = boot(())
    st, b = post(
        port,
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
    )
    check("status", st, 400)
    check("marker", json.loads(b)["error"]["data"]["marker"], "MCP_HTTP_META_MISSING")
    srv.shutdown()

    print("== F3: initialize advertises the enforced version ==")
    srv, port = boot(())
    st, b = post(port, init_body())
    check("status", st, 200)
    check("advertised version", json.loads(b)["result"]["protocolVersion"], PV)
    check(
        "echoed version accepted",
        post(port, init_body(), hdr={"MCP-Protocol-Version": PV})[0],
        200,
    )
    srv.shutdown()

    print("== unchanged guards ==")
    srv, port = boot(())
    check("no token", post(port, init_body(), hdr={"Authorization": ""})[0], 401)
    check(
        "wrong token",
        post(port, init_body(), hdr={"Authorization": "Bearer " + "x" * 40})[0],
        401,
    )
    check(
        "rebinding host", post(port, init_body(), hdr={"Host": "evil.example"})[0], 403
    )
    check("GET", post(port, None, method="GET")[0], 405)
    check("bad path", post(port, init_body(), path="/other")[0], 404)
    check("bad json", post(port, "{")[0], 400)
    check("array body", post(port, "[]")[0], 400)
    check(
        "wrong ctype",
        post(port, init_body(), hdr={"Content-Type": "text/plain"})[0],
        415,
    )
    check(
        "wrong mcp-method",
        post(port, init_body(), hdr={"Mcp-Method": "tools/list"})[0],
        400,
    )
    check(
        "wrong proto",
        post(port, init_body(), hdr={"MCP-Protocol-Version": "2024-11-05"})[0],
        400,
    )
    check("tools/list", post(port, init_body("tools/list"))[0], 200)
    srv.shutdown()

    print(f"\n{'FAILED: ' + ', '.join(_FAILS) if _FAILS else 'all checks passed'}")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
