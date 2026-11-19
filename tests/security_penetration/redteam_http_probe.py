import json, sys, threading, http.client
from pathlib import Path

ROOT = r"C:\Users\rkatz\AppData\Local\Temp\opencode\cf\code-factory"
sys.path.insert(0, ROOT)
from factoryline.mcp import create_streamable_http_server

TOKEN = "B" * 40
PV = "2026-07-28"

def boot(origins):
    srv = create_streamable_http_server(Path(ROOT), bearer_token=TOKEN, port=0,
                                        allowed_origins=origins)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

def post(port, body, hdr=None, origin=None, method="POST", path="/mcp"):
    try:
        m = json.loads(body)["method"]
    except Exception:
        m = "initialize"
    h = {"Content-Type": "application/json", "Mcp-Method": m,
         "MCP-Protocol-Version": PV,
         "Accept": "application/json, text/event-stream",
         "Authorization": f"Bearer {TOKEN}"}
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
    p["_meta"] = {"io.modelcontextprotocol/protocolVersion": PV, "io.modelcontextprotocol/clientCapabilities": {}}
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": p})

def main():
    # Bugged server (literal sentinel origin)
    srv1, p1 = boot(("http://127.0.0.1:PORT",))
    print("== origin allowlist sentinel ==")
    for o in (None, "http://127.0.0.1:PORT", f"http://127.0.0.1:{p1}", "http://evil.example"):
        print(f"  origin={o!r:38} -> {post(p1, init_body(), origin=o)[0]}")
    srv1.shutdown()


    srv3, p3 = boot(())
    print("\n== with empty allowlist (default) ==")
    print(f"  no origin            -> {post(p3, init_body())[0]}")
    print(f"  any origin           -> {post(p3, init_body(), origin='http://evil.example')[0]}")
    print("\n== real MCP surface (no origin) ==")
    print(f"  tools/list           -> {post(p3, init_body('tools/list'))[0]}")
    st, b = post(p3, init_body("tools/call", {"name": "factory.audit_taxonomy", "arguments": {}}),
                 hdr={"Mcp-Name": "factory.audit_taxonomy"})
    print(f"  tools/call taxonomy  -> {st} ({len(b)} bytes)")
    print("\n== auth / framing ==")
    print(f"  no token             -> {post(p3, init_body(), hdr={'Authorization': ''})[0]}")
    print(f"  wrong token          -> {post(p3, init_body(), hdr={'Authorization': 'Bearer x'*20})[0]}")
    print(f"  GET                  -> {post(p3, None, method='GET')[0]}")
    print(f"  bad path             -> {post(p3, init_body(), path='/other')[0]}")
    print(f"  bad json             -> {post(p3, '{')[0]}")
    print(f"  array body           -> {post(p3, '[]')[0]}")
    print(f"  wrong ctype          -> {post(p3, init_body(), hdr={'Content-Type': 'text/plain'})[0]}")
    print(f"  wrong mcp-method     -> {post(p3, init_body(), hdr={'Mcp-Method': 'tools/list'})[0]}")
    print(f"  wrong proto          -> {post(p3, init_body(), hdr={'MCP-Protocol-Version': '2024-11-05'})[0]}")
    srv3.shutdown()

if __name__ == "__main__":
    main()
