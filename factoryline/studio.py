"""Loopback-only local browser surface for the Factoryline target compiler."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
import json
import re
import secrets
import threading
import webbrowser

from .target_compiler import TARGETS, TargetCompileError, create_target_from_prompt


STUDIO_SCHEMA = "factory.studio.v1"
MAX_BODY_BYTES = 64 * 1024
LOOPBACK_HOST = "127.0.0.1"
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}")
FORBIDDEN_ACTIONS = {"deploy", "publish", "sign", "external-message", "credential", "connector-grant"}


class StudioRequestError(ValueError):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


def studio_status(root: Path, port: int) -> dict[str, Any]:
    """Return the exact local Studio authority without opening a listener."""
    resolved = Path(root).resolve()
    return {
        "schema": STUDIO_SCHEMA,
        "marker": "STUDIO_STATUS_EXACT",
        "root": str(resolved),
        "listener": {"host": LOOPBACK_HOST, "port": port, "production": False},
        "targets": TARGETS,
        "limits": {"max_body_bytes": MAX_BODY_BYTES, "output_scope": "beneath_root", "overwrite": False},
        "authority": {
            "can_create_starters": True,
            "can_deploy": False,
            "can_publish": False,
            "can_sign": False,
            "can_send_external_messages": False,
            "can_inject_credentials": False,
            "can_grant_connectors": False,
        },
    }


def _contained_output(root: Path, name: str) -> Path:
    if not NAME_PATTERN.fullmatch(name):
        raise StudioRequestError("PATH_REJECTED", "name must use 1-48 letters, digits, hyphens, or underscores")
    resolved_root = Path(root).resolve()
    output = (resolved_root / name).resolve()
    if output.parent != resolved_root:
        raise StudioRequestError("PATH_REJECTED", "output must be a direct child of Studio root")
    return output


def _validate_action(payload: dict[str, Any]) -> None:
    action = str(payload.get("action", "create"))
    if action in FORBIDDEN_ACTIONS:
        raise StudioRequestError("ACTION_FORBIDDEN", f"Studio cannot perform {action}", 403)
    if action != "create":
        raise StudioRequestError("ACTION_UNSUPPORTED", "only create is available")


def _target_and_prompt(payload: dict[str, Any]) -> tuple[str, str]:
    target = str(payload.get("target", ""))
    if target not in TARGETS:
        raise StudioRequestError("TARGET_UNSUPPORTED", f"target must be one of {', '.join(TARGETS)}")
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise StudioRequestError("SOURCE_REQUIRED", "prompt must be a non-empty string")
    return target, prompt


def _output_name(payload: dict[str, Any], prompt: str) -> str:
    requested_name = payload.get("name")
    if requested_name is not None and not isinstance(requested_name, str):
        raise StudioRequestError("NAME_INVALID", "name must be a string")
    default_name = re.sub(r"[^a-zA-Z0-9]+", "-", prompt.strip().lower()).strip("-")[:48] or "factory-target"
    return requested_name.strip() if isinstance(requested_name, str) and requested_name.strip() else default_name


def create_from_studio(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Compile one contained target from a validated Studio request."""
    _validate_action(payload)
    target, prompt = _target_and_prompt(payload)
    output_name = _output_name(payload, prompt)
    output = _contained_output(root, output_name)
    try:
        result = create_target_from_prompt(
            prompt,
            target=target,
            out_dir=output,
            name=output_name,
            purpose=str(payload.get("purpose", "auto")),
            trigger=str(payload.get("trigger", "manual")),
        )
    except TargetCompileError as exc:
        status = 409 if exc.code == "OUTPUT_EXISTS" else 400
        raise StudioRequestError(exc.code, exc.message, status) from exc
    return {**result, "studio_marker": "STUDIO_CONTAINED"}


def _studio_html(token: str) -> str:
    target_buttons = "".join(
        f'''<label class="target"><input type="radio" name="target" value="{key}" {'checked' if key == 'web' else ''}>
<span><strong>{value['label']}</strong><small>{value['summary']}</small></span></label>'''
        for key, value in TARGETS.items()
    )
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Factory Studio</title>
<style>
:root {{ color-scheme: light; --ink:#172033; --muted:#5f6b7a; --line:#d8e0e8; --blue:#1d4ed8; --green:#166534; --orange:#c2410c; --paper:#f4f7fa; }}
* {{ box-sizing:border-box; }} body {{ margin:0; font-family:Inter,ui-sans-serif,system-ui,sans-serif; color:var(--ink); background:var(--paper); }}
.topbar {{ height:64px; display:flex; align-items:center; justify-content:space-between; padding:0 5vw; color:white; background:#111827; }}
.topbar span {{ color:#93c5fd; font-size:13px; }} main {{ width:min(1180px,90vw); margin:0 auto; padding:38px 0 64px; }}
.intro {{ display:grid; grid-template-columns:1fr auto; gap:24px; align-items:end; padding-bottom:28px; border-bottom:1px solid var(--line); }}
.eyebrow {{ margin:0; color:var(--blue); font-size:12px; font-weight:800; }} h1 {{ margin:8px 0 0; font-size:38px; letter-spacing:0; }}
.boundary {{ padding:14px 16px; border-left:4px solid var(--green); background:#ecfdf5; font-size:13px; }}
form {{ margin-top:30px; display:grid; gap:24px; }} fieldset {{ border:0; padding:0; margin:0; }} legend,label {{ font-weight:700; }}
.targets {{ margin-top:10px; display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
.target {{ min-height:126px; display:flex; gap:10px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; cursor:pointer; }}
.target:has(input:checked) {{ border-color:var(--blue); box-shadow:inset 0 0 0 1px var(--blue); }} .target small {{ display:block; margin-top:8px; color:var(--muted); line-height:1.45; font-weight:400; }}
.inputs {{ display:grid; grid-template-columns:2fr 1fr 1fr; gap:16px; }} .field {{ display:grid; gap:8px; }}
input[type=text],select,textarea {{ width:100%; border:1px solid #94a3b8; border-radius:6px; padding:12px; background:white; color:var(--ink); font:inherit; }}
textarea {{ min-height:180px; resize:vertical; }} button {{ justify-self:start; border:0; border-radius:6px; padding:13px 18px; color:white; background:var(--green); font-weight:800; cursor:pointer; }}
button:disabled {{ opacity:.55; cursor:wait; }} #result {{ min-height:48px; padding:16px; border:1px solid var(--line); border-radius:8px; background:white; white-space:pre-wrap; font:13px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace; }}
.error {{ color:#991b1b; border-color:#fecaca!important; background:#fff1f2!important; }}
@media(max-width:900px) {{ .targets {{ grid-template-columns:1fr 1fr; }} .inputs {{ grid-template-columns:1fr; }} .intro {{ grid-template-columns:1fr; }} }}
@media(max-width:560px) {{ .targets {{ grid-template-columns:1fr; }} h1 {{ font-size:31px; }} }}
</style></head><body>
<header class="topbar"><strong>Factory Studio</strong><span>Local target compiler</span></header>
<main><section class="intro"><div><p class="eyebrow">INTENT TO PROOF-CARRYING STARTER</p><h1>Choose what you are building.</h1></div><div class="boundary">Loopback only. No publish, deploy, signing, credentials, connectors, or external messages.</div></section>
<form id="builder"><fieldset><legend>Target</legend><div class="targets">{target_buttons}</div></fieldset>
<div class="inputs"><label class="field">Project name<input id="name" type="text" maxlength="48" placeholder="derived from intent"></label><label class="field">Purpose<select id="purpose"><option>auto</option><option>developer</option><option>healthcare</option><option>fintech</option><option>marketplace</option><option>saas</option></select></label><label class="field">Trigger<select id="trigger"><option>manual</option><option>cron</option><option>hook</option><option>goal</option><option>heartbeat</option></select></label></div>
<label class="field">Intent<textarea id="prompt" maxlength="60000" required placeholder="Describe the worker, app, mobile experience, or operator workflow."></textarea></label>
<button id="compile" type="submit">Compile starter</button><output id="result">Ready. Generated targets begin blocked until their proof gates pass.</output></form></main>
<script>
const token={json.dumps(token)}; const form=document.getElementById('builder'); const result=document.getElementById('result'); const button=document.getElementById('compile');
form.addEventListener('submit',async(event)=>{{event.preventDefault();button.disabled=true;result.className='';result.textContent='Compiling locally...';
const target=new FormData(form).get('target'); const body={{action:'create',target,prompt:document.getElementById('prompt').value,name:document.getElementById('name').value,purpose:document.getElementById('purpose').value,trigger:document.getElementById('trigger').value}};
try{{const response=await fetch('/api/create',{{method:'POST',headers:{{'Content-Type':'application/json','X-Factory-Studio-Token':token}},body:JSON.stringify(body)}});const payload=await response.json();if(!response.ok)throw new Error(`${{payload.code}}: ${{payload.message}}`);result.textContent=`Compiled ${{payload.target_kind}}\n${{payload.out_dir}}\nReceipt: ${{payload.receipt}}\nState: ${{payload.status}}`;}}
catch(error){{result.className='error';result.textContent=String(error);}}finally{{button.disabled=false;}}}});
</script></body></html>'''


class _StudioHandler(BaseHTTPRequestHandler):
    server_version = "FactoryStudio/1"
    studio_root = Path(".")
    studio_token = ""
    status_payload: dict[str, Any] = {}

    def _headers(self, status: int, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

    def _json(self, status: int, value: dict[str, Any]) -> None:
        self._headers(status, "application/json; charset=utf-8")
        self.wfile.write(json.dumps(value, sort_keys=True).encode("utf-8"))

    def do_GET(self) -> None:
        """Serve only the Studio shell and its public boundary status."""
        if self.path == "/":
            self._headers(200, "text/html; charset=utf-8")
            self.wfile.write(_studio_html(self.studio_token).encode("utf-8"))
            return
        if self.path == "/api/status":
            payload = dict(self.status_payload)
            payload["listener"] = {**payload["listener"], "port": self.server.server_port}
            self._json(200, payload)
            return
        self._json(404, {"code": "NOT_FOUND", "message": "route not found"})

    def _content_length(self) -> int | None:
        try:
            return int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"code": "LENGTH_INVALID", "message": "invalid content length"})
            return None

    def do_POST(self) -> None:
        """Accept one token-bound target creation request within the size limit."""
        if self.path != "/api/create":
            self._json(404, {"code": "NOT_FOUND", "message": "route not found"})
            return
        if not secrets.compare_digest(self.headers.get("X-Factory-Studio-Token", ""), self.studio_token):
            self._json(403, {"code": "TOKEN_REQUIRED", "message": "valid Studio session token required"})
            return
        length = self._content_length()
        if length is None:
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413, {"code": "BODY_LIMIT", "message": f"body must be 1-{MAX_BODY_BYTES} bytes"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise StudioRequestError("JSON_OBJECT_REQUIRED", "request must be a JSON object")
            result = create_from_studio(self.studio_root, payload)
        except StudioRequestError as exc:
            self._json(exc.status, {"code": exc.code, "message": exc.message})
            return
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"code": "JSON_INVALID", "message": "request body must be valid UTF-8 JSON"})
            return
        self._json(201, result)

    def log_message(self, format: str, *args: object) -> None:
        """Suppress the default request log so request data stays out of stdout."""
        return


def make_handler(root: Path, token: str) -> type[BaseHTTPRequestHandler]:
    """Bind immutable root and session data to a request handler class."""
    return type("StudioHandler", (_StudioHandler,), {
        "studio_root": root,
        "studio_token": token,
        "status_payload": studio_status(root, 0),
    })


def create_server(root: Path, port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Create a loopback-only threaded development server and session token."""
    if port < 0 or port > 65535:
        raise StudioRequestError("PORT_INVALID", "port must be between 0 and 65535")
    resolved = Path(root).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer((LOOPBACK_HOST, port), make_handler(resolved, token))
    server.daemon_threads = True
    return server, token


def serve_studio(root: Path, port: int = 0, open_browser: bool = True,
                 on_started: Callable[[str], None] | None = None) -> None:
    """Run Factory Studio until interrupted and always close its listener."""
    server, _token = create_server(root, port)
    url = f"http://{LOOPBACK_HOST}:{server.server_port}/"
    print(f"Factory Studio: {url}", flush=True)
    print("Boundary: loopback development server; no deploy, publish, sign, credential, connector, or external-message authority.", flush=True)
    if on_started:
        on_started(url)
    if open_browser:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
