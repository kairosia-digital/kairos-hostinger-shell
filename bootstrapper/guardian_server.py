from __future__ import annotations

import html
import json
import os
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from provision_runner import (
    BootstrapPaths,
    CommandCallbacks,
    ProvisioningOrchestrator,
    redact_secrets,
    validate_provision_token,
)


_GUARDIAN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Kairós IA · Guardián de Activación</title>
  <style>
    :root {
      --bg: #0b1220;
      --card: #111b2e;
      --border: #1e2d4a;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #0284c7;
      --accent-hover: #0369a1;
      --ok: #16a34a;
      --warn: #d97706;
      --err: #dc2626;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at top, #13223d 0%, var(--bg) 60%);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      width: 100%;
      max-width: 560px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 28px 32px;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
    }
    .badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(2, 132, 199, 0.16);
      color: #38bdf8;
      border: 1px solid rgba(56, 189, 248, 0.3);
      margin-bottom: 12px;
    }
    h1 { margin: 0 0 8px; font-size: 22px; }
    p.sub { margin: 0 0 20px; color: var(--muted); font-size: 14px; line-height: 1.5; }
    label { display: block; font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 6px; }
    input {
      width: 100%;
      padding: 11px 14px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: #08101d;
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13px;
      margin-bottom: 14px;
    }
    button {
      width: 100%;
      padding: 12px 16px;
      border: 0;
      border-radius: 8px;
      background: var(--accent);
      color: #ffffff;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
    }
    button:hover { background: var(--accent-hover); }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .alert {
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 8px;
      font-size: 13px;
      line-height: 1.45;
    }
    .alert-err { background: rgba(220, 38, 38, 0.14); border: 1px solid rgba(220, 38, 38, 0.4); color: #fca5a5; }
    .alert-ok { background: rgba(22, 163, 74, 0.14); border: 1px solid rgba(22, 163, 74, 0.4); color: #86efac; }
    .progress-wrap {
      width: 100%;
      height: 10px;
      background: #08101d;
      border-radius: 999px;
      overflow: hidden;
      margin: 14px 0 8px;
      border: 1px solid var(--border);
    }
    .progress-bar {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #0284c7, #22c55e);
      transition: width 0.35s ease;
    }
    .creds {
      margin-top: 12px;
      background: #08101d;
      border: 1px dashed #22c55e;
      border-radius: 8px;
      padding: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13px;
      word-break: break-all;
    }
    .hidden { display: none; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Hostinger KVM 2 · Gestor de BD bloqueado</span>
    <h1>Kairós IA · Activación Segura de Instancia</h1>
    <p class="sub">
      Este servidor permanece protegido y sin exponer Odoo hasta completar la verificación criptográfica
      contra el Orquestador Central.
    </p>

    <div id="section-form">
      <form id="activate-form">
        <label for="token-input">Código de Activación Único (PROVISION_TOKEN)</label>
        <input id="token-input" name="provision_token" type="password" autocomplete="off"
               placeholder="prov_live_..." required />
        <label for="fqdn-input">Dominio de la instancia (autodetectado)</label>
        <input id="fqdn-input" name="instance_fqdn" type="text" value="__DETECTED_FQDN__" />
        <button id="submit-btn" type="submit">Activar y Desplegar Kairós IA</button>
      </form>
      <div id="error-box" class="alert alert-err __ERR_CLASS__">__ERR_MSG__</div>
    </div>

    <div id="section-progress" class="hidden">
      <div style="font-size:14px;font-weight:600;" id="step-label">Iniciando aprovisionamiento...</div>
      <div class="progress-wrap"><div class="progress-bar" id="progress-bar"></div></div>
      <div style="font-size:12px;color:var(--muted);" id="step-counter">Paso 0 / 5</div>
    </div>

    <div id="section-done" class="hidden">
      <div class="alert alert-ok">
        <strong>Instancia aprovisionada y sellada.</strong> Redirigiendo automáticamente al acceso de Odoo 19...
      </div>
      <div class="creds" id="done-summary"></div>
    </div>
  </div>

  <script>
    const form = document.getElementById('activate-form');
    const secForm = document.getElementById('section-form');
    const secProg = document.getElementById('section-progress');
    const secDone = document.getElementById('section-done');
    const errBox = document.getElementById('error-box');
    const stepLabel = document.getElementById('step-label');
    const stepCounter = document.getElementById('step-counter');
    const bar = document.getElementById('progress-bar');
    const doneSummary = document.getElementById('done-summary');

    async function refreshStatus() {
      try {
        const res = await fetch('/api/guardian/status', { cache: 'no-store' });
        if (!res.ok) return;
        const st = await res.json();
        if (st.phase === 'provisioning') {
          secForm.classList.add('hidden');
          secProg.classList.remove('hidden');
          secDone.classList.add('hidden');
          const pct = Math.min(100, Math.max(8, (st.step || 0) * 20));
          bar.style.width = pct + '%';
          stepLabel.textContent = st.step_label || 'Procesando...';
          stepCounter.textContent = 'Paso ' + (st.step || 0) + ' / 5';
        } else if (st.phase === 'completed') {
          secForm.classList.add('hidden');
          secProg.classList.add('hidden');
          secDone.classList.remove('hidden');
          doneSummary.textContent = '';
          const addLine = (label, value, strongVal = false) => {
            const row = document.createElement('div');
            row.appendChild(document.createTextNode(label + ': '));
            if (strongVal) {
              const s = document.createElement('strong');
              s.textContent = value;
              row.appendChild(s);
            } else {
              row.appendChild(document.createTextNode(value));
            }
            doneSummary.appendChild(row);
          };
          addLine('Expediente', st.installation_id || '');
          addLine('Estado inicial', st.provisioning_stage || '');
          addLine('Usuario admin', st.admin_login || '');
          if (st.generated_admin_password) {
            addLine('Contraseña temporal generada', st.generated_admin_password, true);
          }
          setTimeout(() => { window.location.href = '/web/login'; }, 3500);
        } else if (st.phase === 'error') {
          secProg.classList.add('hidden');
          secForm.classList.remove('hidden');
          document.getElementById('submit-btn').disabled = false;
          errBox.textContent = st.error_message || 'Error en la activación.';
          errBox.classList.remove('hidden');
        }
      } catch (_) {}
    }

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      errBox.classList.add('hidden');
      const btn = document.getElementById('submit-btn');
      btn.disabled = true;
      const payload = {
        provision_token: document.getElementById('token-input').value.trim(),
        instance_fqdn: document.getElementById('fqdn-input').value.trim()
      };
      try {
        const res = await fetch('/api/guardian/activate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) {
          btn.disabled = false;
          errBox.textContent = data.message || 'No se pudo iniciar la activación.';
          errBox.classList.remove('hidden');
          return;
        }
        secForm.classList.add('hidden');
        secProg.classList.remove('hidden');
        refreshStatus();
      } catch (err) {
        btn.disabled = false;
        errBox.textContent = 'Error de comunicación con el Guardián local.';
        errBox.classList.remove('hidden');
      }
    });

    refreshStatus();
    setInterval(refreshStatus, 2000);
  </script>
</body>
</html>
"""


@dataclass
class GuardianState:
    """Thread-safe snapshot of Guardian UI and active provisioning progress."""

    phase: str = 'locked'  # locked | provisioning | completed | error
    step: int = 0
    step_label: str = 'Esperando código PROVISION_TOKEN'
    installation_id: str = ''
    instance_fqdn: str = ''
    plan_tier: str = ''
    provisioning_stage: str = ''
    admin_login: str = ''
    generated_admin_password: str = ''
    error_message: str = ''
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                'phase': self.phase,
                'step': self.step,
                'step_label': self.step_label,
                'installation_id': self.installation_id,
                'instance_fqdn': self.instance_fqdn,
                'plan_tier': self.plan_tier,
                'provisioning_stage': self.provisioning_stage,
                'admin_login': self.admin_login,
                'generated_admin_password': self.generated_admin_password if self.phase == 'completed' else '',
                'error_message': self.error_message,
            }


class GuardianController:
    """Coordinates rate-limited token activation and server lifecycle transitions."""

    def __init__(
        self,
        orchestrator_url: str,
        paths: BootstrapPaths | None = None,
        callbacks: CommandCallbacks | None = None,
        default_fqdn: str = '',
        initial_admin_password: str = '',
        shell_version: str = '19.0.1.0.0',
        strict_preflight: bool = True,
        shutdown_grace_seconds: float = 3.0,
        max_activate_per_min: int = 5,
    ) -> None:
        self.orchestrator_url = orchestrator_url.rstrip('/')
        self.paths = paths or BootstrapPaths()
        self.callbacks = callbacks or CommandCallbacks()
        self.default_fqdn = default_fqdn.strip()
        self.initial_admin_password = initial_admin_password
        self.shell_version = shell_version
        self.strict_preflight = strict_preflight
        self.shutdown_grace_seconds = shutdown_grace_seconds
        self.max_activate_per_min = max_activate_per_min
        self.state = GuardianState(instance_fqdn=self.default_fqdn)
        self._rate_lock = threading.Lock()
        self._rate_buckets: dict[str, list[float]] = defaultdict(list)
        self._httpd: ThreadingHTTPServer | None = None
        self._worker: threading.Thread | None = None

    def attach_server(self, httpd: ThreadingHTTPServer) -> None:
        self._httpd = httpd

    def check_rate_limit(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        with self._rate_lock:
            recent = [ts for ts in self._rate_buckets[client_ip] if ts > cutoff]
            if len(recent) >= self.max_activate_per_min:
                self._rate_buckets[client_ip] = recent
                return False
            recent.append(now)
            self._rate_buckets[client_ip] = recent
            return True

    def start_activation(self, raw_token: str, instance_fqdn: str = '') -> tuple[bool, int, str]:
        clean_token = validate_provision_token(raw_token)
        resolved_fqdn = (instance_fqdn or self.default_fqdn or '').strip()

        with self.state._lock:
            if self.state.phase in ('provisioning', 'completed'):
                return False, HTTPStatus.CONFLICT, 'Activación ya en curso o completada.'
            self.state.phase = 'provisioning'
            self.state.step = 1
            self.state.step_label = 'Iniciando handshake contra Orquestador Central...'
            self.state.error_message = ''
            self.state.instance_fqdn = resolved_fqdn

        self._worker = threading.Thread(
            target=self._run_worker,
            args=(clean_token, resolved_fqdn),
            daemon=True,
        )
        self._worker.start()
        return True, HTTPStatus.ACCEPTED, 'Activación iniciada.'

    def _run_worker(self, clean_token: str, resolved_fqdn: str) -> None:
        runner = ProvisioningOrchestrator(
            orchestrator_url=self.orchestrator_url,
            paths=self.paths,
            callbacks=self.callbacks,
            shell_version=self.shell_version,
            strict_preflight=self.strict_preflight,
        )

        def on_progress(step: int, label: str) -> None:
            with self.state._lock:
                self.state.step = step
                self.state.step_label = label

        try:
            result = runner.run(
                provision_token=clean_token,
                instance_fqdn=resolved_fqdn,
                initial_admin_password=self.initial_admin_password,
                on_progress=on_progress,
            )
            with self.state._lock:
                self.state.phase = 'completed'
                self.state.step = 5
                self.state.step_label = 'Aprovisionamiento completado y sellado.'
                self.state.installation_id = result.get('installation_id', '')
                self.state.plan_tier = result.get('plan_tier', 'basic')
                self.state.provisioning_stage = result.get('stage', 'waiting_erp_sync')
                self.state.admin_login = result.get('admin_login', '')
                self.state.generated_admin_password = result.get('generated_admin_password', '')
                self.state.error_message = ''

            if self._httpd is not None:
                timer = threading.Timer(self.shutdown_grace_seconds, self._httpd.shutdown)
                timer.daemon = True
                timer.start()
        except Exception as exc:
            safe_err = redact_secrets(str(exc), [clean_token, self.initial_admin_password])
            with self.state._lock:
                self.state.phase = 'error'
                self.state.error_message = safe_err
                self.state.step_label = 'Error en activación'


def make_guardian_handler(controller: GuardianController) -> type[BaseHTTPRequestHandler]:
    """Bind a ThreadingHTTPServer handler class to a GuardianController instance."""

    class GuardianHTTPHandler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _client_ip(self) -> str:
            forwarded = self.headers.get('X-Forwarded-For', '')
            if forwarded:
                return forwarded.split(',')[0].strip()
            return self.client_address[0] if self.client_address else '0.0.0.0'

        def _detected_fqdn(self) -> str:
            if controller.default_fqdn:
                return controller.default_fqdn
            host = (self.headers.get('X-Forwarded-Host') or self.headers.get('Host') or '').strip()
            proto = (self.headers.get('X-Forwarded-Proto') or 'https').strip()
            if host and not host.startswith(('127.0.0.1', 'localhost', '0.0.0.0')):
                return f'{proto}://{host}'
            return ''

        def _send_json(self, code: int, payload: dict[str, Any]) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.close_connection = True
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, code: int, body: str) -> None:
            raw = body.encode('utf-8')
            self.close_connection = True
            self.send_response(code)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _is_db_manager_path(self) -> bool:
            path = self.path.split('?', 1)[0].lower()
            return path.startswith('/web/database')

        def do_GET(self) -> None:
            path = self.path.split('?', 1)[0]
            if self._is_db_manager_path():
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {'error': 'forbidden', 'message': 'Odoo database manager is disabled by Guardian.'},
                )
                return

            if path == '/healthz':
                self._send_json(HTTPStatus.OK, {'status': 'guardian', 'phase': controller.state.snapshot()['phase']})
                return

            if path == '/api/guardian/status':
                self._send_json(HTTPStatus.OK, controller.state.snapshot())
                return

            snap = controller.state.snapshot()
            fqdn_escaped = html.escape(snap['instance_fqdn'] or self._detected_fqdn(), quote=True)
            err_msg = html.escape(snap['error_message'] or '', quote=False)
            err_class = '' if snap['phase'] == 'error' and err_msg else 'hidden'
            page = (
                _GUARDIAN_HTML.replace('__DETECTED_FQDN__', fqdn_escaped)
                .replace('__ERR_MSG__', err_msg)
                .replace('__ERR_CLASS__', err_class)
            )
            self._send_html(HTTPStatus.OK, page)

        def do_POST(self) -> None:
            path = self.path.split('?', 1)[0]
            if self._is_db_manager_path():
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {'error': 'forbidden', 'message': 'Odoo database manager is disabled by Guardian.'},
                )
                return

            if path != '/api/guardian/activate':
                self._send_json(HTTPStatus.NOT_FOUND, {'error': 'not_found'})
                return

            client_ip = self._client_ip()
            if not controller.check_rate_limit(client_ip):
                self._send_json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {'error': 'rate_limit_exceeded', 'message': 'Demasiados intentos. Espere un minuto.'},
                )
                return

            try:
                content_len = int(self.headers.get('Content-Length') or 0)
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {'error': 'bad_request', 'message': 'Invalid Content-Length.'})
                return

            if content_len <= 0 or content_len > 8192:
                self._send_json(HTTPStatus.BAD_REQUEST, {'error': 'bad_request', 'message': 'Cuerpo JSON inválido.'})
                return

            try:
                body = json.loads(self.rfile.read(content_len).decode('utf-8'))
            except Exception:
                self._send_json(HTTPStatus.BAD_REQUEST, {'error': 'bad_request', 'message': 'JSON malformado.'})
                return

            if not isinstance(body, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {'error': 'bad_request', 'message': 'Se requiere un objeto JSON.'})
                return

            raw_token = str(body.get('provision_token') or '')
            fqdn = str(body.get('instance_fqdn') or self._detected_fqdn())
            try:
                ok, status_code, message = controller.start_activation(raw_token, fqdn)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {'error': 'invalid_token', 'message': str(exc)})
                return

            self._send_json(status_code, {'ok': ok, 'message': message})

    return GuardianHTTPHandler


def create_guardian_server(
    controller: GuardianController,
    host: str = '0.0.0.0',
    port: int = 8069,
) -> ThreadingHTTPServer:
    """Create and attach a ThreadingHTTPServer bound to the GuardianController."""
    httpd = ThreadingHTTPServer((host, port), make_guardian_handler(controller))
    controller.attach_server(httpd)
    return httpd


def main() -> int:
    orchestrator_url = os.environ.get('ORCHESTRATOR_URL', 'https://kaito.ddns.net').strip()
    provision_token = os.environ.get('PROVISION_TOKEN', '').strip()
    instance_fqdn = os.environ.get('INSTANCE_FQDN', '').strip()
    initial_admin_password = os.environ.get('ODOO_INITIAL_ADMIN_PASSWORD', '')
    shell_version = os.environ.get('SHELL_VERSION', '19.0.1.0.0').strip()
    strict_preflight = os.environ.get('KAIROS_STRICT_PREFLIGHT', 'true').strip().lower() not in ('0', 'false', 'no')

    paths = BootstrapPaths()
    if paths.sentinel_file.is_file():
        return 0

    controller = GuardianController(
        orchestrator_url=orchestrator_url,
        paths=paths,
        default_fqdn=instance_fqdn,
        initial_admin_password=initial_admin_password,
        shell_version=shell_version,
        strict_preflight=strict_preflight,
    )
    httpd = create_guardian_server(controller, host='0.0.0.0', port=8069)

    if provision_token:
        controller.start_activation(provision_token, instance_fqdn)

    try:
        httpd.serve_forever(poll_interval=0.25)
    finally:
        httpd.server_close()

    return 0 if paths.sentinel_file.is_file() else 1


if __name__ == '__main__':
    sys.exit(main())
