from __future__ import annotations

import configparser
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


EXPECTED_ADDONS: tuple[str, ...] = (
    'kairos_digitization',
    'odoo_kairos_addon',
    'kairos_incidencias',
    'menu_visibility_control',
)


@dataclass(frozen=True)
class BootstrapPaths:
    """Filesystem layout used during provisioning inside the Hostinger KVM 2 container."""

    data_dir: Path = Path('/var/lib/odoo')
    addons_dir: Path = Path('/mnt/extra-addons')
    odoo_conf: Path = Path('/etc/odoo/odoo.conf')
    vpn_dir: Path = Path('/etc/kairos-vpn')
    mail_dir: Path = Path('/etc/kairos-mail')
    shm_dir: Path = Path('/dev/shm')
    inject_script_path: Path = Path('/opt/kairos-bootstrapper/inject_config.py')
    db_name: str = 'odoo_prod'

    @property
    def sentinel_file(self) -> Path:
        return self.data_dir / '.provisioned'

    @property
    def shm_tar_path(self) -> Path:
        return self.shm_dir / 'module.tar.gz'

    @property
    def shm_payload_path(self) -> Path:
        return self.shm_dir / 'payload.json'

    @property
    def shm_result_path(self) -> Path:
        return self.shm_dir / 'inject_result.json'


def _read_db_params(paths: BootstrapPaths) -> dict[str, str]:
    params = {
        'host': os.environ.get('DB_HOST', 'db'),
        'port': os.environ.get('DB_PORT', '5432'),
        'user': os.environ.get('DB_USER', 'odoo'),
        'password': os.environ.get('DB_PASSWORD', ''),
    }
    if paths.odoo_conf.is_file():
        parser = configparser.ConfigParser()
        parser.read(paths.odoo_conf, encoding='utf-8')
        if parser.has_section('options'):
            opts = parser['options']
            params['host'] = opts.get('db_host', params['host']) or params['host']
            params['port'] = opts.get('db_port', params['port']) or params['port']
            params['user'] = opts.get('db_user', params['user']) or params['user']
            params['password'] = opts.get('db_password', params['password']) or params['password']
    return params


def _is_root_posix() -> bool:
    return hasattr(os, 'geteuid') and os.geteuid() == 0


def _wrap_odoo_user(cmd: list[str]) -> list[str]:
    if _is_root_posix():
        return ['gosu', 'odoo', *cmd]
    return cmd


def _chown_odoo_if_root(target: Path) -> None:
    if not _is_root_posix():
        return
    try:
        shutil.chown(target, user='odoo', group='odoo')
    except LookupError:
        pass


def default_drop_odoo_db(paths: BootstrapPaths) -> None:
    """Drop target Odoo PostgreSQL database if it exists."""
    db = _read_db_params(paths)
    env = os.environ.copy()
    if db['password']:
        env['PGPASSWORD'] = db['password']
    subprocess.run(
        [
            'dropdb',
            '--if-exists',
            '-h',
            db['host'],
            '-p',
            db['port'],
            '-U',
            db['user'],
            paths.db_name,
        ],
        env=env,
        check=True,
    )


def default_init_odoo_db(paths: BootstrapPaths) -> None:
    """Create a fresh UTF8 database and install base Kairós modules cleanly."""
    db = _read_db_params(paths)
    env = os.environ.copy()
    if db['password']:
        env['PGPASSWORD'] = db['password']

    default_drop_odoo_db(paths)
    subprocess.run(
        [
            'createdb',
            '-h',
            db['host'],
            '-p',
            db['port'],
            '-U',
            db['user'],
            '-T',
            'template0',
            '-E',
            'UTF8',
            paths.db_name,
        ],
        env=env,
        check=True,
    )

    modules_csv = ','.join(('l10n_es', *EXPECTED_ADDONS))
    subprocess.run(
        _wrap_odoo_user([
            'odoo',
            '-c',
            str(paths.odoo_conf),
            '-d',
            paths.db_name,
            '-i',
            modules_csv,
            '--without-demo=all',
            '--stop-after-init',
            '--no-http',
        ]),
        check=True,
    )


def default_run_inject_config(
    paths: BootstrapPaths,
    payload_path: Path,
    result_path: Path,
    runtime_env: dict[str, str],
) -> dict[str, Any]:
    """Execute inject_config.py inside odoo shell against odoo_prod."""
    child_env = os.environ.copy()
    child_env.update(runtime_env)
    child_env['KAIROS_PAYLOAD_FILE'] = str(payload_path)
    child_env['KAIROS_RESULT_FILE'] = str(result_path)

    script_dir = str(paths.inject_script_path.parent)
    shell_snippet = (
        f'import sys\n'
        f'sys.path.insert(0, {script_dir!r})\n'
        f'import inject_config\n'
        f'inject_config.run_in_odoo_shell(env)\n'
    )

    subprocess.run(
        _wrap_odoo_user([
            'odoo',
            'shell',
            '-c',
            str(paths.odoo_conf),
            '-d',
            paths.db_name,
            '--no-http',
        ]),
        input=shell_snippet,
        text=True,
        env=child_env,
        check=True,
    )

    if not result_path.is_file():
        raise RuntimeError('inject_config.py completed without writing result metadata.')
    return json.loads(result_path.read_text(encoding='utf-8'))


@dataclass
class CommandCallbacks:
    """Injectable callbacks wrapping OS/Odoo subprocesses for testability."""

    init_odoo_db: Callable[[BootstrapPaths], None] = default_init_odoo_db
    run_inject_config: Callable[[BootstrapPaths, Path, Path, dict[str, str]], dict[str, Any]] = (
        default_run_inject_config
    )
    drop_odoo_db: Callable[[BootstrapPaths], None] = default_drop_odoo_db


def redact_secrets(text: str, secrets_list: list[str] | None = None) -> str:
    """Scrub tokens, API keys, JWTs, and passwords from error messages/logs."""
    cleaned = str(text or '')
    for secret in secrets_list or []:
        s = (secret or '').strip()
        if len(s) >= 4:
            cleaned = cleaned.replace(s, '***REDACTED***')

    patterns = (
        r'(prov_live_[A-Za-z0-9_\-]+)',
        r'(upd_live_[A-Za-z0-9_\-]+)',
        r'(a3br_[A-Za-z0-9_\-]+)',
        r'(AIza[0-9A-Za-z_\-]{12,})',
        r'(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)',
        r'(Bearer\s+[A-Za-z0-9._\-]+)',
        r'([?&]key=)[^&\s]+',
    )
    cleaned = re.sub(patterns[6], r'\1***REDACTED***', cleaned, flags=re.IGNORECASE)
    for pat in patterns[:6]:
        cleaned = re.sub(pat, '***REDACTED***', cleaned)
    return cleaned


def validate_provision_token(raw_token: str) -> str:
    """Validate syntactic structure of a one-time PROVISION_TOKEN."""
    token = (raw_token or '').strip()
    if not token:
        raise ValueError('El PROVISION_TOKEN es obligatorio.')
    if len(token) > 256:
        raise ValueError('El PROVISION_TOKEN excede la longitud máxima permitida.')
    if any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in token):
        raise ValueError('El PROVISION_TOKEN contiene caracteres no válidos.')
    return token


def _http_json_request(
    url: str,
    method: str,
    body: dict[str, Any] | None = None,
    bearer_token: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'KairosHostingerShell/19.0.1.0.0',
    }
    if bearer_token:
        headers['Authorization'] = f'Bearer {bearer_token}'

    data = json.dumps(body, ensure_ascii=False).encode('utf-8') if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8')
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        err_body = ''
        try:
            err_body = exc.read().decode('utf-8', errors='replace')
        except Exception:
            pass
        detail = err_body[:400] if err_body else exc.reason
        raise RuntimeError(f'HTTP {exc.code} al llamar a {url}: {detail}') from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f'Error de red conectando con {url}: {exc.reason}') from exc


def download_and_verify_tar_gz(
    download_url: str,
    bearer_token: str,
    expected_sha256: str,
    dest_tar_path: Path,
    timeout: int = 120,
) -> str:
    """Download .tar.gz into RAM/tmpfs and verify SHA-256 in constant time."""
    dest_tar_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_tar_path.exists():
        dest_tar_path.unlink()

    headers = {
        'Authorization': f'Bearer {bearer_token}',
        'User-Agent': 'KairosHostingerShell/19.0.1.0.0',
    }
    req = urllib.request.Request(download_url, headers=headers, method='GET')
    hasher = hashlib.sha256()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            fd = os.open(dest_tar_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as out_handle:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    out_handle.write(chunk)
    except urllib.error.HTTPError as exc:
        err_body = ''
        try:
            err_body = exc.read().decode('utf-8', errors='replace')
        except Exception:
            pass
        raise RuntimeError(
            f'Fallo descargando artefacto efímero (HTTP {exc.code}): {err_body[:300]}'
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f'Error de red descargando artefacto: {exc.reason}') from exc

    actual_sha = hasher.hexdigest().lower()
    expected_clean = (expected_sha256 or '').strip().lower()
    if not expected_clean or not hmac.compare_digest(actual_sha, expected_clean):
        raise RuntimeError(
            f'Integridad SHA-256 inválida para el artefacto descargado (esperado={expected_clean[:12]}..., obtenido={actual_sha[:12]}...).'
        )
    return actual_sha


def safe_extract_tar_gz(tar_path: Path, target_dir: Path) -> None:
    """Safely extract .tar.gz rejecting path traversal, symlinks/hardlinks, and device nodes."""
    target_dir.mkdir(parents=True, exist_ok=True)
    target_resolved = target_dir.resolve()

    with tarfile.open(tar_path, mode='r:gz') as tf:
        members = tf.getmembers()
        for member in members:
            member_name = member.name.replace('\\', '/')
            if not member_name or member_name.startswith('/') or ':' in member_name.split('/')[0]:
                raise RuntimeError(f'Entrada de archivo tar insegura (ruta absoluta): {member.name}')

            parts = [p for p in member_name.split('/') if p and p != '.']
            if any(p == '..' for p in parts):
                raise RuntimeError(f'Entrada de archivo tar insegura (path traversal): {member.name}')

            if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo() or member.isdev():
                raise RuntimeError(f'Tipo de entrada tar no permitido: {member.name}')

            dest_path = (target_resolved / Path(*parts)).resolve()
            if dest_path != target_resolved and target_resolved not in dest_path.parents:
                raise RuntimeError(f'Extracción fuera del directorio destino: {member.name}')

        for member in members:
            member_name = member.name.replace('\\', '/')
            parts = [p for p in member_name.split('/') if p and p != '.']
            if not parts:
                continue
            dest_path = target_resolved / Path(*parts)
            if member.isdir():
                dest_path.mkdir(parents=True, exist_ok=True)
                os.chmod(dest_path, 0o750)
                _chown_odoo_if_root(dest_path)
            elif member.isfile():
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                with extracted, dest_path.open('wb') as out:
                    shutil.copyfileobj(extracted, out)
                os.chmod(dest_path, 0o750 if dest_path.suffix == '.sh' else 0o640)
                _chown_odoo_if_root(dest_path)

    for addon in EXPECTED_ADDONS:
        manifest = target_dir / addon / '__manifest__.py'
        if not manifest.is_file():
            raise RuntimeError(f'El artefacto extraído no contiene el módulo requerido: {addon}')


def _write_secret_file(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(content)


def write_vpn_config(vpn_dir: Path, payload: dict[str, Any]) -> str:
    """Persist WireGuard or Tailscale configuration under /etc/kairos-vpn for vpn container."""
    vpn = payload.get('vpn') or {}
    mode = str(vpn.get('mode') or 'wireguard').strip().lower()
    vpn_dir.mkdir(parents=True, exist_ok=True)

    if mode == 'wireguard':
        vps_priv = str(vpn.get('vps_private_key') or '').strip()
        win_pub = str(vpn.get('windows_public_key') or '').strip()
        psk = str(vpn.get('preshared_key') or '').strip()
        vps_cidr = str(vpn.get('vps_ip') or '10.88.10.1/24').strip()
        win_ip = str(vpn.get('windows_ip') or '10.88.10.2/32').strip()
        listen_port = int(vpn.get('listen_port') or 51820)

        if not vps_priv or not win_pub:
            raise RuntimeError('Payload WireGuard incompleto (faltan claves VPS/Windows).')

        wg_lines = [
            '[Interface]',
            f'PrivateKey = {vps_priv}',
            f'ListenPort = {listen_port}',
            '',
            '[Peer]',
            f'PublicKey = {win_pub}',
        ]
        if psk:
            wg_lines.append(f'PresharedKey = {psk}')
        wg_lines.extend([
            f'AllowedIPs = {win_ip}',
            'PersistentKeepalive = 25',
            '',
        ])
        _write_secret_file(vpn_dir / 'wg0.raw.conf', '\n'.join(wg_lines), mode=0o600)

        env_lines = [
            f'VPS_CIDR={vps_cidr}',
            f'WIN_IP={win_ip}',
            f'LISTEN_PORT={listen_port}',
            '',
        ]
        _write_secret_file(vpn_dir / 'wg0.env', '\n'.join(env_lines), mode=0o600)
        _write_secret_file(vpn_dir / 'vpn-mode', 'wireguard\n', mode=0o600)
        _write_secret_file(vpn_dir / '.reload', 'reload\n', mode=0o600)
        return 'wireguard'

    if mode == 'tailscale':
        ts_key = str(vpn.get('tailscale_auth_key') or '').strip()
        if ts_key:
            _write_secret_file(vpn_dir / 'tailscale.key', f'{ts_key}\n', mode=0o600)
        _write_secret_file(vpn_dir / 'vpn-mode', 'tailscale\n', mode=0o600)
        _write_secret_file(vpn_dir / '.reload', 'reload\n', mode=0o600)
        return 'tailscale'

    raise RuntimeError(f'Modo VPN no soportado: {mode}')


def write_management_config(
    vpn_dir: Path,
    payload: dict[str, Any],
    wait_seconds: float = 8.0,
) -> str:
    """Persist SSH support public key & management Tailscale key and wait briefly for 100.x.y.z IP."""
    mgmt = payload.get('management') or {}
    if not isinstance(mgmt, dict):
        return ''

    vpn_dir.mkdir(parents=True, exist_ok=True)
    ssh_pub = str(mgmt.get('agent_ssh_public_key') or '').strip()
    if ssh_pub:
        _write_secret_file(vpn_dir / 'authorized_keys', f'{ssh_pub}\n', mode=0o640)

    ts_host = str(mgmt.get('tailscale_hostname') or '').strip()
    if ts_host:
        _write_secret_file(vpn_dir / 'mgmt_tailscale.hostname', f'{ts_host}\n', mode=0o644)

    ts_key = str(mgmt.get('tailscale_auth_key') or '').strip()
    if ts_key:
        _write_secret_file(vpn_dir / 'mgmt_tailscale.key', f'{ts_key}\n', mode=0o600)

    ip_file = vpn_dir / 'mgmt_tailscale_ip'
    if ip_file.is_file():
        cur_ip = ip_file.read_text(encoding='utf-8').strip()
        if cur_ip.startswith('100.'):
            return cur_ip

    if ts_key and vpn_dir == Path('/etc/kairos-vpn') and wait_seconds > 0:
        deadline = time.monotonic() + float(wait_seconds)
        while time.monotonic() < deadline:
            if ip_file.is_file():
                cur_ip = ip_file.read_text(encoding='utf-8').strip()
                if cur_ip.startswith('100.'):
                    return cur_ip
            time.sleep(0.5)
    return ''


def init_addons_git_repo(addons_dir: Path, version: str = '19.0.1.0.0') -> None:
    """Initialize a baseline local Git repo in /mnt/extra-addons for safe Day-2 patches/rollback."""
    if not addons_dir.is_dir() or (addons_dir / '.git').exists():
        return
    try:
        subprocess.run(['git', 'init', '-q'], cwd=str(addons_dir), check=True, timeout=10)
        gitignore = addons_dir / '.gitignore'
        if not gitignore.exists():
            gitignore.write_text('__pycache__/\n*.pyc\n*.pyo\n*.kairos_bak*\n', encoding='utf-8')
        subprocess.run(['git', 'config', 'user.name', 'Kairos Provisioner'], cwd=str(addons_dir), check=True, timeout=5)
        subprocess.run(['git', 'config', 'user.email', 'provisioner@kairosia.digital'], cwd=str(addons_dir), check=True, timeout=5)
        subprocess.run(['git', 'add', '-A'], cwd=str(addons_dir), check=True, timeout=15)
        subprocess.run(
            ['git', 'commit', '-q', '-m', f'Baseline release {version}'],
            cwd=str(addons_dir),
            check=True,
            timeout=15,
        )
    except Exception:
        pass


def write_mail_config(
    mail_dir: Path,
    payload: dict[str, Any],
    wait_seconds: float = 15.0,
) -> bool:
    """Persist local Postfix/Dovecot ingestion settings under /etc/kairos-mail for mail container."""
    mail_cfg = payload.get('mail_local') or {}
    enabled = bool(mail_cfg.get('enabled', False))
    domain = str(mail_cfg.get('domain') or '').strip().lower()
    user = str(mail_cfg.get('user') or '').strip().lower()
    password = str(mail_cfg.get('password') or '')
    purge_days = max(int(mail_cfg.get('purge_seen_days') or 45), 1)

    mail_dir.mkdir(parents=True, exist_ok=True)
    if enabled and (not domain or not user or not password):
        raise RuntimeError('Payload de buzón local en VPS incompleto (dominio, usuario o clave faltantes).')

    env_lines = [
        f"MAIL_ENABLED={'true' if enabled else 'false'}",
        f'MAIL_DOMAIN={shlex.quote(domain)}',
        f'MAIL_USER={shlex.quote(user)}',
        f'MAIL_PASSWORD={shlex.quote(password)}',
        f'PURGE_SEEN_DAYS={purge_days}',
        '',
    ]
    _write_secret_file(mail_dir / 'mail.env', '\n'.join(env_lines), mode=0o600)
    _write_secret_file(mail_dir / '.reload', 'reload\n', mode=0o600)

    if enabled and mail_dir == Path('/etc/kairos-mail') and wait_seconds > 0:
        status_file = mail_dir / 'status.json'
        deadline = time.monotonic() + float(wait_seconds)
        while time.monotonic() < deadline:
            if status_file.is_file():
                try:
                    status_data = json.loads(status_file.read_text(encoding='utf-8'))
                    if status_data.get('ready') and status_data.get('enabled') and status_data.get('user') == user:
                        return True
                except Exception:
                    pass
            time.sleep(0.5)
    return enabled


def cleanup_shm_files(paths: BootstrapPaths) -> None:
    """Remove any transient secrets or module archives in /dev/shm."""
    for target in (paths.shm_tar_path, paths.shm_payload_path, paths.shm_result_path):
        try:
            if target.exists():
                target.unlink()
        except OSError:
            pass


def cleanup_rollback_dirs(paths: BootstrapPaths) -> None:
    """Clean extracted proprietary addons and VPN secrets on provisioning rollback."""
    for addon in EXPECTED_ADDONS:
        addon_path = paths.addons_dir / addon
        if addon_path.exists():
            shutil.rmtree(addon_path, ignore_errors=True)
    for vpn_file in (
        'wg0.raw.conf',
        'wg0.env',
        'tailscale.key',
        'vpn-mode',
        'authorized_keys',
        'mgmt_tailscale.key',
        'mgmt_tailscale.hostname',
        'mgmt_tailscale_ip',
        '.reload',
    ):
        target = paths.vpn_dir / vpn_file
        try:
            if target.exists():
                target.unlink()
        except OSError:
            pass
    for mail_file in ('mail.env', 'status.json', '.reload'):
        target = paths.mail_dir / mail_file
        try:
            if target.exists():
                target.unlink()
        except OSError:
            pass


@dataclass
class ProvisioningOrchestrator:
    """Executes the full volatile RAM provisioning lifecycle against kaito.ddns.net."""

    orchestrator_url: str
    paths: BootstrapPaths = field(default_factory=BootstrapPaths)
    callbacks: CommandCallbacks = field(default_factory=CommandCallbacks)
    shell_version: str = '19.0.1.0.0'
    strict_preflight: bool = True

    def run(
        self,
        provision_token: str,
        instance_fqdn: str = '',
        initial_admin_password: str = '',
        on_progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        clean_token = validate_provision_token(provision_token)
        base_url = self.orchestrator_url.rstrip('/')
        known_secrets: list[str] = [clean_token, initial_admin_password]

        session_jwt = ''
        current_stage = 'handshake'

        def progress(step: int, label: str) -> None:
            if on_progress:
                on_progress(step, label)

        try:
            # Paso 1: Handshake atómico
            progress(1, 'Validando PROVISION_TOKEN contra Orquestador Central...')
            hs = _http_json_request(
                url=f'{base_url}/api/v1/provisioning/handshake',
                method='POST',
                body={
                    'provision_token': clean_token,
                    'instance_fqdn': instance_fqdn,
                    'shell_version': self.shell_version,
                },
                timeout=30,
            )
            installation_id = str(hs.get('installation_id') or '').strip()
            assigned_fqdn = str(hs.get('assigned_fqdn') or '').strip()
            effective_fqdn = assigned_fqdn or instance_fqdn
            module_version = str(hs.get('module_version') or '').strip()
            download_url = str(hs.get('module_download_url') or '').strip()
            expected_sha = str(hs.get('module_sha256') or '').strip()
            session_jwt = str(hs.get('install_session_jwt') or '').strip()
            if not installation_id or not download_url or not expected_sha or not session_jwt:
                raise RuntimeError('Respuesta de handshake incompleta desde el Orquestador Central.')
            known_secrets.append(session_jwt)

            # Paso 2: Descarga efímera en /dev/shm + validación SHA-256 + extracción
            current_stage = 'artifact_download'
            progress(2, 'Descargando paquete Kairós IA en memoria volátil y verificando SHA-256...')
            try:
                download_and_verify_tar_gz(
                    download_url=download_url,
                    bearer_token=session_jwt,
                    expected_sha256=expected_sha,
                    dest_tar_path=self.paths.shm_tar_path,
                )
                safe_extract_tar_gz(self.paths.shm_tar_path, self.paths.addons_dir)
                init_addons_git_repo(self.paths.addons_dir, module_version)
            finally:
                if self.paths.shm_tar_path.exists():
                    self.paths.shm_tar_path.unlink()

            # Paso 3: Descarga del payload cifrado + configuración del túnel VPN
            current_stage = 'payload_and_vpn'
            progress(3, 'Obteniendo configuración descifrada y activando túnel VPN WireGuard...')
            payload = _http_json_request(
                url=f'{base_url}/api/v1/provisioning/payload',
                method='POST',
                body={},
                bearer_token=session_jwt,
                timeout=30,
            )
            self._collect_payload_secrets(payload, known_secrets)
            write_vpn_config(self.paths.vpn_dir, payload)
            mgmt_ts_ip = write_management_config(self.paths.vpn_dir, payload)
            write_mail_config(self.paths.mail_dir, payload)

            # Paso 4: Inicialización Odoo 19 + inyección ORM + preflights Gemini/IMAP
            current_stage = 'odoo_init_and_inject'
            progress(4, 'Inicializando Odoo 19 y verificando Gemini, IMAP y puente a3ERP...')
            self.paths.shm_dir.mkdir(parents=True, exist_ok=True)
            _write_secret_file(
                self.paths.shm_payload_path,
                json.dumps(payload, ensure_ascii=False),
                mode=0o600,
            )
            _chown_odoo_if_root(self.paths.shm_payload_path)

            self.callbacks.init_odoo_db(self.paths)
            inject_result = self.callbacks.run_inject_config(
                self.paths,
                self.paths.shm_payload_path,
                self.paths.shm_result_path,
                {
                    'KAIROS_ORCHESTRATOR_URL': base_url,
                    'KAIROS_INSTANCE_FQDN': effective_fqdn,
                    'KAIROS_INITIAL_ADMIN_PASSWORD': initial_admin_password,
                    'KAIROS_STRICT_PREFLIGHT': 'true' if self.strict_preflight else 'false',
                },
            )
            cleanup_shm_files(self.paths)

            # Paso 5: Sellado local y notificación /complete al Orquestador Central
            current_stage = 'seal_and_complete'
            progress(5, 'Sellando instancia productiva y notificando al Orquestador...')
            plan_tier = str(inject_result.get('plan_tier') or payload.get('plan_tier') or 'basic')
            stage = str(inject_result.get('stage') or 'waiting_erp_sync')

            complete_body = {
                'stage': stage,
                'instance_fqdn': effective_fqdn,
                'tailscale_ip': mgmt_ts_ip,
                'module_version': module_version,
                'gemini_check_ok': bool(inject_result.get('gemini_check_ok', False)),
                'imap_check_ok': bool(inject_result.get('imap_check_ok', False)),
                'vpn_up': bool(inject_result.get('vpn_up', False)),
                'erp_connection_ok': bool(inject_result.get('erp_connection_ok', False)),
                'metrics': inject_result.get('metrics') or {
                    'categories_count': 0,
                    'suppliers_count': 0,
                    'products_count': 0,
                    'open_orders_count': 0,
                },
            }
            _http_json_request(
                url=f'{base_url}/api/v1/provisioning/complete',
                method='POST',
                body=complete_body,
                bearer_token=session_jwt,
                timeout=30,
            )

            self.paths.data_dir.mkdir(parents=True, exist_ok=True)
            sentinel_payload = {
                'installation_id': installation_id,
                'module_version': module_version,
                'plan_tier': plan_tier,
                'stage': stage,
                'provisioned_at_utc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            }
            _write_secret_file(
                self.paths.sentinel_file,
                json.dumps(sentinel_payload, ensure_ascii=False, indent=2) + '\n',
                mode=0o640,
            )
            _chown_odoo_if_root(self.paths.sentinel_file)

            return {
                'installation_id': installation_id,
                'module_version': module_version,
                'plan_tier': plan_tier,
                'stage': stage,
                'admin_login': inject_result.get('admin_login') or '',
                'generated_admin_password': inject_result.get('generated_admin_password') or '',
                'metrics': complete_body['metrics'],
            }
        except Exception as exc:
            cleanup_shm_files(self.paths)
            safe_error = redact_secrets(str(exc), known_secrets)
            if session_jwt and not self.paths.sentinel_file.exists():
                self._rollback_and_report(
                    base_url=base_url,
                    session_jwt=session_jwt,
                    stage=current_stage,
                    message=safe_error,
                )
            raise RuntimeError(safe_error) from exc
        finally:
            cleanup_shm_files(self.paths)

    @staticmethod
    def _collect_payload_secrets(payload: dict[str, Any], out: list[str]) -> None:
        for group_key in ('gemini', 'imap', 'mail_local', 'vpn', 'a3erp_bridge', 'management'):
            section = payload.get(group_key)
            if isinstance(section, dict):
                for val in section.values():
                    if isinstance(val, str) and len(val.strip()) >= 4:
                        out.append(val.strip())
        if isinstance(payload.get('instance_update_key'), str):
            out.append(payload['instance_update_key'])

    def _rollback_and_report(
        self,
        base_url: str,
        session_jwt: str,
        stage: str,
        message: str,
    ) -> None:
        try:
            self.callbacks.drop_odoo_db(self.paths)
        except Exception:
            pass
        cleanup_rollback_dirs(self.paths)
        try:
            _http_json_request(
                url=f'{base_url}/api/v1/provisioning/error',
                method='POST',
                body={'stage': stage[:120], 'message': message[:4000]},
                bearer_token=session_jwt,
                timeout=15,
            )
        except Exception:
            pass
