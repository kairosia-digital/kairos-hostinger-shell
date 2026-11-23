from __future__ import annotations

import imaplib
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from provision_runner import redact_secrets


def _default_verify_gemini(api_key: str) -> None:
    """Validate Google Gemini API Key by calling the models discovery endpoint."""
    key = (api_key or '').strip()
    if not key:
        raise RuntimeError('La API Key de Google Gemini está vacía.')

    url = f'https://generativelanguage.googleapis.com/v1beta/models?key={urllib.parse.quote(key)}'
    req = urllib.request.Request(url, headers={'Accept': 'application/json'}, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                raise RuntimeError(f'Gemini devolvió HTTP {resp.status}.')
    except urllib.error.HTTPError as exc:
        raise RuntimeError(redact_secrets(f'Gemini rechazó la API Key (HTTP {exc.code}).', [key])) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(redact_secrets(f'No se pudo contactar con Google Gemini: {exc.reason}', [key])) from exc


def _default_verify_imap(imap_cfg: dict[str, Any]) -> None:
    """Validate IMAP login and folder selection in read-only mode."""
    server = str(imap_cfg.get('server') or '').strip()
    port = int(imap_cfg.get('port') or 993)
    use_ssl = bool(imap_cfg.get('ssl', True))
    user = str(imap_cfg.get('user') or '').strip()
    password = str(imap_cfg.get('password') or '')
    folder = str(imap_cfg.get('folder') or 'INBOX').strip() or 'INBOX'

    if not server or not user or not password:
        raise RuntimeError('Credenciales IMAP incompletas (servidor, usuario o contraseña).')

    client: imaplib.IMAP4 | None = None
    try:
        if use_ssl:
            client = imaplib.IMAP4_SSL(server, port, timeout=10)
        else:
            client = imaplib.IMAP4(server, port, timeout=10)
        client.login(user, password)
        status, _data = client.select(folder, readonly=True)
        if status != 'OK':
            raise RuntimeError(f'No se pudo abrir la carpeta IMAP "{folder}".')
    except Exception as exc:
        raise RuntimeError(
            redact_secrets(f'Error verificando buzón IMAP {server}:{port} ({exc})', [password])
        ) from exc
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


def _default_check_bridge_health(bridge_url: str, bridge_token: str) -> bool:
    """Probe the Windows a3ERP ActiveX Bridge /api/v1/invoice/health over VPN."""
    url_base = (bridge_url or '').strip().rstrip('/')
    if not url_base:
        return False

    headers = {'Accept': 'application/json'}
    if bridge_token:
        headers['Authorization'] = f'Bearer {bridge_token}'
        headers['X-A3ERP-Token'] = bridge_token

    req = urllib.request.Request(f'{url_base}/api/v1/invoice/health', headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.status == 200
    except Exception:
        return False


def _normalize_base_url(instance_fqdn: str) -> str:
    fqdn = (instance_fqdn or '').strip().rstrip('/')
    if not fqdn:
        return ''
    if fqdn.startswith(('http://', 'https://')):
        return fqdn
    return f'https://{fqdn}'


def apply_payload_to_odoo_env(
    env: Any,
    payload: dict[str, Any],
    orchestrator_url: str,
    instance_fqdn: str = '',
    initial_admin_password: str = '',
    strict_preflight: bool = True,
    gemini_verifier: Callable[[str], None] = _default_verify_gemini,
    imap_verifier: Callable[[dict[str, Any]], None] = _default_verify_imap,
    bridge_health_checker: Callable[[str, str], bool] = _default_check_bridge_health,
) -> dict[str, Any]:
    """Inject client secrets, company settings, plan directives, and preflight checks into Odoo."""
    icp = env['ir.config_parameter'].sudo()
    installation_id = str(payload.get('installation_id') or '').strip()
    update_key = str(payload.get('instance_update_key') or '').strip()
    plan_tier = str(payload.get('plan_tier') or 'basic').strip().lower()

    lic = payload.get('license') or {}
    company_cfg = payload.get('company') or {}
    gemini_cfg = payload.get('gemini') or {}
    imap_cfg = payload.get('imap') or {}
    bridge_cfg = payload.get('a3erp_bridge') or {}

    base_url = _normalize_base_url(instance_fqdn)
    if base_url:
        icp.set_param('web.base.url', base_url)
        icp.set_param('web.base.url.freeze', 'True')

    admin_email = str(company_cfg.get('admin_email') or '').strip()
    icp.set_param('kairos.orchestrator_url', orchestrator_url.rstrip('/'))
    icp.set_param('kairos.installation_id', installation_id)
    icp.set_param('kairos.instance_update_key', update_key)
    icp.set_param('auth_signup.reset_password', 'True')
    if admin_email:
        icp.set_param('kairos_incidencias.default_assignee_email', admin_email)

    env['kairos.plan.service'].apply_plan_directives(
        plan_tier=plan_tier,
        license_active=bool(lic.get('active', True)),
        source_of_truth_readonly=bool(lic.get('source_of_truth_readonly', True)),
        license_valid_until=lic.get('valid_until'),
    )

    company_name = str(company_cfg.get('name') or 'Empresa Cliente Kairós IA').strip()
    company_vat = str(company_cfg.get('vat') or '').strip()
    country_code = str(company_cfg.get('country_code') or 'ES').strip().upper()
    currency_code = str(company_cfg.get('currency_code') or 'EUR').strip().upper()

    country = env['res.country'].sudo().search([('code', '=', country_code)], limit=1)
    currency = env['res.currency'].sudo().search([('name', '=', currency_code)], limit=1)

    company_vals: dict[str, Any] = {
        'name': company_name,
        'vat': company_vat or False,
        'email': admin_email or False,
        'x_a3erp_bridge_url': str(bridge_cfg.get('url') or '').strip(),
        'x_a3erp_bridge_token': str(bridge_cfg.get('token') or '').strip(),
        'x_a3erp_db_name': str(bridge_cfg.get('company_code') or '').strip(),
        'x_a3erp_user': str(bridge_cfg.get('user') or 'sa').strip(),
        'x_a3erp_folder_name': company_name,
    }
    if country:
        company_vals['country_id'] = country.id
    if currency:
        company_vals['currency_id'] = currency.id

    company = env.company.sudo().with_context(from_a3erp_sync=True)
    company.write(company_vals)

    # Admin user provisioning
    generated_password = ''
    effective_password = (initial_admin_password or '').strip()
    if not effective_password:
        generated_password = secrets.token_urlsafe(15)
        effective_password = generated_password

    admin_login = admin_email or 'admin'
    admin_user = env.ref('base.user_admin', raise_if_not_found=False)
    if admin_user:
        user_vals: dict[str, Any] = {
            'name': f'Administrador {company_name}',
            'password': effective_password,
        }
        if admin_email:
            user_vals['login'] = admin_email
            user_vals['email'] = admin_email
        admin_user.sudo().with_context(from_a3erp_sync=True).write(user_vals)
        if admin_email and admin_user.partner_id:
            admin_user.partner_id.sudo().with_context(from_a3erp_sync=True).write({'email': admin_email})
        admin_login = admin_user.login or admin_login

    # Dedicated internal XML-RPC support user for Gestión Kairós incident sync
    mgmt_cfg = payload.get('management') or {}
    support_login = str(mgmt_cfg.get('support_login') or '').strip()
    support_password = str(mgmt_cfg.get('support_password') or '').strip()
    if support_login and support_password:
        Users = env['res.users'].sudo().with_context(
            from_a3erp_sync=True,
            no_reset_password=True,
            mail_create_nosubscribe=True,
        )
        grp_user = env.ref('base.group_user', raise_if_not_found=False)
        grp_sys = env.ref('base.group_system', raise_if_not_found=False)
        group_ids = [g.id for g in (grp_user, grp_sys) if g]
        sup_user = Users.search([('login', '=', support_login)], limit=1)
        sup_vals: dict[str, Any] = {
            'name': 'Kairós IA · Soporte Central',
            'login': support_login,
            'email': support_login,
            'password': support_password,
            'active': True,
        }
        if group_ids:
            sup_vals['group_ids'] = [(6, 0, group_ids)]
        if sup_user:
            sup_user.write(sup_vals)
        else:
            Users.create(sup_vals)

    # Gemini AI configuration & preflight
    gemini_key = str(gemini_cfg.get('api_key') or '').strip()
    gemini_model = str(gemini_cfg.get('model') or 'gemini-3.6-flash').strip()
    icp.set_param('kairos_digitization.gemini_api_key', gemini_key)
    icp.set_param('kairos_digitization.gemini_model', gemini_model)
    icp.set_param(
        'kairos_digitization.ai_client_fine_tuning',
        f'Empresa cliente: {company_name} (NIF/CIF: {company_vat or "N/D"})',
    )

    gemini_check_ok = False
    if gemini_key:
        try:
            gemini_verifier(gemini_key)
            gemini_check_ok = True
        except Exception:
            if strict_preflight:
                raise
    elif strict_preflight:
        raise RuntimeError('No se proporcionó la API Key de Google Gemini en el payload.')

    # IMAP incoming digitization server & preflight
    imap_check_ok = False
    imap_server_host = str(imap_cfg.get('server') or '').strip()
    if imap_server_host:
        try:
            imap_verifier(imap_cfg)
            imap_check_ok = True
        except Exception:
            if strict_preflight:
                raise

        log_model = env['ir.model'].sudo().search([('model', '=', 'kairos.email.digitization.log')], limit=1)
        FetchmailServer = env['fetchmail.server'].sudo()
        server_rec = FetchmailServer.search([('name', '=', 'Kairós IA - Recepción Documentos')], limit=1)
        server_vals: dict[str, Any] = {
            'name': 'Kairós IA - Recepción Documentos',
            'server_type': 'imap',
            'server': imap_server_host,
            'port': int(imap_cfg.get('port') or 993),
            'is_ssl': bool(imap_cfg.get('ssl', True)),
            'user': str(imap_cfg.get('user') or '').strip(),
            'password': str(imap_cfg.get('password') or ''),
            'state': 'done',
        }
        if log_model:
            server_vals['object_id'] = log_model.id

        if server_rec:
            server_rec.write(server_vals)
        else:
            server_rec = FetchmailServer.create(server_vals)

        icp.set_param('kairos_digitization.email_server_id', str(server_rec.id))
        icp.set_param('kairos_digitization.email_digitization_enabled', 'True')
        icp.set_param('kairos_digitization.email_auto_process', 'True')

        for cron_xmlid in (
            'kairos_digitization.cron_process_email_digitizations',
            'kairos_digitization.cron_process_queue_digitizations',
        ):
            cron = env.ref(cron_xmlid, raise_if_not_found=False)
            if cron:
                cron.sudo().write({'active': True})
    elif strict_preflight:
        raise RuntimeError('No se proporcionó configuración IMAP en el payload.')

    # Update master sync cron cadence
    sync_interval = max(5, int(bridge_cfg.get('sync_interval_minutes') or 15))
    sync_cron = env.ref('odoo_kairos_addon.ir_cron_a3erp_master_sync', raise_if_not_found=False)
    if sync_cron:
        sync_cron.sudo().write({'interval_number': sync_interval, 'interval_type': 'minutes'})

    # Opportunistic Day-1 Bridge health check & initial master import
    bridge_url = company_vals['x_a3erp_bridge_url']
    bridge_token = company_vals['x_a3erp_bridge_token']
    vpn_up = False
    erp_connection_ok = False
    stage = 'waiting_erp_sync'
    metrics = {
        'categories_count': 0,
        'suppliers_count': 0,
        'products_count': 0,
        'open_orders_count': 0,
    }

    if bridge_url and bridge_health_checker(bridge_url, bridge_token):
        vpn_up = True
        if company_vals['x_a3erp_db_name']:
            try:
                metrics = env['a3erp.master.sync.service'].sync_company_masters(company)
                erp_connection_ok = True
                stage = 'active'
            except Exception:
                erp_connection_ok = False
                stage = 'waiting_erp_sync'

    icp.set_param('kairos.provisioning_state', stage)
    env.cr.commit()

    return {
        'installation_id': installation_id,
        'plan_tier': 'advanced' if plan_tier == 'advanced' else 'basic',
        'stage': stage,
        'gemini_check_ok': gemini_check_ok,
        'imap_check_ok': imap_check_ok,
        'vpn_up': vpn_up,
        'erp_connection_ok': erp_connection_ok,
        'metrics': metrics,
        'admin_login': admin_login,
        'generated_admin_password': generated_password,
    }


def run_in_odoo_shell(env: Any) -> None:
    """Entrypoint invoked from odoo shell during unattended KVM 2 provisioning."""
    payload_file = Path(os.environ['KAIROS_PAYLOAD_FILE'])
    result_file = Path(os.environ['KAIROS_RESULT_FILE'])
    orchestrator_url = os.environ.get('KAIROS_ORCHESTRATOR_URL', 'https://kaito.ddns.net')
    instance_fqdn = os.environ.get('KAIROS_INSTANCE_FQDN', '')
    initial_admin_password = os.environ.get('KAIROS_INITIAL_ADMIN_PASSWORD', '')
    strict_preflight = os.environ.get('KAIROS_STRICT_PREFLIGHT', 'true').strip().lower() not in ('0', 'false', 'no')

    payload = json.loads(payload_file.read_text(encoding='utf-8'))
    result = apply_payload_to_odoo_env(
        env=env,
        payload=payload,
        orchestrator_url=orchestrator_url,
        instance_fqdn=instance_fqdn,
        initial_admin_password=initial_admin_password,
        strict_preflight=strict_preflight,
    )
    fd = os.open(result_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        json.dump(result, handle, ensure_ascii=False)
