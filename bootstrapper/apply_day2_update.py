from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

from provision_runner import (
    BootstrapPaths,
    EXPECTED_ADDONS,
    _http_json_request,
    _wrap_odoo_user,
    download_and_verify_tar_gz,
    redact_secrets,
    safe_extract_tar_gz,
)


def default_upgrade_addons(paths: BootstrapPaths) -> None:
    """Upgrade all Kairós client addons cleanly in production DB."""
    subprocess.run(
        _wrap_odoo_user([
            'odoo',
            '-c',
            str(paths.odoo_conf),
            '-d',
            paths.db_name,
            '-u',
            ','.join(EXPECTED_ADDONS),
            '--stop-after-init',
            '--no-http',
        ]),
        check=True,
    )


def run_day2_update(
    orchestrator_url: str,
    instance_update_key: str,
    current_version: str = '19.0.1.0.0',
    paths: BootstrapPaths | None = None,
    upgrade_cb: Callable[[BootstrapPaths], None] = default_upgrade_addons,
) -> dict[str, str]:
    """Poll kaito.ddns.net for pending Day-2 release, verify SHA-256 in /dev/shm, and upgrade."""
    paths = paths or BootstrapPaths()
    base_url = orchestrator_url.rstrip('/')
    key = (instance_update_key or '').strip()
    if not key:
        raise ValueError('Se requiere instance_update_key para verificar actualizaciones Día 2.')

    directives = _http_json_request(
        url=f'{base_url}/api/v1/instance/heartbeat',
        method='POST',
        body={'module_version': current_version},
        bearer_token=key,
        timeout=20,
    )
    pending = directives.get('pending_update')
    if not isinstance(pending, dict) or not pending.get('download_url'):
        return {'updated': 'false', 'version': current_version}

    target_version = str(pending.get('version') or '').strip()
    target_sha = str(pending.get('sha256') or '').strip()
    download_url = str(pending.get('download_url') or '').strip()

    shm_update_tar = paths.shm_dir / 'day2_update.tar.gz'
    try:
        download_and_verify_tar_gz(
            download_url=download_url,
            bearer_token=key,
            expected_sha256=target_sha,
            dest_tar_path=shm_update_tar,
        )
        safe_extract_tar_gz(shm_update_tar, paths.addons_dir)
    except Exception as exc:
        raise RuntimeError(redact_secrets(str(exc), [key])) from exc
    finally:
        if shm_update_tar.exists():
            shm_update_tar.unlink()

    upgrade_cb(paths)

    _http_json_request(
        url=f'{base_url}/api/v1/instance/heartbeat',
        method='POST',
        body={'module_version': target_version},
        bearer_token=key,
        timeout=20,
    )
    return {'updated': 'true', 'version': target_version}


def main() -> int:
    orch_url = os.environ.get('ORCHESTRATOR_URL', 'https://kaito.ddns.net')
    update_key = os.environ.get('INSTANCE_UPDATE_KEY', '')
    current_version = os.environ.get('CURRENT_MODULE_VERSION', '19.0.1.0.0')
    result = run_day2_update(
        orchestrator_url=orch_url,
        instance_update_key=update_key,
        current_version=current_version,
    )
    print(f"Day-2 update check: updated={result['updated']} version={result['version']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
