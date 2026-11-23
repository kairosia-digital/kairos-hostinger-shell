#!/usr/bin/env python3
from __future__ import annotations

import configparser
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ODOO_CONF = Path('/etc/odoo/odoo.conf')
PID_FILE = Path('/var/run/kairos-odoo.pid')
RESTART_FLAG = Path('/var/run/kairos-restart-odoo')
LOG_FILE = Path('/var/log/odoo/odoo.log')
JSONL_LOG_FILE = Path('/var/log/odoo/odoo.jsonl')
DEFAULT_IMAGE = 'ghcr.io/kairosia-digital/kairos-hostinger-shell:19.0'


def _read_db_settings() -> dict[str, str]:
    settings = {
        'db_host': os.environ.get('DB_HOST', 'db'),
        'db_port': os.environ.get('DB_PORT', '5432'),
        'db_user': os.environ.get('DB_USER', 'odoo'),
        'db_password': os.environ.get('DB_PASSWORD', ''),
        'db_name': 'odoo_prod',
    }
    if ODOO_CONF.is_file():
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(ODOO_CONF, encoding='utf-8')
            if parser.has_section('options'):
                opts = parser['options']
                for k in ('db_host', 'db_port', 'db_user', 'db_password', 'db_name'):
                    val = (opts.get(k, '') or '').strip()
                    if val and val.lower() != 'false':
                        settings[k] = val
        except Exception:
            pass
    return settings


def _is_odoo_running() -> bool:
    if not PID_FILE.is_file():
        return False
    try:
        pid = int(PID_FILE.read_text(encoding='utf-8').strip())
        if pid <= 1:
            return False
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _handle_ps(args: list[str]) -> int:
    up_str = 'Up (local)' if _is_odoo_running() else 'Stopped'
    filter_val = ''
    fmt_val = ''
    idx = 0
    while idx < len(args):
        if args[idx] in ('--filter', '-f') and idx + 1 < len(args):
            filter_val = args[idx + 1]
            idx += 2
        elif args[idx].startswith('--filter='):
            filter_val = args[idx].split('=', 1)[1]
            idx += 1
        elif args[idx] == '--format' and idx + 1 < len(args):
            fmt_val = args[idx + 1]
            idx += 2
        elif args[idx].startswith('--format='):
            fmt_val = args[idx].split('=', 1)[1]
            idx += 1
        else:
            idx += 1

    if 'Status' in fmt_val and ('kairos-odoo' in filter_val or not filter_val):
        print(f'kairos-odoo | {up_str} | Imagen: {DEFAULT_IMAGE}')
        return 0
    if filter_val and 'kairos-db' not in filter_val and 'db' not in filter_val:
        if 'kairos-odoo' in filter_val:
            print('kairos-odoo')
        return 0
    print('kairos-odoo')
    print('kairos-db')
    return 0


def _handle_inspect(args: list[str]) -> int:
    fmt = ''
    idx = 0
    while idx < len(args):
        if args[idx] in ('--format', '-f') and idx + 1 < len(args):
            fmt = args[idx + 1]
            idx += 2
        elif args[idx].startswith('--format='):
            fmt = args[idx].split('=', 1)[1]
            idx += 1
        else:
            idx += 1

    db = _read_db_settings()
    if '.LogPath' in fmt:
        print(str(JSONL_LOG_FILE if JSONL_LOG_FILE.is_file() else LOG_FILE))
        return 0
    if '.State.Running' in fmt:
        print('true' if _is_odoo_running() else 'false')
        return 0
    if '.Config.Env' in fmt:
        print(f"HOST={db['db_host']}")
        print(f"PORT={db['db_port']}")
        print(f"USER={db['db_user']}")
        print(f"PASSWORD={db['db_password']}")
        print(f"DB_NAME={db['db_name']}")
        return 0
    if '.Config.Image' in fmt or '{{.Image}}' in fmt:
        print(DEFAULT_IMAGE)
        return 0
    print('kairos-odoo')
    return 0


def _handle_logs(args: list[str]) -> int:
    tail_n = 200
    idx = 0
    while idx < len(args):
        if args[idx] in ('--tail', '-n') and idx + 1 < len(args):
            try:
                tail_n = max(int(args[idx + 1]), 1)
            except ValueError:
                pass
            idx += 2
        elif args[idx].startswith('--tail='):
            try:
                tail_n = max(int(args[idx].split('=', 1)[1]), 1)
            except ValueError:
                pass
            idx += 1
        else:
            idx += 1

    if LOG_FILE.is_file():
        lines = LOG_FILE.read_text(encoding='utf-8', errors='replace').splitlines()
        for ln in lines[-tail_n:]:
            print(ln)
    return 0


def _handle_exec(args: list[str]) -> int:
    pos = 0
    while pos < len(args) and args[pos].startswith('-'):
        flag = args[pos]
        if flag in ('-u', '--user', '-w', '--workdir', '-e', '--env') and pos + 1 < len(args):
            pos += 2
        else:
            pos += 1

    if pos >= len(args):
        return 1
    _container = args[pos]
    cmd = args[pos + 1 :]
    if not cmd:
        return 1

    db = _read_db_settings()
    env = os.environ.copy()
    env['HOST'] = db['db_host']
    env['PORT'] = db['db_port']
    env['USER'] = db['db_user']
    env['PASSWORD'] = db['db_password']
    env['DB_HOST'] = db['db_host']
    env['DB_PORT'] = db['db_port']
    env['DB_USER'] = db['db_user']
    env['DB_PASSWORD'] = db['db_password']
    env['PGHOST'] = db['db_host']
    env['PGPORT'] = db['db_port']
    env['PGUSER'] = db['db_user']
    env['PGPASSWORD'] = db['db_password']

    bin_name = Path(cmd[0]).name
    if bin_name.startswith('python') or bin_name == 'odoo':
        if os.geteuid() == 0:
            os.execvpe('gosu', ['gosu', 'odoo', *cmd], env)
    os.execvpe(cmd[0], cmd, env)
    return 0


def _handle_restart() -> int:
    RESTART_FLAG.parent.mkdir(parents=True, exist_ok=True)
    RESTART_FLAG.write_text('restart\n', encoding='utf-8')
    if PID_FILE.is_file():
        try:
            pid = int(PID_FILE.read_text(encoding='utf-8').strip())
            if pid > 1:
                os.kill(pid, signal.SIGTERM)
        except Exception:
            pass

    deadline = time.monotonic() + 25.0
    time.sleep(2.0)
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8069/web/login', timeout=3) as resp:
                if resp.status < 500:
                    return 0
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return 0
        except Exception:
            pass
        time.sleep(1.0)
    return 1


def main() -> int:
    if len(sys.argv) < 2:
        return 1
    subcmd = sys.argv[1]
    rest = sys.argv[2:]
    if subcmd == 'ps':
        return _handle_ps(rest)
    if subcmd == 'inspect':
        return _handle_inspect(rest)
    if subcmd == 'logs':
        return _handle_logs(rest)
    if subcmd == 'exec':
        return _handle_exec(rest)
    if subcmd == 'restart':
        return _handle_restart()
    if subcmd == 'save':
        return 0
    return 0


if __name__ == '__main__':
    sys.exit(main())
