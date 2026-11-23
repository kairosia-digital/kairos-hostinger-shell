#!/usr/bin/env bash
set -euo pipefail

ODOO_DATA_DIR="/var/lib/odoo"
ADDONS_DIR="/mnt/extra-addons"
ODOO_CONF="/etc/odoo/odoo.conf"
VPN_DIR="/etc/kairos-vpn"
MAIL_DIR="/etc/kairos-mail"
SHM_DIR="/dev/shm"
SENTINEL_FILE="${ODOO_DATA_DIR}/.provisioned"

cleanup_shm() {
    rm -f "${SHM_DIR}/module.tar.gz" \
          "${SHM_DIR}/payload.json" \
          "${SHM_DIR}/inject_result.json" \
          "${SHM_DIR}/day2_update.tar.gz"
}
trap cleanup_shm EXIT

log() {
    printf '[kairos-entrypoint %s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

wait_for_postgres() {
    local host="${DB_HOST:-db}"
    local port="${DB_PORT:-5432}"
    local user="${DB_USER:-odoo}"
    local attempt=0
    local max_attempts=60

    log "Esperando disponibilidad de PostgreSQL en ${host}:${port}..."
    until PGPASSWORD="${DB_PASSWORD:-}" pg_isready -h "${host}" -p "${port}" -U "${user}" >/dev/null 2>&1; do
        attempt=$((attempt + 1))
        if [[ "${attempt}" -ge "${max_attempts}" ]]; then
            log "ERROR: PostgreSQL no respondió tras $((max_attempts * 2)) segundos."
            exit 1
        fi
        sleep 2
    done
    log "PostgreSQL operativo."
}

prepare_directories() {
    mkdir -p "${ODOO_DATA_DIR}" "${ADDONS_DIR}" /etc/odoo "${VPN_DIR}" "${MAIL_DIR}" /var/log/odoo /var/run /root/.ssh
    chown -R odoo:odoo "${ODOO_DATA_DIR}" "${ADDONS_DIR}" /var/log/odoo
    chmod 0750 "${ODOO_DATA_DIR}" "${ADDONS_DIR}" /var/log/odoo
    chown root:odoo /etc/odoo "${VPN_DIR}"
    chmod 0750 /etc/odoo
    chmod 0770 "${VPN_DIR}"
    chown root:root "${MAIL_DIR}" /root/.ssh
    chmod 0700 "${MAIL_DIR}" /root/.ssh
}

generate_odoo_conf_if_missing() {
    if [[ -f "${ODOO_CONF}" ]]; then
        chown root:odoo "${ODOO_CONF}"
        chmod 0640 "${ODOO_CONF}"
        return 0
    fi

    local admin_passwd
    admin_passwd="$(python3 -c 'import secrets, string; a = string.ascii_letters + string.digits; print("".join(secrets.choice(a) for _ in range(32)))')"

    log "Generando configuración endurecida en ${ODOO_CONF}..."
    cat > "${ODOO_CONF}" <<EOF
[options]
admin_passwd = ${admin_passwd}
addons_path = ${ADDONS_DIR},/usr/lib/python3/dist-packages/odoo/addons
data_dir = ${ODOO_DATA_DIR}
logfile = /var/log/odoo/odoo.log
db_host = ${DB_HOST:-db}
db_port = ${DB_PORT:-5432}
db_user = ${DB_USER:-odoo}
db_password = ${DB_PASSWORD:-}
db_name = odoo_prod
dbfilter = ^odoo_prod$
list_db = False
proxy_mode = True
http_interface = 0.0.0.0
http_port = 8069
workers = 4
max_cron_threads = 1
limit_memory_soft = 2147483648
limit_memory_hard = 2684354560
limit_time_cpu = 600
limit_time_real = 1200
without_demo = all
EOF

    chown root:odoo "${ODOO_CONF}"
    chmod 0640 "${ODOO_CONF}"
}

start_log_mirror() {
    touch /var/log/odoo/odoo.log /var/log/odoo/odoo.jsonl
    chown odoo:odoo /var/log/odoo/odoo.log /var/log/odoo/odoo.jsonl
    python3 - << 'PYEOF' &
import json
import os
import sys
import time
from pathlib import Path

log_path = Path('/var/log/odoo/odoo.log')
jsonl_path = Path('/var/log/odoo/odoo.jsonl')
offset = log_path.stat().st_size if log_path.is_file() else 0

while True:
    try:
        if log_path.is_file():
            cur_size = log_path.stat().st_size
            if cur_size < offset:
                offset = 0
            if cur_size > offset:
                with log_path.open('r', encoding='utf-8', errors='replace') as src:
                    src.seek(offset)
                    chunk = src.read()
                    offset = src.tell()
                if chunk:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                    lines = chunk.splitlines(keepends=True)
                    with jsonl_path.open('a', encoding='utf-8') as dst:
                        for ln in lines:
                            dst.write(json.dumps({'log': ln}, ensure_ascii=False) + '\n')
                    if jsonl_path.stat().st_size > 15 * 1024 * 1024:
                        tail = jsonl_path.read_text(encoding='utf-8', errors='replace').splitlines()[-1500:]
                        jsonl_path.write_text('\n'.join(tail) + '\n', encoding='utf-8')
    except Exception:
        pass
    time.sleep(0.5)
PYEOF
}

start_mgmt_sshd_loop() {
    local ts_ip_file="${VPN_DIR}/mgmt_tailscale_ip"
    local auth_src="${VPN_DIR}/authorized_keys"
    local auth_dst="/root/.ssh/authorized_keys"
    local sshd_cfg="/etc/ssh/kairos-mgmt-sshd.conf"
    local sshd_pid="/var/run/kairos-sshd.pid"
    local last_sig=""

    while true; do
        if [[ -s "${ts_ip_file}" && -s "${auth_src}" ]]; then
            local ts_ip
            ts_ip="$(tr -d '[:space:]' < "${ts_ip_file}")"
            if [[ "${ts_ip}" =~ ^100\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                local auth_hash
                auth_hash="$(sha256sum "${auth_src}" | awk '{print $1}')"
                local cur_sig="${ts_ip}|${auth_hash}"
                local need_reload=0
                if [[ "${cur_sig}" != "${last_sig}" ]]; then
                    need_reload=1
                elif [[ ! -s "${sshd_pid}" ]] || ! kill -0 "$(cat "${sshd_pid}" 2>/dev/null)" 2>/dev/null; then
                    need_reload=1
                fi

                if [[ "${need_reload}" -eq 1 ]]; then
                    cp "${auth_src}" "${auth_dst}.tmp"
                    chown root:root "${auth_dst}.tmp"
                    chmod 0600 "${auth_dst}.tmp"
                    mv "${auth_dst}.tmp" "${auth_dst}"
                    ssh-keygen -A >/dev/null 2>&1 || true

                    cat > "${sshd_cfg}" <<EOF
Port 22
ListenAddress ${ts_ip}
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PidFile ${sshd_pid}
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthorizedKeysFile /root/.ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AllowUsers root
X11Forwarding no
Subsystem sftp internal-sftp
EOF
                    chmod 0600 "${sshd_cfg}"
                    if [[ -s "${sshd_pid}" ]] && kill -0 "$(cat "${sshd_pid}" 2>/dev/null)" 2>/dev/null; then
                        kill -TERM "$(cat "${sshd_pid}")" 2>/dev/null || true
                        sleep 0.5
                    fi
                    if /usr/sbin/sshd -t -f "${sshd_cfg}" 2>/dev/null; then
                        /usr/sbin/sshd -f "${sshd_cfg}"
                        last_sig="${cur_sig}"
                        log "SSHD de soporte activo exclusivamente en Tailscale ${ts_ip}:22."
                    fi
                fi
            fi
        fi
        sleep 5
    done
}

main() {
    cleanup_shm
    prepare_directories
    wait_for_postgres
    generate_odoo_conf_if_missing

    if [[ ! -f "${SENTINEL_FILE}" ]]; then
        log "Instancia sin sellar (${SENTINEL_FILE} ausente). Iniciando Guardián de Activación en puerto 8069..."
        export PYTHONPATH="/opt/kairos-bootstrapper${PYTHONPATH:+:${PYTHONPATH}}"
        python3 /opt/kairos-bootstrapper/guardian_server.py
        cleanup_shm
    else
        log "Instancia ya aprovisionada (${SENTINEL_FILE}). Omitiendo Guardián."
    fi

    if [[ ! -f "${SENTINEL_FILE}" ]]; then
        log "ERROR CRÍTICO: El proceso Guardián terminó sin sellar ${SENTINEL_FILE}."
        exit 1
    fi

    unset PROVISION_TOKEN
    unset ODOO_INITIAL_ADMIN_PASSWORD

    start_log_mirror
    LOG_MIRROR_PID="$!"
    start_mgmt_sshd_loop &
    SSHD_LOOP_PID="$!"

    STOP_REQUESTED=0
    ODOO_PID=""
    handle_stop() {
        STOP_REQUESTED=1
        if [[ -n "${ODOO_PID}" ]] && kill -0 "${ODOO_PID}" 2>/dev/null; then
            kill -TERM "${ODOO_PID}" 2>/dev/null || true
        fi
        kill "${LOG_MIRROR_PID}" "${SSHD_LOOP_PID}" 2>/dev/null || true
    }
    trap 'cleanup_shm; handle_stop' EXIT INT TERM QUIT

    log "Iniciando Odoo 19 en modo producción endurecido (--db-filter=^odoo_prod$)..."
    while [[ "${STOP_REQUESTED}" -eq 0 ]]; do
        rm -f /var/run/kairos-restart-odoo
        gosu odoo odoo -c "${ODOO_CONF}" --db-filter=^odoo_prod$ --logfile=/var/log/odoo/odoo.log &
        ODOO_PID="$!"
        echo "${ODOO_PID}" > /var/run/kairos-odoo.pid
        set +e
        wait "${ODOO_PID}"
        rc=$?
        set -e
        rm -f /var/run/kairos-odoo.pid
        ODOO_PID=""
        if [[ "${STOP_REQUESTED}" -ne 0 ]]; then
            exit "${rc}"
        fi
        if [[ -f /var/run/kairos-restart-odoo ]]; then
            log "Reinicio controlado de Odoo completado tras mantenimiento."
            rm -f /var/run/kairos-restart-odoo
            sleep 1
        else
            log "Odoo finalizó inesperadamente (rc=${rc}); reiniciando en 3s..."
            sleep 3
        fi
    done
}

main "$@"
