#!/usr/bin/env bash
set -euo pipefail

ODOO_DATA_DIR="/var/lib/odoo"
ADDONS_DIR="/mnt/extra-addons"
ODOO_CONF="/etc/odoo/odoo.conf"
VPN_DIR="/etc/kairos-vpn"
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
    mkdir -p "${ODOO_DATA_DIR}" "${ADDONS_DIR}" /etc/odoo "${VPN_DIR}"
    chown -R odoo:odoo "${ODOO_DATA_DIR}" "${ADDONS_DIR}"
    chmod 0750 "${ODOO_DATA_DIR}" "${ADDONS_DIR}"
    chown root:odoo /etc/odoo
    chmod 0750 /etc/odoo
    chown root:root "${VPN_DIR}"
    chmod 0700 "${VPN_DIR}"
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

    log "Iniciando Odoo 19 en modo producción endurecido (--db-filter=^odoo_prod$)..."
    exec gosu odoo odoo -c "${ODOO_CONF}" --db-filter=^odoo_prod$
}

main "$@"
