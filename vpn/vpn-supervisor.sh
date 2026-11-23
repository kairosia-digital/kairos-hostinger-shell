#!/usr/bin/env bash
set -euo pipefail

VPN_DIR="/etc/kairos-vpn"
MODE_FILE="${VPN_DIR}/vpn-mode"
STATUS_FILE="${VPN_DIR}/status.json"
RELOAD_FLAG="${VPN_DIR}/.reload"
TAILSCALE_PID=""
MGMT_LOOP_PID=""

log() {
    printf '[kairos-vpn %s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

write_status() {
    local mode="$1"
    local iface="$2"
    local vps_cidr="$3"
    local win_ip="$4"
    local up="$5"
    local details="$6"
    jq -n \
        --arg mode "$mode" \
        --arg iface "$iface" \
        --arg vps_cidr "$vps_cidr" \
        --arg win_ip "$win_ip" \
        --argjson up "$up" \
        --arg details "$details" \
        --arg updated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        '{mode: $mode, interface: $iface, vps_cidr: $vps_cidr, win_ip: $win_ip, up: $up, details: $details, updated_at: $updated_at}' \
        > "${STATUS_FILE}.tmp"
    mv "${STATUS_FILE}.tmp" "${STATUS_FILE}"
}

write_mgmt_ip_file() {
    local ip_val="$1"
    local out_file="${VPN_DIR}/mgmt_tailscale_ip"
    if [[ -n "${ip_val}" ]]; then
        printf '%s\n' "${ip_val}" > "${out_file}.tmp"
        chmod 0644 "${out_file}.tmp"
        mv "${out_file}.tmp" "${out_file}"
    fi
}

cleanup() {
    if [[ -n "${MGMT_LOOP_PID}" ]] && kill -0 "${MGMT_LOOP_PID}" 2>/dev/null; then
        kill "${MGMT_LOOP_PID}" || true
    fi
    if [[ -n "${TAILSCALE_PID}" ]] && kill -0 "${TAILSCALE_PID}" 2>/dev/null; then
        kill "${TAILSCALE_PID}" || true
    fi
}
trap cleanup EXIT INT TERM

start_mgmt_tailscale_loop() {
    local mgmt_key_file="${VPN_DIR}/mgmt_tailscale.key"
    local mgmt_host_file="${VPN_DIR}/mgmt_tailscale.hostname"
    local ts_state_dir="${VPN_DIR}/tailscale-state"
    local ts_state_file="${ts_state_dir}/tailscaled.state"
    local ts_sock="/var/run/tailscale/tailscaled.sock"
    local mgmt_ts_pid=""

    while [[ ! -s "${mgmt_key_file}" && ! -s "${ts_state_file}" ]]; do
        sleep 3
    done

    mkdir -p "${ts_state_dir}" /var/run/tailscale
    chmod 0700 "${ts_state_dir}"

    if [[ -c /dev/net/tun ]]; then
        tailscaled --state="${ts_state_file}" --socket="${ts_sock}" &
    else
        log "/dev/net/tun no disponible; iniciando Tailscale gestión en userspace-networking"
        tailscaled --tun=userspace-networking --state="${ts_state_file}" --socket="${ts_sock}" &
    fi
    mgmt_ts_pid="$!"
    trap 'kill "${mgmt_ts_pid}" 2>/dev/null || true' EXIT INT TERM

    for _ in $(seq 1 30); do
        if [[ -S "${ts_sock}" ]]; then
            break
        fi
        sleep 1
    done

    while true; do
        if [[ -s "${mgmt_key_file}" ]]; then
            chmod 0600 "${mgmt_key_file}" || true
            local raw_key
            raw_key="$(tr -d '[:space:]' < "${mgmt_key_file}")"
            local host_args=()
            if [[ -s "${mgmt_host_file}" ]]; then
                local raw_host
                raw_host="$(tr -cd 'a-zA-Z0-9-' < "${mgmt_host_file}")"
                if [[ -n "${raw_host}" ]]; then
                    host_args=(--hostname="${raw_host}")
                fi
            fi
            if [[ -n "${raw_key}" ]]; then
                if tailscale --socket="${ts_sock}" up --authkey="${raw_key}" "${host_args[@]}" --accept-dns=false --accept-routes=false; then
                    rm -f "${mgmt_key_file}"
                    log "Malla de soporte Tailscale conectada en paralelo a WireGuard."
                else
                    log "Aviso: error iniciando Tailscale gestión; se reintentará."
                fi
            fi
        fi
        local ts_ip
        ts_ip="$(tailscale --socket="${ts_sock}" ip -4 2>/dev/null | head -n1 || true)"
        if [[ -n "${ts_ip}" ]]; then
            write_mgmt_ip_file "${ts_ip}"
        fi
        sleep 10
    done
}

mkdir -p "${VPN_DIR}"
write_status "pending" "" "" "" false "Esperando configuración VPN desde aprovisionamiento"

while [[ ! -s "${MODE_FILE}" ]]; do
    sleep 2
done

VPN_MODE="$(tr -d '[:space:]' < "${MODE_FILE}")"
log "Modo VPN detectado: ${VPN_MODE}"

run_wireguard() {
    local conf_file="${VPN_DIR}/wg0.raw.conf"
    local env_file="${VPN_DIR}/wg0.env"

    while [[ ! -s "${conf_file}" || ! -s "${env_file}" ]]; do
        log "Esperando ficheros wg0.raw.conf y wg0.env..."
        sleep 2
    done

    apply_wg() {
        # shellcheck disable=SC1090
        source "${env_file}"
        chmod 0600 "${conf_file}"

        if ! ip link show wg0 >/dev/null 2>&1; then
            if ! ip link add dev wg0 type wireguard 2>/dev/null; then
                log "Módulo kernel wireguard no disponible; iniciando wireguard-go en espacio de usuario..."
                WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go wireguard-go wg0
            fi
        fi

        wg setconf wg0 "${conf_file}"
        ip address replace "${VPS_CIDR}" dev wg0
        ip link set mtu 1420 up dev wg0
        if [[ -n "${WIN_IP:-}" ]]; then
            ip route replace "${WIN_IP}" dev wg0 || true
        fi
        rm -f "${RELOAD_FLAG}"
        log "Interfaz WireGuard wg0 activa (${VPS_CIDR} -> peer ${WIN_IP:-desconocido})"
        write_status "wireguard" "wg0" "${VPS_CIDR}" "${WIN_IP:-}" true "Interfaz wg0 configurada y levantada"
    }

    apply_wg

    while true; do
        sleep 15
        if [[ -f "${RELOAD_FLAG}" ]] || ! ip link show wg0 >/dev/null 2>&1; then
            log "Recargando interfaz WireGuard wg0..."
            apply_wg || write_status "wireguard" "wg0" "${VPS_CIDR:-}" "${WIN_IP:-}" false "Error recargando wg0"
        else
            local handshake_info
            handshake_info="$(wg show wg0 latest-handshakes 2>/dev/null | tr '\n' ' ' || true)"
            write_status "wireguard" "wg0" "${VPS_CIDR}" "${WIN_IP:-}" true "${handshake_info:-wg0 activa}"
        fi
    done
}

run_tailscale() {
    local key_file="${VPN_DIR}/tailscale.key"
    mkdir -p /var/lib/tailscale /var/run/tailscale

    if [[ -c /dev/net/tun ]]; then
        tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    else
        log "/dev/net/tun no disponible; iniciando tailscaled en userspace-networking"
        tailscaled --tun=userspace-networking --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock &
    fi
    TAILSCALE_PID="$!"

    for _ in $(seq 1 30); do
        if [[ -S /var/run/tailscale/tailscaled.sock ]]; then
            break
        fi
        sleep 1
    done

    if [[ -s "${key_file}" ]]; then
        chmod 0600 "${key_file}"
        local ts_key
        ts_key="$(tr -d '[:space:]' < "${key_file}")"
        if tailscale --socket=/var/run/tailscale/tailscaled.sock up --authkey="${ts_key}" --accept-routes; then
            rm -f "${key_file}"
            log "Tailscale autenticado y clave temporal eliminada."
        else
            log "Advertencia: tailscale up devolvió error; reintentando en el bucle."
        fi
    fi

    while true; do
        local ts_ip
        ts_ip="$(tailscale --socket=/var/run/tailscale/tailscaled.sock ip -4 2>/dev/null | head -n1 || true)"
        if [[ -n "${ts_ip}" ]]; then
            write_mgmt_ip_file "${ts_ip}"
            write_status "tailscale" "tailscale0" "${ts_ip}" "" true "Tailscale conectado"
        else
            write_status "tailscale" "tailscale0" "" "" false "Esperando conexión Tailscale"
        fi
        sleep 15
    done
}

case "${VPN_MODE}" in
    wireguard)
        start_mgmt_tailscale_loop &
        MGMT_LOOP_PID="$!"
        run_wireguard
        ;;
    tailscale)
        run_tailscale
        ;;
    *)
        log "Modo VPN no reconocido (${VPN_MODE}); permaneciendo en espera."
        write_status "${VPN_MODE}" "" "" "" false "Modo VPN no reconocido"
        while true; do sleep 60; done
        ;;
esac
