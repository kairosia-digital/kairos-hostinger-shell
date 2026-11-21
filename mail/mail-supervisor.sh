#!/usr/bin/env bash
set -euo pipefail

MAIL_DIR="/etc/kairos-mail"
ENV_FILE="${MAIL_DIR}/mail.env"
STATUS_FILE="${MAIL_DIR}/status.json"
RELOAD_FLAG="${MAIL_DIR}/.reload"
VMAIL_ROOT="/var/mail/vhosts"

log() {
    printf '[kairos-mail %s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

write_status() {
    local ready="$1"
    local enabled="$2"
    local user="$3"
    local details="$4"
    jq -n \
        --argjson ready "$ready" \
        --argjson enabled "$enabled" \
        --arg user "$user" \
        --arg details "$details" \
        --arg updated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        '{ready: $ready, enabled: $enabled, user: $user, details: $details, updated_at: $updated_at}' \
        > "${STATUS_FILE}.tmp"
    mv "${STATUS_FILE}.tmp" "${STATUS_FILE}"
}

cleanup() {
    dovecot stop >/dev/null 2>&1 || true
    postfix stop >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "${MAIL_DIR}" "${VMAIL_ROOT}"
chown -R vmail:vmail "${VMAIL_ROOT}"
write_status false false "" "Esperando configuración /etc/kairos-mail/mail.env"

while [[ ! -s "${ENV_FILE}" ]]; do
    sleep 2
done

configure_and_start() {
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    chmod 0600 "${ENV_FILE}"

    local enabled="${MAIL_ENABLED:-false}"
    local domain="${MAIL_DOMAIN:-kairosia.digital}"
    local mail_user="${MAIL_USER:-}"
    local mail_pass="${MAIL_PASSWORD:-}"
    local purge_days="${PURGE_SEEN_DAYS:-45}"

    if [[ "${enabled}" != "true" ]] || [[ -z "${mail_user}" ]] || [[ -z "${mail_pass}" ]]; then
        log "Buzón local en VPS deshabilitado (se utiliza IMAP externo)."
        dovecot stop >/dev/null 2>&1 || true
        postfix stop >/dev/null 2>&1 || true
        rm -f "${RELOAD_FLAG}"
        write_status true false "${mail_user}" "Modo IMAP externo activo"
        return 0
    fi

    local localpart="${mail_user%%@*}"
    local user_domain="${mail_user#*@}"
    if [[ -n "${user_domain}" ]]; then
        domain="${user_domain}"
    fi

    local home_dir="${VMAIL_ROOT}/${domain}/${localpart}"
    mkdir -p "${home_dir}/Maildir"
    chown -R vmail:vmail "${VMAIL_ROOT}/${domain}"

    local pass_hash
    pass_hash="$(doveadm pw -s SHA512-CRYPT -p "${mail_pass}")"
    printf '%s:%s:5000:5000::%s::userdb_mail=maildir:~/Maildir\n' "${mail_user}" "${pass_hash}" "${home_dir}" > /etc/dovecot/users
    chmod 0640 /etc/dovecot/users
    chown root:dovecot /etc/dovecot/users || true

    cat > /etc/dovecot/dovecot.conf <<EOF
protocols = imap lmtp
listen = *
mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
last_valid_uid = 5000
mail_location = maildir:~/Maildir
ssl = no
disable_plaintext_auth = no
auth_mechanisms = plain login

passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users
}

userdb {
  driver = passwd-file
  args = username_format=%u /etc/dovecot/users
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 0
  }
}

namespace inbox {
  inbox = yes
}
EOF

    mkdir -p /var/spool/postfix/private
    printf '%s %s/Maildir/\n' "${mail_user}" "${domain}/${localpart}" > /etc/postfix/vmailbox
    postmap "lmdb:/etc/postfix/vmailbox"

    postconf -e "myhostname = ${domain}"
    postconf -e "mydomain = ${domain}"
    postconf -e "mydestination = localhost"
    postconf -e "inet_interfaces = all"
    postconf -e "inet_protocols = ipv4"
    postconf -e "virtual_mailbox_domains = ${domain}"
    postconf -e "virtual_mailbox_maps = lmdb:/etc/postfix/vmailbox"
    postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
    postconf -e "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination, reject_unlisted_recipient"
    postconf -e "default_transport = error:Outbound mail disabled on ingestion-only mailbox"
    postconf -e "message_size_limit = 26214400"
    postconf -e "maillog_file = /dev/stdout"

    dovecot stop >/dev/null 2>&1 || true
    postfix stop >/dev/null 2>&1 || true
    dovecot
    postfix start
    doveadm mailbox create -u "${mail_user}" INBOX >/dev/null 2>&1 || true

    rm -f "${RELOAD_FLAG}"
    log "Servidor de correo de ingesta activo para ${mail_user} (purga SEEN > ${purge_days} días)."
    write_status true true "${mail_user}" "Postfix (25/tcp) + Dovecot IMAP interno (143/tcp) operativos"
}

configure_and_start
LAST_PURGE_DAY=""

while true; do
    sleep 30
    if [[ -f "${RELOAD_FLAG}" ]]; then
        log "Recarga solicitada en ${RELOAD_FLAG}..."
        configure_and_start || write_status false false "" "Error recargando configuración de correo"
    fi

    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    TODAY_UTC="$(date -u +'%Y-%m-%d')"
    if [[ "${MAIL_ENABLED:-false}" == "true" ]] && [[ -n "${MAIL_USER:-}" ]] && [[ "${TODAY_UTC}" != "${LAST_PURGE_DAY}" ]]; then
        PURGE_DAYS="${PURGE_SEEN_DAYS:-45}"
        doveadm expunge -u "${MAIL_USER}" mailbox INBOX SEEN savedbefore "${PURGE_DAYS}d" >/dev/null 2>&1 || true
        LAST_PURGE_DAY="${TODAY_UTC}"
    fi
done
