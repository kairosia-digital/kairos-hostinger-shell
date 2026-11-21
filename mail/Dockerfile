FROM alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/kairosia-digital/kairos-hostinger-shell"

RUN apk add --no-cache \
        bash \
        postfix \
        dovecot \
        dovecot-lmtpd \
        jq \
        tzdata \
        ca-certificates && \
    addgroup -g 5000 vmail && \
    adduser -D -u 5000 -G vmail -h /var/mail/vhosts -s /sbin/nologin vmail

COPY mail-supervisor.sh /usr/local/bin/mail-supervisor.sh
RUN chmod 0755 /usr/local/bin/mail-supervisor.sh

EXPOSE 25 143

ENTRYPOINT ["/usr/local/bin/mail-supervisor.sh"]
