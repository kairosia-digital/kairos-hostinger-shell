FROM alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/kairosia-digital/kairos-hostinger-shell"

RUN apk add --no-cache \
    bash \
    iproute2 \
    wireguard-tools \
    iptables \
    tailscale \
    ca-certificates \
    jq

COPY vpn-supervisor.sh /usr/local/bin/vpn-supervisor.sh
RUN chmod 0755 /usr/local/bin/vpn-supervisor.sh

ENTRYPOINT ["/usr/local/bin/vpn-supervisor.sh"]
