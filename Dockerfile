FROM odoo:19.0

LABEL org.opencontainers.image.source="https://github.com/kairosia-digital/kairos-hostinger-shell"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        poppler-utils \
        curl \
        jq \
        gosu \
        ca-certificates \
        postgresql-client && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed \
        google-generativeai \
        pdf2image \
        Pillow \
        thefuzz \
        python-Levenshtein \
        pyopenssl

COPY bootstrapper/ /opt/kairos-bootstrapper/
RUN chmod 0755 /opt/kairos-bootstrapper/entrypoint-bootstrapper.sh \
    /opt/kairos-bootstrapper/provision_runner.py \
    /opt/kairos-bootstrapper/guardian_server.py \
    /opt/kairos-bootstrapper/inject_config.py \
    /opt/kairos-bootstrapper/apply_day2_update.py

EXPOSE 8069 8072

ENTRYPOINT ["/opt/kairos-bootstrapper/entrypoint-bootstrapper.sh"]
