# Kairós IA — Hostinger KVM 2 Deployment Shell

Plantilla pública Docker Compose (*Cascarón Público*) para el despliegue 1-Click de **Odoo 19.0 Community + Kairós IA** sobre **Hostinger VPS KVM 2** (2 vCPU AMD EPYC, 8 GB RAM, 100 GB NVMe).

> **Seguridad de Código y Secretos:** Este repositorio contiene exclusivamente la definición de infraestructura base y el agente de arranque (*Guardián*). No incluye código propietario ni credenciales. Los módulos y parámetros de cada cliente se entregan por HTTPS mediante un `PROVISION_TOKEN` de un solo uso y se procesan exclusivamente en memoria volátil (`/dev/shm`).

---

## Despliegue 1-Click en Hostinger

[![Deploy on Hostinger](https://assets.hostinger.com/vps/deploy.svg)](https://www.hostinger.com/es/docker-hosting?compose_url=https://raw.githubusercontent.com/kairosia-digital/kairos-hostinger-shell/main/docker-compose.yml&REFERRALCODE=WN8LORENZMQY)

### Arquitectura del Stack (`docker-compose.yml`)

| Servicio | Imagen / Rol | Recursos y Seguridad |
| :--- | :--- | :--- |
| **`db`** | `postgres:16-alpine` | Dimensionado para KVM 2 (`shared_buffers=2GB`, `effective_cache_size=4GB`, `work_mem=16MB`). Sin exposición al host. |
| **`odoo`** | `odoo:19.0` + Bootstrapper Guardián | `tmpfs` en `/dev/shm` (`512m`), `workers=4`, `list_db=False`, `proxy_mode=True` tras Traefik. Bloquea `/web/database*` y detiene el arranque público de Odoo hasta completar la activación con token válido. |
| **`vpn`** | Supervisor WireGuard / Tailscale (`alpine:3.20`) | Comparte `network_mode: "service:odoo"` para levantar `wg0` (`10.88.<octeto>.1/24`) con `CAP_NET_ADMIN` aislado en su contenedor y tráfico saliente directo hacia el puente local `10.88.<octeto>.2:8765`. |

---

## Flujos de Activación (`PROVISION_TOKEN`)

1. **Ruta A (Cero clics adicionales):** El cliente pega `PROVISION_TOKEN` en las variables de entorno de Hostinger Docker Manager antes de pulsar *Deploy*. Al arrancar el contenedor, el Guardián detecta el token, ejecuta el handshake automático y abre Odoo listo para operar.
2. **Ruta B (Pantalla Guardián Web):** Si `PROVISION_TOKEN` se deja vacío en el despliegue, el puerto `8069` expone una pantalla segura de **Activación de Sistema** (protegida con *rate limiting* y bloqueo completo del gestor de bases de datos) para introducir el código de un solo uso.

## Flujo en Memoria Volátil (`/dev/shm`)

1. `POST /api/v1/provisioning/handshake` → consume el `PROVISION_TOKEN` y emite una URL efímera (`TTL = 60 s`) + JWT de sesión (`TTL = 15 min`).
2. `GET /api/v1/provisioning/artifact/{one_time_id}` → descarga en `/dev/shm/module.tar.gz`, verifica `SHA-256` en tiempo constante, extrae en `/mnt/extra-addons` y elimina inmediatamente el `.tar.gz` de RAM.
3. `POST /api/v1/provisioning/payload` → escribe `/dev/shm/payload.json` (`0600`), configura `wg0`/Tailscale, inicializa `odoo_prod` (`l10n_es` + addons Kairós), inyecta compañía/usuario/Gemini/IMAP con autoverificación y borra `/dev/shm/payload.json`.
4. Sella `/var/lib/odoo/.provisioned` y notifica `waiting_erp_sync` o `active` al orquestador central.
