# Odoo Sandbox

Upload an Odoo addon ZIP, pick an Odoo version, and get a throwaway Odoo instance
with the addon installed — each one with its own PostgreSQL, resource limits, and
no outbound network. Built for functional consultants to try addons without a
developer setting up an environment.

## How it works

```
browser ──► proxy (nginx) ──┬── <SANDBOX_DOMAIN>          ──► api (FastAPI + manager page)
                            └── <job id>.<SANDBOX_DOMAIN> ──► lab-<job id>  (Odoo)
                                                                   │
api ──► data/lab.sqlite3 ◄── worker ──► host Docker ──► per-job compose project:
                                                        db (postgres:16) + odoo:<version>
```

1. `POST /api/jobs` stores the ZIP and queues a job.
2. The worker validates and extracts the ZIP and checks each manifest's version
   against the chosen Odoo version. It then starts PostgreSQL, installs the addons
   with `--stop-after-init`, and verifies that they are `installed`.
3. The worker connects the shared proxy to the job's private (internal) network and
   marks the job `ready` with its URL.
4. Sandboxes are deleted 2 hours after they become ready (`LAB_TTL_SECONDS`).

Job status flow: `queued → validating → provisioning → installing → starting → ready`,
or `failed` with an `error`. Stop/start/delete go through `*_requested` states
that the worker picks up.

## Project layout

```
app/
  main.py                  API and quota checks; serves the manager page at /
  worker.py                Job runner (stdlib only): ZIP checks, docker compose, cleanup
  manager.html             Manager UI: upload, status, open/stop/start/delete
proxy/
  default.conf.template    nginx config for the manager host and per-sandbox subdomains
examples/
  ibase_billing_note.zip   Sample addon (Odoo 20.0)
Dockerfile                 Image for api and worker (Python + docker CLI)
docker-compose.yml         Local stack
docker-compose.prod.yml    Production overrides
.env.example               Production settings
data/                      Runtime state: SQLite DB, uploaded ZIPs, per-job logs (git-ignored)
```

## Run locally

Requirements: Docker Desktop (or Docker Engine) with Compose v2.

```bash
docker compose up -d --build
```

- Manager: <http://localhost:8080> (or the API directly at <http://127.0.0.1:8000>)
- Sandboxes: `http://<job id without dashes>.localhost:8080`, login `admin` / `admin`

`*.localhost` resolves to your own machine in Chrome, Firefox, and curl. If a browser
does not resolve it, add `127.0.0.1 <job id hex>.localhost` to `/etc/hosts`.

Run `docker compose` from the project directory. The worker passes paths under
`data/` to the host Docker daemon as bind-mount sources, so `data/` is mounted at
the same absolute path inside the containers.

Logs:

```bash
docker compose logs -f worker                # status changes for every job
tail -f data/jobs/<job id>/worker.log        # docker/Odoo output for one job
```

## API

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/jobs` | Form fields `odoo_version` (`18.0`, `19.0`, `20.0`) and `addon_zip`. Returns `202` with the job. |
| `GET` | `/api/me` | Returns the user name of the caller (`{"user": "fc-somchai"}`). |
| `GET` | `/api/jobs` | Lists jobs (newest first). |
| `GET` | `/api/jobs/{id}` | Returns one job: `status`, `url`, `error`. |
| `POST` | `/api/jobs/{id}/stop` | Stops a `ready` sandbox and keeps its data. |
| `POST` | `/api/jobs/{id}/start` | Starts a `stopped` sandbox again. |
| `POST` | `/api/jobs/{id}/delete` | Removes containers, volumes, and files. |
| `POST` | `/api/tokens` | Admin only. JSON `{"name": "fc-somchai"}`. Returns the token once. |
| `GET` | `/api/tokens` | Admin only. Lists token names (not the tokens themselves). |
| `DELETE` | `/api/tokens/{id}` | Admin only. Revokes a token. |

```bash
curl -F odoo_version=20.0 -F addon_zip=@examples/ibase_billing_note.zip http://localhost:8080/api/jobs
curl http://localhost:8080/api/jobs/<job id>
```

### API tokens

Scripts and other systems call the API with a token in the `X-API-Key` header.

1. Generate a token with `POST /api/tokens` as admin. The response shows the token
   once. The database stores only its SHA-256 hash.
2. Jobs created with a token belong to the token's name. A token sees only its own
   jobs, and the per-user quota counts its jobs separately from other tokens.
3. Revoke a token with `DELETE /api/tokens/{id}`. Requests with that token then get
   `401`.

```bash
# Generate (locally the API is open; in production add -u <basic auth user>:<password>)
curl -X POST -H 'Content-Type: application/json' -d '{"name": "fc-somchai"}' \
  https://sandbox.example.com/api/tokens

# List and revoke
curl https://sandbox.example.com/api/tokens
curl -X DELETE https://sandbox.example.com/api/tokens/<token id>

# Use
curl -H "X-API-Key: sbx_..." -F odoo_version=19.0 -F addon_zip=@my_addon.zip \
  https://sandbox.example.com/api/jobs
```

The manager page asks for a token too, so every job shows who created it. The page
keeps the token in the browser's local storage.

Who is `admin`: anyone who uses the manager page (protected by basic auth in
production, open locally), or an `admin:<key>` entry in `SANDBOX_API_KEYS`. A request
with an `X-API-Key` header skips the proxy's basic auth, and the API checks the key.
An unknown key gets `401`.

### ZIP rules

- One or more addon folders, each with `__manifest__.py` and `__init__.py`. The
  folders can be at the ZIP root or nested inside one folder.
- 20 MB upload limit, 200 MB uncompressed, 5000 entries max.
- No symlinks, absolute paths, `..`, or encrypted entries.
- A full manifest version (`20.0.1.0.0`) must match the selected Odoo version.

## Configuration

Set these in the shell or in `.env` next to the compose files.

| Variable | Default | Purpose |
|---|---|---|
| `SANDBOX_DOMAIN` | `localhost` | Host name of the manager page. Sandboxes are served from its subdomains. |
| `LAB_URL_TEMPLATE` | `http://{id}.localhost:8080` | Sandbox URL returned by the API. `{id}` is the job ID without dashes. |
| `SANDBOX_DATA_DIR` | `$PWD/data` | Absolute host path for runtime data. |
| `PROXY_BIND` | `0.0.0.0:80` | Production only: the address the proxy listens on. |
| `MAX_ACTIVE_PER_USER` | `2` | Sandboxes per user that are not `failed` or `deleted`. |
| `MAX_ACTIVE_TOTAL` | `6` | Server-wide cap. Each sandbox can use up to 1.5 CPU and 2 GB RAM. |
| `LAB_TTL_SECONDS` | `7200` | Seconds a sandbox stays available after it becomes ready. |
| `ODOO_IMAGE_18` / `_19` / `_20` | `ghcr.io/imotif/odoo-ee:<version>` | Use a different Odoo image for a version. |
| `REGISTRY`, `REGISTRY_USER`, `REGISTRY_TOKEN` | `ghcr.io`, empty, empty | Worker only. Logs in to pull private images. For GHCR, use a token with `read:packages`. |
| `SANDBOX_API_KEYS` | empty | Optional fixed `user:key,...` pairs. If this is set, requests without a key are rejected, which also disables the manager page. Prefer generated tokens. |

## Production

1. **DNS:** create records for both `sandbox.example.com` and `*.sandbox.example.com`
   that point to the server.
2. **TLS:** terminate TLS in front of the proxy, for example with a Cloudflare proxied
   record or a load balancer. The proxy listens on plain HTTP and forwards
   `X-Forwarded-Proto` to Odoo.
   - Cloudflare Universal SSL covers only one subdomain level. A name like
     `*.sandbox.example.com` needs an Advanced Certificate. The other option is a
     dedicated domain, so that sandboxes are `<id>.example-sandbox.com`.
3. **Settings:**
   ```bash
   cp .env.example .env    # set SANDBOX_DOMAIN, LAB_URL_TEMPLATE (https://{id}...), SANDBOX_DATA_DIR
   mkdir -p /srv/odoo-sandbox/data
   ```
4. **Manager login:** the manager page and the API are protected by HTTP basic auth
   at the proxy:
   ```bash
   docker run --rm httpd:alpine htpasswd -nbB fc1 'a-strong-password' >> proxy/htpasswd
   ```
5. **Start:**
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```

In production, the API port is not published, so the proxy is the only way in. To
pre-pull the Odoo images and make the first job faster, run
`docker pull ghcr.io/imotif/odoo-ee:20.0 postgres:16` (and any other versions you use).
The worker pulls an image only when it is missing on the host.

## Security notes

- The worker mounts `/var/run/docker.sock`, which gives it root access to the host.
  Run the stack on a dedicated machine or VM.
- Uploaded addons run as Odoo code inside the sandbox. Each sandbox has dropped
  capabilities, `no-new-privileges`, CPU/RAM/PID limits, and an internal network with
  no internet access. This limits what an addon can do, but containers are not a
  strong boundary against hostile code.
- Every sandbox uses `admin` / `admin`. The URL contains a random 128-bit job ID, so
  anyone who has the link can log in. Share the links only with people who should
  use them.

## Limitations

- One worker runs one job at a time. Stop, start, and delete requests wait while an
  install is running.
- Quota checks are not atomic, so two uploads at the same moment can both pass.
- Addons that need extra Python packages or other addons that are not in the ZIP
  fail at install. Use a custom image (`ODOO_IMAGE_<version>`) for these addons.
