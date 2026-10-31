# Odoo Sandbox

Upload an Odoo addon ZIP, pick an Odoo version, and get a throwaway Odoo instance
with the addon installed — each one with its own PostgreSQL, resource limits, and
no outbound network. Built for functional consultants to try addons without a
developer setting up an environment.

## How it works

```
browser ──► proxy (nginx) ──┬── <SANDBOX_DOMAIN>          ──► React UI (odoo-sandbox-ui) + api (FastAPI)
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
  main.py                  API, Microsoft sign-in, sessions, and quota checks
  worker.py                Job runner (stdlib only): ZIP checks, docker compose, cleanup
proxy/
  default.conf.template    nginx config for the UI/API host and per-sandbox subdomains
tests/
  test_auth.py             Sign-in, session, role, and CSRF checks
examples/
  ibase_billing_note.zip   Sample addon (Odoo 20.0)
Dockerfile                 Image for api and worker, published as taotoxicboy/odoo-sandbox:1
docker-compose.yml         Local and production stack
.env.example               Production settings
data/                      Runtime state: SQLite DB, uploaded ZIPs, per-job logs (git-ignored)
```

## Run locally

Requirements: Docker Desktop (or Docker Engine) with Compose v2.

```bash
docker compose up -d
```

- UI: run `npm run dev` in `odoo-sandbox-ui`, then open <http://localhost:5173>. Vite forwards `/api` and `/auth` to the proxy on port 8080.
- Set `OIDC_TENANT_ID`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` in `.env` first (see [Microsoft sign-in](#microsoft-sign-in)).
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
| `GET` | `/auth/login` | Redirects to Microsoft sign-in. |
| `GET` | `/auth/callback` | Microsoft redirect target. Sets the access and refresh token cookies. |
| `POST` | `/auth/refresh` | Rotates both tokens using the refresh token cookie. |
| `POST` | `/auth/logout` | Revokes both tokens here. The Microsoft session stays signed in. |
| `POST` | `/api/jobs` | Form fields `odoo_version` (`18.0`, `19.0`, `20.0`), `addon_zip`, and optional `edition` (`enterprise` by default, or `community`). Returns `202` with the job. |
| `GET` | `/api/me` | Returns the caller: `user`, `display_name`, `is_admin`. |
| `GET` | `/api/stats` | Admin only. Returns the total as `environments`. |
| `GET` | `/api/jobs` | Lists every user's jobs (newest first). |
| `POST` | `/api/jobs/{id}/stop` | Owner or admin. Stops a `ready` sandbox and keeps its data. |
| `POST` | `/api/jobs/{id}/start` | Owner or admin. Starts a `stopped` sandbox again. |
| `POST` | `/api/jobs/{id}/delete` | Owner or admin. Removes containers, volumes, and files. |

### Microsoft sign-in

The API handles the whole sign-in with the Entra app `Odoo Sandbox`. It then issues
its own access and refresh tokens in `HttpOnly` cookies. Both are random values, and the
database stores only their SHA-256 hashes. Each refresh replaces both tokens.

1. In the app registration, add a **Web** redirect URI that matches
   `OIDC_REDIRECT_URI`. Locally this is `http://localhost:5173/auth/callback`.
2. Create a client secret and put it in `.env` as `OIDC_CLIENT_SECRET`.
3. Assign the app role with value `admin` to admins. Admins see `/api/stats` and can
   change any job. Everyone in the tenant can sign in, create
   sandboxes, see every job, and change their own jobs.

Role changes apply at the next Microsoft sign-in. Each refresh resets the refresh token
to `REFRESH_TOKEN_TTL_SECONDS`, so users sign in again only after that long without use.
To remove someone's access at once, delete their rows from `auth_tokens`.

### ZIP rules

- One or more addon folders, each with `__manifest__.py` and `__init__.py`. The
  folders can be at the ZIP root or nested inside one folder.
- No upload size limit. Extraction limits: `ZIP_MAX_UNCOMPRESSED_MB` (5120) and
  `ZIP_MAX_ENTRIES` (100000), plus a compression ratio check against ZIP bombs.
- No symlinks, absolute paths, `..`, or encrypted entries.
- A full manifest version (`20.0.1.0.0`) must match the selected Odoo version.

## Configuration

Set these in the shell or in `.env` next to the compose files.

| Variable | Default | Purpose |
|---|---|---|
| `SANDBOX_DOMAIN` | `localhost` | Host name of the UI and API. Sandboxes are served from its subdomains. |
| `LAB_URL_TEMPLATE` | `http://{id}.localhost:8080` | Sandbox URL returned by the API. `{id}` is the job ID without dashes. |
| `SANDBOX_DATA_DIR` | `$PWD/data` | Absolute host path for runtime data. |
| `PROXY_BIND` | `127.0.0.1:8080` | Address the proxy listens on. Use `0.0.0.0:80` in production. |
| `MAX_ACTIVE_PER_USER` | `2` | Sandboxes per user that are not `failed` or `deleted`. |
| `MAX_ACTIVE_TOTAL` | `6` | Server-wide cap. Each sandbox can use up to 1.5 CPU and 2 GB RAM. |
| `LAB_TTL_SECONDS` | `7200` | Seconds a sandbox stays available after it becomes ready. |
| `ODOO_IMAGE_18` / `_19` / `_20` | `ghcr.io/imotif/odoo-ee:<version>` | Use a different Enterprise image for a version. |
| `ODOO_COMMUNITY_IMAGE_18` / `_19` / `_20` | `odoo:<version>` | Use a different Community image for a version. |
| `OIDC_TENANT_ID`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | empty | API only. Entra app used for sign-in. |
| `OIDC_REDIRECT_URI` | `http://localhost:5173/auth/callback` | Must match the Web redirect URI in Entra. `https://` also makes cookies `Secure`. |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | How long an access token lasts. |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | Time without use (30 days) before Microsoft sign-in is required again. |
| `REGISTRY`, `REGISTRY_USER`, `REGISTRY_TOKEN` | `ghcr.io`, empty, empty | Worker only. Logs in to pull private images. For GHCR, use a token with `read:packages`. |

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
4. **UI:** deploy `odoo-sandbox-ui` on the same `SANDBOX_DOMAIN` with `BACKEND_URL`
   pointing at this proxy, and add the production Web redirect URI in Entra.
5. **Start:**
   ```bash
   docker compose up -d
   ```

To pre-pull the Odoo images and make the first job faster, run
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
  anyone who has the link can log in. Every signed-in user sees every link.

## Limitations

- One worker runs one job at a time. Stop, start, and delete requests wait while an
  install is running.
- Quota checks are not atomic, so two uploads at the same moment can both pass.
- Addons that need extra Python packages or other addons that are not in the ZIP
  fail at install. Use a custom image (`ODOO_IMAGE_<version>`) for these addons.
