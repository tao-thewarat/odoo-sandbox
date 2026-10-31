import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import time
import urllib.parse
import urllib.request
import zipfile
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, NamedTuple
from uuid import UUID, uuid4

from fastapi import Body, Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel

DATA_DIR = Path(os.getenv("DATA_DIR", "data")).resolve()
JOBS_DIR = DATA_DIR / "jobs"
DATABASE = DATA_DIR / "lab.sqlite3"

MAX_ACTIVE_PER_USER = int(os.getenv("MAX_ACTIVE_PER_USER", "2"))
MAX_ACTIVE_TOTAL = int(os.getenv("MAX_ACTIVE_TOTAL", "6"))
INACTIVE = ("failed", "deleted")
OdooVersion = Literal["18.0", "19.0", "20.0"]
OdooEdition = Literal["enterprise", "community"]
LOG = logging.getLogger("uvicorn.error")

# Microsoft Entra sign-in (authorization code flow with PKCE, handled entirely here).
OIDC_TENANT_ID = os.getenv("OIDC_TENANT_ID", "")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "http://localhost:5173/auth/callback")
OIDC_AUTHORITY = f"https://login.microsoftonline.com/{OIDC_TENANT_ID}"
ACCESS_COOKIE = "sandbox_access"
REFRESH_COOKIE = "sandbox_refresh"
LOGIN_COOKIE = "sandbox_login"
ACCESS_TOKEN_TTL = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900"))
# Sliding: each refresh resets this, so it expires only after this long without use.
REFRESH_TOKEN_TTL = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", str(30 * 24 * 3600)))
SECURE_COOKIES = OIDC_REDIRECT_URI.startswith("https://")

# SANDBOX_API_KEYS="alice:<key>,bob:<key>"; the "admin" user sees every job.
API_KEYS = {
    key: user
    for user, _, key in (
        item.strip().partition(":")
        for item in os.getenv("SANDBOX_API_KEYS", "").split(",")
        if item.strip()
    )
}
if not all(user and len(key) >= 16 for key, user in API_KEYS.items()):
    raise RuntimeError("SANDBOX_API_KEYS must be 'user:key,...' (keys of 16+ chars)")


def connect():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


@asynccontextmanager
async def lifespan(app: FastAPI):
    JOBS_DIR.mkdir(parents=True, exist_ok=True)

    with closing(connect()) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                odoo_version TEXT NOT NULL,
                status TEXT NOT NULL,
                zip_path TEXT NOT NULL,
                url TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                owner TEXT,
                edition TEXT NOT NULL DEFAULT 'enterprise',
                name TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS auth_tokens (
                access_hash TEXT PRIMARY KEY,
                refresh_hash TEXT NOT NULL UNIQUE,
                user TEXT NOT NULL,
                display_name TEXT NOT NULL,
                is_admin INTEGER NOT NULL,
                access_expires_at INTEGER NOT NULL,
                refresh_expires_at INTEGER NOT NULL
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(jobs)")}
        if "owner" not in columns:
            connection.execute("ALTER TABLE jobs ADD COLUMN owner TEXT")
        if "edition" not in columns:
            connection.execute("ALTER TABLE jobs ADD COLUMN edition TEXT NOT NULL DEFAULT 'enterprise'")
        if "name" not in columns:
            connection.execute("ALTER TABLE jobs ADD COLUMN name TEXT")
        connection.commit()

    yield


app = FastAPI(title="IMOTIF Odoo Sandbox", lifespan=lifespan)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Principal(NamedTuple):
    name: str
    is_admin: bool
    display_name: str


def check_same_origin(request: Request) -> None:
    # Sandboxes run uploaded code on sibling subdomains, which are same-site for
    # SameSite cookies, so cookie-authenticated writes must also match on Origin.
    origin = urllib.parse.urlsplit(request.headers.get("origin", "")).hostname
    host = urllib.parse.urlsplit("//" + request.headers.get("host", "")).hostname
    if not origin or origin != host:
        raise HTTPException(status_code=403, detail="Cross-origin request rejected")


def current_user(request: Request, x_api_key: Annotated[str, Header()] = "") -> Principal:
    if x_api_key:
        for key, user in API_KEYS.items():
            if secrets.compare_digest(key.encode(), x_api_key.encode()):
                return Principal(user, user == "admin", user)
        with closing(connect()) as connection:
            token = connection.execute(
                "SELECT name FROM tokens WHERE token_hash = ?", (hash_token(x_api_key),)
            ).fetchone()
        if token:
            return Principal(token["name"], False, token["name"])
        raise HTTPException(status_code=401, detail="Invalid API key")

    access = request.cookies.get(ACCESS_COOKIE)
    if access:
        with closing(connect()) as connection:
            row = connection.execute(
                """
                SELECT user, display_name, is_admin FROM auth_tokens
                WHERE access_hash = ? AND access_expires_at > ?
                """,
                (hash_token(access), int(time.time())),
            ).fetchone()
        if row:
            if request.method not in ("GET", "HEAD"):
                check_same_origin(request)
            return Principal(row["user"], bool(row["is_admin"]), row["display_name"])
    raise HTTPException(status_code=401, detail="Not signed in")


User = Annotated[Principal, Depends(current_user)]


class JobResponse(BaseModel):
    id: str
    odoo_version: OdooVersion
    edition: OdooEdition = "enterprise"
    name: str | None = None
    status: str
    url: str | None = None
    error: str | None = None
    created_at: str
    owner: str | None = None


def set_token_cookies(response: Response, access: str, refresh: str, refresh_expires_at: int) -> None:
    common = {"httponly": True, "samesite": "lax", "secure": SECURE_COOKIES}
    response.set_cookie(ACCESS_COOKIE, access, max_age=ACCESS_TOKEN_TTL, path="/", **common)
    # Scoped to /auth so the refresh token is sent only when it is needed.
    response.set_cookie(
        REFRESH_COOKIE, refresh, max_age=refresh_expires_at - int(time.time()), path="/auth", **common
    )


def clear_token_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path="/auth")


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def exchange_code(code: str, verifier: str) -> dict:
    """Redeems the code directly with Microsoft and returns the id_token claims."""
    body = urllib.parse.urlencode({
        "client_id": OIDC_CLIENT_ID,
        "client_secret": OIDC_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OIDC_REDIRECT_URI,
        "code_verifier": verifier,
    }).encode()
    request = urllib.request.Request(f"{OIDC_AUTHORITY}/oauth2/v2.0/token", data=body)
    with urllib.request.urlopen(request, timeout=10) as response:
        id_token = json.load(response)["id_token"]
    # The token came straight from Microsoft over TLS, so OIDC Core 3.1.3.7 lets us
    # skip the signature check; the claims are still validated by the caller.
    payload = id_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def valid_claims(claims: dict, nonce: str) -> bool:
    return (
        claims.get("aud") == OIDC_CLIENT_ID
        and claims.get("tid") == OIDC_TENANT_ID
        and claims.get("iss") == f"{OIDC_AUTHORITY}/v2.0"
        and secrets.compare_digest(str(claims.get("nonce", "")), nonce)
        and claims.get("exp", 0) > time.time()
        and bool(claims.get("preferred_username"))
    )


@app.get("/auth/login", include_in_schema=False)
def login():
    if not (OIDC_TENANT_ID and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET):
        raise HTTPException(status_code=503, detail="Microsoft sign-in is not configured")

    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    query = urllib.parse.urlencode({
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "response_mode": "query",
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": base64url(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
        "prompt": "select_account",
    })
    response = RedirectResponse(f"{OIDC_AUTHORITY}/oauth2/v2.0/authorize?{query}", status_code=303)
    response.set_cookie(
        LOGIN_COOKIE, f"{state}.{nonce}.{verifier}", max_age=600, path="/auth",
        httponly=True, samesite="lax", secure=SECURE_COOKIES,
    )  # fmt: skip
    return response


@app.get("/auth/callback", include_in_schema=False)
def callback(request: Request, code: str = "", state: str = ""):
    response = RedirectResponse("/?login_error=1", status_code=303)
    response.delete_cookie(LOGIN_COOKIE, path="/auth")

    expected_state, _, rest = request.cookies.get(LOGIN_COOKIE, "").partition(".")
    nonce, _, verifier = rest.partition(".")
    if not (code and verifier and secrets.compare_digest(state, expected_state)):
        LOG.warning("Sign-in rejected: missing code or state mismatch")
        return response

    try:
        claims = exchange_code(code, verifier)
    except Exception:
        LOG.exception("Sign-in failed: could not redeem the authorization code")
        return response
    if not valid_claims(claims, nonce):
        LOG.warning("Sign-in rejected: invalid id_token claims")
        return response

    access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    username = claims["preferred_username"].lower()
    now = int(time.time())
    refresh_expires_at = now + REFRESH_TOKEN_TTL
    with closing(connect()) as connection:
        connection.execute("DELETE FROM auth_tokens WHERE refresh_expires_at <= ?", (now,))
        connection.execute(
            """
            INSERT INTO auth_tokens (
                access_hash, refresh_hash, user, display_name, is_admin,
                access_expires_at, refresh_expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hash_token(access),
                hash_token(refresh),
                username,
                claims.get("name") or username,
                int("admin" in claims.get("roles", [])),
                now + ACCESS_TOKEN_TTL,
                refresh_expires_at,
            ),
        )
        connection.commit()

    response.headers["location"] = "/"
    set_token_cookies(response, access, refresh, refresh_expires_at)
    return response


@app.post("/auth/refresh", status_code=204, include_in_schema=False)
def refresh_tokens(request: Request, response: Response):
    check_same_origin(request)
    old_refresh = hash_token(request.cookies.get(REFRESH_COOKIE, ""))
    access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = int(time.time())
    refresh_expires_at = now + REFRESH_TOKEN_TTL
    with closing(connect()) as connection:
        # One UPDATE: a refresh token can rotate only once, even under concurrent calls.
        rotated = connection.execute(
            """
            UPDATE auth_tokens
            SET access_hash = ?, refresh_hash = ?, access_expires_at = ?, refresh_expires_at = ?
            WHERE refresh_hash = ? AND refresh_expires_at > ?
            """,
            (
                hash_token(access),
                hash_token(refresh),
                now + ACCESS_TOKEN_TTL,
                refresh_expires_at,
                old_refresh,
                now,
            ),
        ).rowcount
        connection.commit()
    if not rotated:
        failure = Response(status_code=401)
        clear_token_cookies(failure)
        return failure
    set_token_cookies(response, access, refresh, refresh_expires_at)


@app.post("/auth/logout", status_code=204, include_in_schema=False)
def logout(request: Request, response: Response):
    check_same_origin(request)
    # Works with an expired access token too, so the refresh token is always revoked.
    with closing(connect()) as connection:
        connection.execute(
            "DELETE FROM auth_tokens WHERE access_hash = ? OR refresh_hash = ?",
            (
                hash_token(request.cookies.get(ACCESS_COOKIE, "")),
                hash_token(request.cookies.get(REFRESH_COOKIE, "")),
            ),
        )
        connection.commit()
    clear_token_cookies(response)


@app.get("/api/me")
def me(user: User):
    return {"user": user.name, "display_name": user.display_name, "is_admin": user.is_admin}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/jobs", response_model=JobResponse, status_code=202)
def create_job(
    user: User,
    odoo_version: Annotated[OdooVersion, Form()],
    addon_zip: Annotated[UploadFile, File()],
    edition: Annotated[OdooEdition, Form()] = "enterprise",
):
    marks = ",".join("?" for _ in INACTIVE)
    with closing(connect()) as connection:
        # ponytail: check-then-insert can race; fine for a handful of FCs.
        total, mine = connection.execute(
            f"""
            SELECT count(*), coalesce(sum(owner = ?), 0)
            FROM jobs WHERE status NOT IN ({marks})
            """,
            (user.name, *INACTIVE),
        ).fetchone()
    if mine >= MAX_ACTIVE_PER_USER:
        raise HTTPException(
            status_code=429,
            detail=f"Quota reached: delete one of your {mine} active sandboxes first",
        )
    if total >= MAX_ACTIVE_TOTAL:
        raise HTTPException(status_code=503, detail="Server is full; try again later")

    job_id = str(uuid4())
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir()

    zip_path = job_dir / "addon.zip"

    try:
        # ponytail: no upload size cap (OCA repos are big); a full disk is the ceiling.
        with zip_path.open("wb") as destination:
            shutil.copyfileobj(addon_zip.file, destination, 1024 * 1024)

        if not zipfile.is_zipfile(zip_path):
            raise HTTPException(
                status_code=400,
                detail="Invalid ZIP file",
            )

        created_at = datetime.now(timezone.utc).isoformat()
        name = Path(addon_zip.filename or "addon").stem[:80]

        with closing(connect()) as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    id, odoo_version, status, zip_path, created_at, owner, edition, name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    odoo_version,
                    "queued",
                    str(zip_path),
                    created_at,
                    user.name,
                    edition,
                    name,
                ),
            )
            connection.commit()

    except Exception:
        shutil.rmtree(job_dir)
        raise
    finally:
        addon_zip.file.close()

    return JobResponse(
        id=job_id,
        odoo_version=odoo_version,
        edition=edition,
        name=name,
        status="queued",
        created_at=created_at,
        owner=user.name,
    )


@app.get("/api/jobs", response_model=list[JobResponse])
def list_jobs(user: User):
    with closing(connect()) as connection:
        rows = connection.execute(
            """
            SELECT id, odoo_version, edition, name, status, url, error, created_at, owner
            FROM jobs
            WHERE status != 'deleted'
            ORDER BY created_at DESC
            LIMIT 100
            """
        ).fetchall()
    return [dict(row) for row in rows]


def load_job(connection, job_id: UUID):
    job = connection.execute(
        """
        SELECT id, odoo_version, edition, name, status, url, error, created_at, owner
        FROM jobs
        WHERE id = ?
        """,
        (str(job_id),),
    ).fetchone()

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    return dict(job)


@app.get("/api/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: UUID, user: User):
    with closing(connect()) as connection:
        return load_job(connection, job_id)


# action -> (statuses it is allowed from, status the worker picks up)
ACTIONS = {
    "stop": (("ready",), "stop_requested"),
    "start": (("stopped",), "start_requested"),
    "delete": (("queued", "ready", "stopped", "failed"), "delete_requested"),
}


@app.post("/api/jobs/{job_id}/{action}", response_model=JobResponse, status_code=202)
def request_action(job_id: UUID, action: Literal["stop", "start", "delete"], user: User):
    allowed, requested = ACTIONS[action]
    with closing(connect()) as connection:
        job = load_job(connection, job_id)
        # Everyone can see every job; only its owner or an admin can change it.
        if job["owner"] != user.name and not user.is_admin:
            raise HTTPException(status_code=403, detail="Only the owner can change this sandbox")
        marks = ",".join("?" for _ in allowed)
        changed = connection.execute(
            f"UPDATE jobs SET status = ? WHERE id = ? AND status IN ({marks})",
            (requested, job["id"], *allowed),
        ).rowcount
        connection.commit()

    if not changed:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot {action} a job that is {job['status']}",
        )

    return {**job, "status": requested}


def require_admin(user: User) -> None:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")


@app.get("/api/stats", dependencies=[Depends(require_admin)])
def stats():
    marks = ",".join("?" for _ in INACTIVE)
    with closing(connect()) as connection:
        environments = connection.execute(
            f"SELECT count(*) FROM jobs WHERE status NOT IN ({marks})", INACTIVE
        ).fetchone()[0]
    return {"environments": environments}


class TokenResponse(BaseModel):
    id: str
    name: str
    created_at: str
    token: str | None = None  # Only returned once, on creation.


@app.post(
    "/api/tokens",
    response_model=TokenResponse,
    status_code=201,
    dependencies=[Depends(require_admin)],
)
def create_token(name: Annotated[str, Body(embed=True)]):
    # The name becomes the job owner, so it must not grant admin rights.
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name) or name == "admin":
        raise HTTPException(
            status_code=400,
            detail="Name must be 1-40 letters, digits, '.', '_' or '-' and not 'admin'",
        )

    token = "sbx_" + secrets.token_urlsafe(32)
    row = {
        "id": str(uuid4()),
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with closing(connect()) as connection:
        connection.execute(
            "INSERT INTO tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)",
            (row["id"], name, hash_token(token), row["created_at"]),
        )
        connection.commit()

    return {**row, "token": token}


@app.get(
    "/api/tokens",
    response_model=list[TokenResponse],
    dependencies=[Depends(require_admin)],
)
def list_tokens():
    with closing(connect()) as connection:
        rows = connection.execute(
            "SELECT id, name, created_at FROM tokens ORDER BY created_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


@app.delete(
    "/api/tokens/{token_id}",
    status_code=204,
    dependencies=[Depends(require_admin)],
)
def revoke_token(token_id: UUID):
    with closing(connect()) as connection:
        deleted = connection.execute(
            "DELETE FROM tokens WHERE id = ?", (str(token_id),)
        ).rowcount
        connection.commit()

    if not deleted:
        raise HTTPException(status_code=404, detail="Token not found")
