import hashlib
import os
import re
import secrets
import shutil
import sqlite3
import zipfile
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import Body, Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

DATA_DIR = Path(os.getenv("DATA_DIR", "data")).resolve()
JOBS_DIR = DATA_DIR / "jobs"
DATABASE = DATA_DIR / "lab.sqlite3"

MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MB
MAX_ACTIVE_PER_USER = int(os.getenv("MAX_ACTIVE_PER_USER", "2"))
MAX_ACTIVE_TOTAL = int(os.getenv("MAX_ACTIVE_TOTAL", "6"))
INACTIVE = ("failed", "deleted")
OdooVersion = Literal["18.0", "19.0", "20.0"]

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
                owner TEXT
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
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(jobs)")}
        if "owner" not in columns:
            connection.execute("ALTER TABLE jobs ADD COLUMN owner TEXT")
        connection.commit()

    yield


app = FastAPI(title="IMOTIF Odoo Sandbox", lifespan=lifespan)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(x_api_key: Annotated[str, Header()] = "") -> str:
    if x_api_key:
        for key, user in API_KEYS.items():
            if secrets.compare_digest(key.encode(), x_api_key.encode()):
                return user
        with closing(connect()) as connection:
            token = connection.execute(
                "SELECT name FROM tokens WHERE token_hash = ?", (hash_token(x_api_key),)
            ).fetchone()
        if token:
            return token["name"]
        raise HTTPException(status_code=401, detail="Invalid API key")
    # No key: trust the caller only when no env keys are configured. In production
    # the proxy's basic auth guards key-less requests (the manager page).
    if not API_KEYS:
        return "admin"
    raise HTTPException(status_code=401, detail="Missing X-API-Key")


User = Annotated[str, Depends(current_user)]


class JobResponse(BaseModel):
    id: str
    odoo_version: OdooVersion
    status: str
    url: str | None = None
    error: str | None = None
    created_at: str
    owner: str | None = None


@app.get("/", include_in_schema=False)
def manager():
    return FileResponse(Path(__file__).with_name("manager.html"))


@app.get("/api/me")
def me(user: User):
    return {"user": user}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/jobs", response_model=JobResponse, status_code=202)
def create_job(
    user: User,
    odoo_version: Annotated[OdooVersion, Form()],
    addon_zip: Annotated[UploadFile, File()],
):
    marks = ",".join("?" for _ in INACTIVE)
    with closing(connect()) as connection:
        # ponytail: check-then-insert can race; fine for a handful of FCs.
        total, mine = connection.execute(
            f"""
            SELECT count(*), coalesce(sum(owner = ?), 0)
            FROM jobs WHERE status NOT IN ({marks})
            """,
            (user, *INACTIVE),
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
        size = 0
        with zip_path.open("wb") as destination:
            while chunk := addon_zip.file.read(1024 * 1024):
                size += len(chunk)

                if size > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="ZIP must be smaller than 20 MB",
                    )

                destination.write(chunk)

        if not zipfile.is_zipfile(zip_path):
            raise HTTPException(
                status_code=400,
                detail="Invalid ZIP file",
            )

        created_at = datetime.now(timezone.utc).isoformat()

        with closing(connect()) as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    id, odoo_version, status, zip_path, created_at, owner
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    odoo_version,
                    "queued",
                    str(zip_path),
                    created_at,
                    user,
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
        status="queued",
        created_at=created_at,
        owner=user,
    )


@app.get("/api/jobs", response_model=list[JobResponse])
def list_jobs(user: User):
    with closing(connect()) as connection:
        rows = connection.execute(
            """
            SELECT id, odoo_version, status, url, error, created_at, owner
            FROM jobs
            WHERE status != 'deleted' AND (owner = ? OR ? = 'admin')
            ORDER BY created_at DESC
            LIMIT 100
            """,
            (user, user),
        ).fetchall()
    return [dict(row) for row in rows]


def load_job(connection, job_id: UUID, user: str):
    job = connection.execute(
        """
        SELECT id, odoo_version, status, url, error, created_at, owner
        FROM jobs
        WHERE id = ?
        """,
        (str(job_id),),
    ).fetchone()

    if job is None or (job["owner"] != user and user != "admin"):
        raise HTTPException(status_code=404, detail="Job not found")

    return dict(job)


@app.get("/api/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: UUID, user: User):
    with closing(connect()) as connection:
        return load_job(connection, job_id, user)


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
        job = load_job(connection, job_id, user)
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
    if user != "admin":
        raise HTTPException(status_code=403, detail="Only admin can manage tokens")


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
