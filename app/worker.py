"""Odoo Sandbox worker. Shares DATA_DIR with app/main.py.

Requires Docker Compose v2 and Python 3.10+ on macOS/Linux.
Uses only the Python standard library. Labs are served through the shared nginx
proxy (proxy/default.conf.template) at <job id hex>.<domain>; see README.md.
"""

import ast
import fcntl
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import closing
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from uuid import UUID

DATA = Path(os.getenv("DATA_DIR", "data")).resolve()
JOBS = DATA / "jobs"
DB = DATA / "lab.sqlite3"
IMAGES = {v: os.getenv(f"ODOO_IMAGE_{v[:2]}", f"ghcr.io/imotif/odoo-ee:{v}") for v in ("18.0", "19.0", "20.0")}
PROXY = "odoo-sandbox-proxy"  # Container and network name from docker-compose.yml.
PROXY_URL = os.getenv("LAB_PROXY_URL", "http://127.0.0.1:8080")
URL_TEMPLATE = os.getenv("LAB_URL_TEMPLATE", "http://{id}.localhost:8080")
TTL = int(os.getenv("LAB_TTL_SECONDS", "7200"))
LOG = logging.getLogger("lab-worker")
BUSY = ("validating", "provisioning", "installing", "starting")


def connect():
    db = sqlite3.connect(DB, timeout=30)
    db.row_factory = sqlite3.Row
    return db


def update(job_id, status, **fields):
    fields["status"] = status
    with closing(connect()) as db:
        db.execute(
            "UPDATE jobs SET " + ", ".join(f"{k}=?" for k in fields) + " WHERE id=?",
            (*fields.values(), job_id),
        )
        db.commit()
    LOG.info("%s: %s", job_id, status)


def claim():
    with closing(connect()) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if row:
            db.execute("UPDATE jobs SET status='validating' WHERE id=?", (row["id"],))
        db.commit()
        return dict(row) if row else None


def directory(job_id):
    return JOBS / str(UUID(job_id))


def lab_url(job_id):
    return URL_TEMPLATE.format(id=UUID(job_id).hex)


def docker(*args, check=True):
    result = subprocess.run(
        ["docker", *args], text=True, capture_output=True, timeout=120
    )
    if check and result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result


def registry_login():
    # Private images (e.g. ghcr.io/imotif/odoo-ee) need credentials inside this
    # container; the host's docker login is not visible here.
    user, token = os.getenv("REGISTRY_USER"), os.getenv("REGISTRY_TOKEN")
    if not (user and token):
        return
    registry = os.getenv("REGISTRY", "ghcr.io")
    result = subprocess.run(
        ["docker", "login", registry, "-u", user, "--password-stdin"],
        input=token, text=True, capture_output=True, timeout=60,
    )  # fmt: skip
    if result.returncode:
        raise SystemExit(f"docker login {registry} failed: {result.stderr.strip()}")
    LOG.info("Logged in to %s as %s", registry, user)


def reattach_proxy():
    # A recreated proxy container has lost its links to labs that are still alive.
    with closing(connect()) as db:
        rows = db.execute("SELECT id FROM jobs WHERE status IN ('ready', 'stopped')")
        for row in rows.fetchall():
            attach(row["id"])


def network(job_id):
    return "lab_" + UUID(job_id).hex + "_default"


def attach(job_id):
    result = docker("network", "connect", network(job_id), PROXY, check=False)
    if result.returncode and "already exists" not in result.stderr:
        raise RuntimeError("Proxy attach failed: " + result.stderr.strip())


def compose(job_id, *args, timeout=120, capture=False):
    folder = directory(job_id)
    command = [
        "docker",
        "compose",
        "-p",
        "lab_" + UUID(job_id).hex,
        "-f",
        str(folder / "compose.json"),
        *args,
    ]
    if capture:
        result = subprocess.run(
            command, check=True, text=True, capture_output=True, timeout=timeout
        )
        return result.stdout.strip()
    log = folder / "worker.log"
    with log.open("a") as output:
        output.write("\n$ docker compose " + " ".join(args) + "\n")
        output.flush()
        code = subprocess.run(
            command, stdout=output, stderr=subprocess.STDOUT, timeout=timeout
        ).returncode
    if code:
        # Surface docker's own last words instead of a bare exit status.
        tail = [line for line in log.read_text().splitlines() if line.strip()][-1]
        raise RuntimeError(f"docker compose {args[0]} failed: {tail.strip()}")
    return ""


def extract_addons(archive, target, serie):
    if target.exists():
        raise ValueError("Extraction directory already exists")
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > 5000:
            raise ValueError("ZIP has too many entries")
        if sum(i.file_size for i in entries) > 200 * 1024 * 1024:
            raise ValueError("Uncompressed ZIP exceeds 200 MB")
        selected = []
        seen = set()
        for info in entries:
            path = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in info.filename
                or ":" in info.filename
                or "\x00" in info.filename
            ):
                raise ValueError("Unsafe ZIP path")
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("ZIP contains a symlink or special file")
            if info.flag_bits & 1:
                raise ValueError("Encrypted ZIP is unsupported")
            if info.file_size > 20 * 1024 * 1024:
                raise ValueError("ZIP entry exceeds 20 MB")
            if info.file_size > max(info.compress_size, 1) * 1000:
                raise ValueError("Suspicious ZIP compression ratio")
            if "__MACOSX" in path.parts or path.name == ".DS_Store":
                continue
            key = str(path).casefold()
            if key in seen:
                raise ValueError("Duplicate ZIP path")
            seen.add(key)
            selected.append((info, path))
        target.mkdir(parents=True)
        target.chmod(0o755)
        for info, path in selected:
            dest = target.joinpath(*path.parts)
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                dest.chmod(0o755)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as source, dest.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            dest.chmod(0o644)
    manifests = list(target.rglob("__manifest__.py"))
    if not manifests:
        raise ValueError("No Odoo __manifest__.py found")
    roots, modules = set(), set()
    for manifest in manifests:
        module = manifest.parent
        if module == target or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", module.name):
            raise ValueError("ZIP must contain named addon folders")
        if module.name in modules:
            raise ValueError("Duplicate addon name")
        if not (module / "__init__.py").is_file():
            raise ValueError(f"{module.name}: missing __init__.py")
        try:
            version = str(ast.literal_eval(manifest.read_text("utf-8")).get("version", ""))
        except (ValueError, SyntaxError, AttributeError) as error:
            raise ValueError(f"{module.name}: unreadable __manifest__.py") from error
        if version.count(".") >= 4 and not version.startswith(serie + "."):
            raise ValueError(
                f"{module.name} is version {version}; it cannot install on Odoo {serie}"
            )
        modules.add(module.name)
        roots.add(module.parent.relative_to(target).as_posix())
    return sorted(modules), sorted(roots)


def prepare(job, modules, roots):
    folder = directory(job["id"])
    password = secrets.token_hex(24)
    config = folder / "odoo.conf"
    config.write_text(
        "[options]\n"
        f"admin_passwd = {secrets.token_hex(24)}\n"
        "db_host = db\ndb_port = 5432\ndb_user = odoo\n"
        f"db_password = {password}\n"
        "db_name = lab\ndbfilter = ^lab$\nlist_db = False\nproxy_mode = True\nhttp_interface = 0.0.0.0\n"
        "data_dir = /var/lib/odoo\n"
        "addons_path = /usr/lib/python3/dist-packages/odoo/addons,/mnt/enterprise,"
        + ",".join("/mnt/extra-addons" + ("" if r == "." else "/" + r) for r in roots)
        + "\nworkers = 0\nmax_cron_threads = 0\n",
        encoding="utf-8",
    )
    config.chmod(0o644)  # Must be readable by the image's non-root Odoo user.
    spec = {
        "services": {
            "db": {
                "image": "postgres:16",
                "environment": {
                    "POSTGRES_USER": "odoo",
                    "POSTGRES_PASSWORD": password,
                    "POSTGRES_DB": "postgres",
                },
                "volumes": ["db-data:/var/lib/postgresql/data"],
                "cpus": 0.5,
                "mem_limit": "512m",
                "pids_limit": 128,
                "healthcheck": {
                    "test": ["CMD-SHELL", "pg_isready -U odoo -d postgres"],
                    "interval": "2s",
                    "timeout": "5s",
                    "retries": 30,
                },
            },
            "odoo": {
                "image": IMAGES[job["odoo_version"]],
                "environment": {"HOST": "db", "USER": "odoo", "PASSWORD": password},
                "depends_on": {"db": {"condition": "service_healthy"}},
                "volumes": [
                    str(folder / "addons") + ":/mnt/extra-addons:ro",
                    "/path/to/enterprise:/mnt/enterprise:ro",
                    str(config) + ":/etc/odoo/odoo.conf:ro",
                    "odoo-data:/var/lib/odoo",
                ],
                # No published port: the shared proxy joins this network instead.
                "networks": {"default": {"aliases": ["lab-" + UUID(job["id"]).hex]}},
                "cpus": 1.0,
                "mem_limit": "1536m",
                "pids_limit": 256,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "command": ["odoo", "-c", "/etc/odoo/odoo.conf", "-d", "lab"],
            },
        },
        "networks": {"default": {"internal": True}},
        "volumes": {"db-data": {}, "odoo-data": {}},
    }
    path = folder / "compose.json"
    path.write_text(json.dumps(spec, indent=2), encoding="utf-8")
    path.chmod(0o600)


def wait_ready(job_id, timeout=180):
    # Ask the proxy directly so a public domain need not resolve on this host.
    request = urllib.request.Request(
        PROXY_URL + "/web/login?db=lab",
        headers={"Host": urlsplit(lab_url(job_id)).netloc},
    )
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        try:
            with opener.open(request, timeout=5) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(2)
    raise TimeoutError("Odoo HTTP readiness timed out")


def destroy(job_id):
    if (directory(job_id) / "compose.json").exists():
        docker("network", "disconnect", "-f", network(job_id), PROXY, check=False)
        compose(job_id, "down", "--volumes", "--remove-orphans", timeout=120)


def remove(job_id):
    destroy(job_id)
    shutil.rmtree(directory(job_id), ignore_errors=True)
    update(job_id, "deleted")


def start(job_id):
    compose(job_id, "up", "-d", "--wait", "--wait-timeout", "90", "db", timeout=120)
    compose(job_id, "up", "-d", "odoo")
    attach(job_id)
    wait_ready(job_id)
    update(job_id, "ready", url=lab_url(job_id), error=None)


def fail(job_id, error):
    message = str(error)
    try:
        if (directory(job_id) / "compose.json").exists():
            compose(job_id, "logs", "--no-color", "--tail", "150", timeout=30)
        destroy(job_id)
    except Exception as cleanup_error:
        message += f"; cleanup failed: {cleanup_error}"
    update(job_id, "failed", url=None, error=message[:2000])


def run_job(job):
    job_id = job["id"]
    try:
        if job["odoo_version"] not in IMAGES:
            raise ValueError("Unsupported image version; set ODOO_IMAGE_20 for 20.0")
        folder = directory(job_id)
        archive = folder / "addon.zip"
        modules, roots = extract_addons(archive, folder / "addons", job["odoo_version"])
        update(job_id, "provisioning")
        prepare(job, modules, roots)
        compose(job_id, "pull", "--policy", "missing", timeout=900)
        compose(job_id, "up", "-d", "--wait", "--wait-timeout", "90", "db", timeout=120)
        update(job_id, "installing")
        compose(
            job_id,
            "run",
            "--rm",
            "--no-deps",
            "--name",
            "lab_init_" + UUID(job_id).hex,
            "odoo",
            "odoo",
            "-c",
            "/etc/odoo/odoo.conf",
            "-d",
            "lab",
            "-i",
            ",".join(modules),
            "--without-demo=all",
            "--stop-after-init",
            timeout=600,
        )
        names = ",".join("'" + m + "'" for m in modules)  # Names validated above.
        installed = compose(
            job_id,
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "odoo",
            "-d",
            "lab",
            "-At",
            "-c",
            f"SELECT count(*) FROM ir_module_module WHERE name IN ({names}) AND state='installed'",
            capture=True,
        )
        if int(installed) != len(modules):
            raise RuntimeError("Some addons were not installed; see worker.log")
        update(job_id, "starting")
        (folder / "runtime.json").write_text(
            json.dumps({"expires_at": time.time() + TTL})
        )
        start(job_id)
        LOG.info("Open %s (login: admin / admin)", lab_url(job_id))
    except Exception as error:
        LOG.exception("Job %s failed", job_id)
        fail(job_id, error)


def cleanup_expired():
    with closing(connect()) as db:
        rows = db.execute(
            "SELECT id FROM jobs WHERE status IN ('ready', 'stopped')"
        ).fetchall()
    for row in rows:
        meta = directory(row["id"]) / "runtime.json"
        if meta.exists() and json.loads(meta.read_text())["expires_at"] <= time.time():
            try:
                remove(row["id"])
            except Exception:
                LOG.exception("TTL cleanup failed: %s", row["id"])


def handle_requests():
    # ponytail: actions wait behind an install in progress (single worker loop).
    with closing(connect()) as db:
        rows = db.execute(
            "SELECT id, status FROM jobs WHERE status IN "
            "('stop_requested', 'start_requested', 'delete_requested')"
        ).fetchall()
    for row in rows:
        job_id, action = row["id"], row["status"].removesuffix("_requested")
        try:
            if action == "delete":
                remove(job_id)
            elif action == "stop":
                compose(job_id, "stop")
                update(job_id, "stopped")
            elif action == "start":
                start(job_id)
        except Exception as error:
            LOG.exception("%s %s failed", action, job_id)
            fail(job_id, f"{action} failed: {error}")


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    if not DB.exists():
        raise SystemExit(f"{DB} not found; start the API first (it creates the database)")
    subprocess.run(["docker", "compose", "version"], check=True)
    with (DATA / "worker.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another worker is running")
        registry_login()
        reattach_proxy()
        # A crashed install is ambiguous: clean it up instead of replaying hooks.
        with closing(connect()) as db:
            marks = ",".join("?" for _ in BUSY)
            interrupted = db.execute(
                f"SELECT id FROM jobs WHERE status IN ({marks})", BUSY
            ).fetchall()
        for row in interrupted:
            fail(row["id"], "Worker interrupted; upload again to retry")
        LOG.info("Worker ready; TTL=%ss; data=%s", TTL, DATA)
        while True:
            handle_requests()
            cleanup_expired()
            job = claim()
            if job:
                run_job(job)
            else:
                time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nWorker stopped. Interrupted jobs will be cleaned on next startup.")
