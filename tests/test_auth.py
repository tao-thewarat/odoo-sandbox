"""Run: DATA_DIR=$(mktemp -d) python -m unittest tests.test_auth (needs httpx)."""

import os
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

os.environ["DATA_DIR"] = tempfile.mkdtemp()
os.environ.update(OIDC_TENANT_ID="tenant", OIDC_CLIENT_ID="client", OIDC_CLIENT_SECRET="secret")

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

ORIGIN = {"Origin": "http://testserver"}


def sign_in(client, nonce=None, **claims):
    login = client.get("/auth/login", follow_redirects=False)
    query = parse_qs(urlsplit(login.headers["location"]).query)
    token = {
        "aud": "client",
        "tid": "tenant",
        "iss": "https://login.microsoftonline.com/tenant/v2.0",
        "nonce": nonce or query["nonce"][0],
        "exp": time.time() + 60,
        "preferred_username": "User@imotif.io",
        "name": "User",
        **claims,
    }
    with mock.patch.object(main, "exchange_code", return_value=token):
        return client.get(
            "/auth/callback", params={"code": "c", "state": query["state"][0]}, follow_redirects=False
        )


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def test_requires_sign_in(self):
        self.assertEqual(self.client.get("/api/jobs").status_code, 401)

    def test_user_is_not_admin(self):
        self.assertEqual(sign_in(self.client).headers["location"], "/")
        self.assertEqual(
            self.client.get("/api/me").json(),
            {"user": "user@imotif.io", "display_name": "User", "is_admin": False},
        )
        self.assertEqual(self.client.get("/api/stats").status_code, 403)

    def test_admin_role_sees_stats(self):
        sign_in(self.client, roles=["admin"])
        self.assertEqual(self.client.get("/api/stats").status_code, 200)

    def test_rejects_wrong_nonce_and_tenant(self):
        self.assertIn("login_error", sign_in(self.client, nonce="bad").headers["location"])
        self.assertIn("login_error", sign_in(self.client, tid="other").headers["location"])
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_rejects_state_mismatch(self):
        self.client.get("/auth/login", follow_redirects=False)
        response = self.client.get(
            "/auth/callback", params={"code": "c", "state": "bad"}, follow_redirects=False
        )
        self.assertIn("login_error", response.headers["location"])

    def test_sandbox_subdomain_cannot_write_with_cookie(self):
        sign_in(self.client)
        evil = {"Origin": "http://abc123.testserver"}
        self.assertEqual(self.client.post("/auth/logout", headers=evil).status_code, 403)
        self.assertEqual(self.client.post("/auth/logout").status_code, 403)

    def test_logout_ends_session(self):
        sign_in(self.client)
        self.assertEqual(self.client.post("/auth/logout", headers=ORIGIN).status_code, 204)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_tokens_are_http_only_cookies(self):
        cookies = sign_in(self.client).headers.get_list("set-cookie")
        access = next(c for c in cookies if c.startswith("sandbox_access="))
        refresh = next(c for c in cookies if c.startswith("sandbox_refresh="))
        self.assertIn("HttpOnly", access)
        self.assertIn("HttpOnly", refresh)
        self.assertIn("Path=/auth", refresh)

    def test_refresh_restores_expired_access_token(self):
        with mock.patch.object(main, "ACCESS_TOKEN_TTL", -1):
            sign_in(self.client)
        self.client.cookies.delete("sandbox_access")
        self.assertEqual(self.client.get("/api/me").status_code, 401)
        self.assertEqual(self.client.post("/auth/refresh", headers=ORIGIN).status_code, 204)
        self.assertEqual(self.client.get("/api/me").status_code, 200)

    def test_refresh_token_works_only_once(self):
        sign_in(self.client)
        old = self.client.cookies.get("sandbox_refresh", path="/auth")
        self.assertEqual(self.client.post("/auth/refresh", headers=ORIGIN).status_code, 204)
        replay = TestClient(main.app)
        replay.cookies.set("sandbox_refresh", old, path="/auth")
        self.assertEqual(replay.post("/auth/refresh", headers=ORIGIN).status_code, 401)

    def test_refresh_rejects_other_origin(self):
        sign_in(self.client)
        evil = {"Origin": "http://abc123.testserver"}
        self.assertEqual(self.client.post("/auth/refresh", headers=evil).status_code, 403)

    def test_logout_revokes_refresh_token(self):
        sign_in(self.client)
        old = self.client.cookies.get("sandbox_refresh", path="/auth")
        self.client.post("/auth/logout", headers=ORIGIN)
        replay = TestClient(main.app)
        replay.cookies.set("sandbox_refresh", old, path="/auth")
        self.assertEqual(replay.post("/auth/refresh", headers=ORIGIN).status_code, 401)

    def test_refresh_slides_expiry_up_to_max(self):
        sign_in(self.client)
        with main.connect() as connection:
            connection.execute("UPDATE auth_tokens SET refresh_expires_at = ?", (int(time.time()) + 60,))
        response = self.client.post("/auth/refresh", headers=ORIGIN)
        self.assertEqual(response.status_code, 204)
        with main.connect() as connection:
            expires_at = connection.execute("SELECT max(refresh_expires_at) FROM auth_tokens").fetchone()[0]
        self.assertLessEqual(expires_at, time.time() + 30 * 24 * 3600)
        self.assertGreater(expires_at, time.time() + 30 * 24 * 3600 - 60)

    def test_everyone_sees_jobs_but_only_owner_or_admin_changes_them(self):
        owner, other, admin = self.client, TestClient(main.app), TestClient(main.app)
        sign_in(owner, preferred_username="owner@imotif.io")
        sign_in(other, preferred_username="other@imotif.io")
        sign_in(admin, preferred_username="boss@imotif.io", roles=["admin"])
        with open("examples/ibase_billing_note.zip", "rb") as addon:
            job = owner.post(
                "/api/jobs",
                headers=ORIGIN,
                data={"odoo_version": "19.0"},
                files={"addon_zip": ("shared.zip", addon)},
            ).json()
        self.assertIn(job["id"], [row["id"] for row in other.get("/api/jobs").json()])
        self.assertEqual(other.get(f"/api/jobs/{job['id']}").status_code, 200)
        self.assertEqual(other.post(f"/api/jobs/{job['id']}/delete", headers=ORIGIN).status_code, 403)
        self.assertEqual(set(admin.get("/api/stats").json()), {"environments"})
        self.assertEqual(admin.post(f"/api/jobs/{job['id']}/delete", headers=ORIGIN).status_code, 202)

    def test_create_job_keeps_edition_and_name(self):
        sign_in(self.client)
        with open("examples/ibase_billing_note.zip", "rb") as addon:
            job = self.client.post(
                "/api/jobs",
                headers=ORIGIN,
                data={"odoo_version": "19.0", "edition": "community"},
                files={"addon_zip": ("my_addon.zip", addon)},
            )
        self.assertEqual(job.status_code, 202)
        self.assertEqual(job.json()["edition"], "community")
        self.assertEqual(job.json()["name"], "my_addon")
        self.assertEqual(job.json()["owner"], "user@imotif.io")


if __name__ == "__main__":
    unittest.main()
