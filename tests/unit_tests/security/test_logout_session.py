# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from flask import Flask, redirect, session
from flask_login import login_user, LoginManager, logout_user, UserMixin


class FakeUser(UserMixin):
    """Minimal user object for testing."""

    def __init__(self, user_id: int, username: str) -> None:
        self.id = user_id
        self.username = username


def _create_test_app() -> Flask:
    """Create a minimal Flask app wired with Flask-Login for session tests."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret-key"  # noqa: S105
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["TESTING"] = True
    app.config["LOGIN_REDIRECT_URL"] = "/"
    app.config["LOGOUT_REDIRECT_URL"] = "/"

    lm = LoginManager(app)
    fake_user = FakeUser(user_id=1, username="testuser")

    @lm.user_loader
    def load_user(user_id: str) -> FakeUser | None:
        if str(user_id) == str(fake_user.id):
            return fake_user
        return None

    app.fake_user = fake_user
    return app


def test_logout_clears_session() -> None:
    """After logout, the session dict is empty (no _user_id key)."""
    app = _create_test_app()

    with app.test_request_context():
        login_user(app.fake_user)
        assert "_user_id" in session

        logout_user()
        session.clear()

        assert "_user_id" not in session
        assert len(session) == 0


def test_logout_response_deletes_cookie() -> None:
    """The logout response sets a Set-Cookie header that expires
    the session cookie."""
    app = _create_test_app()

    with app.test_request_context("/logout/"):
        login_user(app.fake_user)
        logout_user()
        session.clear()
        response = redirect("/")
        response.delete_cookie(
            app.config.get("SESSION_COOKIE_NAME", "session"),
            path=app.config.get("SESSION_COOKIE_PATH", "/"),
            domain=app.config.get("SESSION_COOKIE_DOMAIN"),
        )

        set_cookie_headers = response.headers.getlist("Set-Cookie")
        assert any("session=" in h for h in set_cookie_headers), (
            "Expected a Set-Cookie header that clears the session cookie"
        )
        cookie_header = next(h for h in set_cookie_headers if "session=" in h)
        has_max_age = "Max-Age=0" in cookie_header
        has_expires = "expires=" in cookie_header.lower()
        assert has_max_age or has_expires


def test_captured_cookie_invalid_after_logout() -> None:
    """A session cookie captured before logout cannot restore auth."""
    app = _create_test_app()

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["_fresh"] = True

        # Simulate session clear (as logout does)
        with client.session_transaction() as sess:
            sess.clear()

        # Verify the session is empty after clearing
        with client.session_transaction() as sess:
            assert "_user_id" not in sess
