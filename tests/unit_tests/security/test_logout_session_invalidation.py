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
"""Tests verifying that session cookies are invalidated after logout.

These tests exercise both the view-based logout (/logout/) and the
REST API logout (POST /api/v1/security/logout) to confirm that a
previously-captured session cookie cannot be replayed to regain
an authenticated session.
"""

from flask.testing import FlaskClient
from flask_appbuilder.security.sqla.models import User
from pytest_mock import MockerFixture

from superset.app import SupersetApp


def _ensure_admin(app: SupersetApp) -> User:
    """Return the admin user, creating it if necessary."""
    sm = app.appbuilder.sm
    admin_role = sm.find_role("Admin")
    user = sm.find_user(username="admin")
    if user is None:
        user = sm.add_user(
            "admin",
            "admin",
            "user",
            "admin@fab.org",
            admin_role,
            password="general",  # noqa: S106
        )
    return user


def _login_user(app: SupersetApp, client: FlaskClient) -> User:
    """Log in the admin user within a request context via flask-login."""
    user = _ensure_admin(app)
    # Use the test client to establish a session with the user logged in
    with client.session_transaction() as sess:
        sess["_user_id"] = user.id
        sess["_fresh"] = True
    return user


# --- View-based logout tests (/logout/) ---


def test_view_logout_invalidates_session(
    app: SupersetApp,
    client: FlaskClient,
) -> None:
    """After calling the view logout, the old session cookie is rejected."""
    _login_user(app, client)

    with client.session_transaction() as sess:
        assert "_user_id" in sess

    client.get("/logout/", follow_redirects=True)

    with client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_view_logout_calls_on_user_logout(
    app: SupersetApp,
    client: FlaskClient,
    mocker: MockerFixture,
) -> None:
    """The view logout triggers the security manager's audit callback."""
    _login_user(app, client)

    mock_on_logout = mocker.patch.object(
        app.appbuilder.sm,
        "on_user_logout",
    )

    client.get("/logout/", follow_redirects=True)

    mock_on_logout.assert_called_once()


def test_view_logout_returns_redirect(
    app: SupersetApp,
    client: FlaskClient,
) -> None:
    """The view logout redirects to the index page."""
    _login_user(app, client)

    resp = client.get("/logout/")
    assert resp.status_code == 302


# --- API logout tests (POST /api/v1/security/logout) ---
# The API endpoint uses @protect(), so full_api_access is needed to
# bypass FAB's JWT / permission checks in the unit-test environment.


def test_api_logout_invalidates_session(
    app: SupersetApp,
    client: FlaskClient,
    full_api_access: None,
) -> None:
    """After calling POST /api/v1/security/logout, the session is invalid."""
    _login_user(app, client)

    with client.session_transaction() as sess:
        assert "_user_id" in sess

    resp = client.post("/api/v1/security/logout/")
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_api_logout_calls_on_user_logout(
    app: SupersetApp,
    client: FlaskClient,
    full_api_access: None,
    mocker: MockerFixture,
) -> None:
    """The API logout triggers the security manager's audit callback."""
    _login_user(app, client)

    mock_on_logout = mocker.patch.object(
        app.appbuilder.sm,
        "on_user_logout",
    )

    client.post("/api/v1/security/logout/")

    mock_on_logout.assert_called_once()


def test_api_logout_returns_200(
    app: SupersetApp,
    client: FlaskClient,
    full_api_access: None,
) -> None:
    """The API logout returns a 200 JSON response."""
    _login_user(app, client)

    resp = client.post("/api/v1/security/logout/")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["message"] == "OK"
