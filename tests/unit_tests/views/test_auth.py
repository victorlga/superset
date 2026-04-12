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
from unittest.mock import patch

from superset.views.auth import _is_self_registration_enabled


def test_is_self_registration_enabled_true(app_context: None) -> None:
    """Returns True when AUTH_USER_SELF_REGISTRATION is True."""
    from flask import current_app

    current_app.config["AUTH_USER_SELF_REGISTRATION"] = True
    assert _is_self_registration_enabled() is True


def test_is_self_registration_enabled_false(app_context: None) -> None:
    """Returns False when AUTH_USER_SELF_REGISTRATION is False."""
    from flask import current_app

    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False
    assert _is_self_registration_enabled() is False


def test_is_self_registration_enabled_defaults_false(app_context: None) -> None:
    """Returns False when AUTH_USER_SELF_REGISTRATION is not set."""
    from flask import current_app

    current_app.config.pop("AUTH_USER_SELF_REGISTRATION", None)
    assert _is_self_registration_enabled() is False


def test_register_route_blocked_when_self_registration_disabled(
    app_context: None,
) -> None:
    """The /register/ route returns 403 when self-registration is disabled."""
    from flask import current_app

    current_app.config["AUTH_USER_REGISTRATION"] = True
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False

    with current_app.test_client() as client:
        resp = client.get("/register/")
        assert resp.status_code == 403


def test_register_activation_blocked_when_self_registration_disabled(
    app_context: None,
) -> None:
    """Activation route returns 403 when self-registration is off."""
    from flask import current_app

    current_app.config["AUTH_USER_REGISTRATION"] = True
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False

    with current_app.test_client() as client:
        resp = client.get("/register/activation/some-hash")
        assert resp.status_code == 403


def test_register_route_accessible_when_self_registration_enabled(
    app_context: None,
) -> None:
    """The /register/ route is accessible when self-registration is enabled."""
    from flask import current_app

    current_app.config["AUTH_USER_REGISTRATION"] = True
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = True

    with current_app.test_client() as client:
        with patch(
            "superset.views.base.BaseSupersetView.render_app_template",
            return_value="OK",
        ):
            resp = client.get("/register/")
            assert resp.status_code == 200
