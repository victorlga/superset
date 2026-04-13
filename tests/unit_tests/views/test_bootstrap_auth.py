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
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import g
from flask_appbuilder.const import (
    AUTH_DB,
    AUTH_LDAP,
    AUTH_OAUTH,
    AUTH_SAML,
)

from superset.views.base import cached_common_bootstrap_data


@pytest.fixture(autouse=True)
def mock_user() -> None:
    g.user = MagicMock()


def _get_bootstrap(user_id: int = 1) -> dict[str, Any]:
    with patch("superset.views.base.menu_data", return_value={}):
        return cached_common_bootstrap_data(user_id=user_id, locale=None)


def test_bootstrap_saml_providers(app_context: None) -> None:
    """SAML providers are included in bootstrap data."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = AUTH_SAML
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False
    current_app.config["SAML_PROVIDERS"] = [
        {"name": "okta", "icon": "fa-okta"},
        {"name": "entra_id", "icon": "fa-microsoft"},
    ]

    payload = _get_bootstrap()

    assert payload["conf"]["AUTH_TYPE"] == AUTH_SAML
    providers = payload["conf"]["AUTH_PROVIDERS"]
    assert len(providers) == 2
    assert providers[0] == {"name": "okta", "icon": "fa-okta"}
    assert providers[1] == {"name": "entra_id", "icon": "fa-microsoft"}


def test_bootstrap_saml_provider_default_icon(app_context: None) -> None:
    """SAML providers without an icon get a default icon."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = AUTH_SAML
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False
    current_app.config["SAML_PROVIDERS"] = [
        {"name": "onelogin"},
    ]

    payload = _get_bootstrap()

    providers = payload["conf"]["AUTH_PROVIDERS"]
    assert providers[0] == {"name": "onelogin", "icon": "fa-sign-in"}


def test_bootstrap_oauth_providers(app_context: None) -> None:
    """OAuth providers are included in bootstrap data."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = AUTH_OAUTH
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False
    current_app.config["OAUTH_PROVIDERS"] = [
        {"name": "github", "icon": "fa-github"},
    ]

    payload = _get_bootstrap()

    assert payload["conf"]["AUTH_TYPE"] == AUTH_OAUTH
    providers = payload["conf"]["AUTH_PROVIDERS"]
    assert len(providers) == 1
    assert providers[0] == {"name": "github", "icon": "fa-github"}


@pytest.mark.parametrize(
    "auth_type",
    [AUTH_OAUTH, AUTH_SAML],
)
def test_recaptcha_not_shown_for_federated_auth(
    app_context: None,
    auth_type: int,
) -> None:
    """Recaptcha should not be shown for OAuth or SAML auth types."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = auth_type
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = True
    current_app.config["AUTH_USER_REGISTRATION_ROLE"] = "Public"
    current_app.config.pop("RECAPTCHA_PUBLIC_KEY", None)

    payload = _get_bootstrap()

    assert "RECAPTCHA_PUBLIC_KEY" not in payload["conf"]


@pytest.mark.parametrize(
    "auth_type",
    [AUTH_DB, AUTH_LDAP],
)
def test_recaptcha_shown_for_non_federated_auth(
    app_context: None,
    auth_type: int,
) -> None:
    """Recaptcha should be shown for DB and LDAP auth types when registration is on."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = auth_type
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = True
    current_app.config["AUTH_USER_REGISTRATION_ROLE"] = "Public"
    current_app.config["RECAPTCHA_PUBLIC_KEY"] = "test-key"

    payload = _get_bootstrap()

    assert payload["conf"]["RECAPTCHA_PUBLIC_KEY"] == "test-key"


def test_self_registration_disabled_by_default_with_auth_registration_on(
    app_context: None,
) -> None:
    """When AUTH_USER_REGISTRATION=True but AUTH_USER_SELF_REGISTRATION is not set,
    bootstrap data should NOT expose registration to the frontend."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = AUTH_DB
    current_app.config["AUTH_USER_REGISTRATION"] = True
    current_app.config.pop("AUTH_USER_SELF_REGISTRATION", None)

    payload = _get_bootstrap()

    assert payload["conf"]["AUTH_USER_REGISTRATION"] is False
    assert "AUTH_USER_REGISTRATION_ROLE" not in payload["conf"]


def test_self_registration_enabled_exposes_registration(
    app_context: None,
) -> None:
    """When AUTH_USER_SELF_REGISTRATION=True, bootstrap data should expose
    registration to the frontend."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = AUTH_DB
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = True
    current_app.config["AUTH_USER_REGISTRATION_ROLE"] = "Public"

    payload = _get_bootstrap()

    assert payload["conf"]["AUTH_USER_REGISTRATION"] is True
    assert payload["conf"]["AUTH_USER_REGISTRATION_ROLE"] == "Public"


def test_self_registration_false_hides_registration(
    app_context: None,
) -> None:
    """When AUTH_USER_SELF_REGISTRATION=False, bootstrap data should NOT expose
    registration to the frontend, even with AUTH_USER_REGISTRATION=True."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = AUTH_DB
    current_app.config["AUTH_USER_REGISTRATION"] = True
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False

    payload = _get_bootstrap()

    assert payload["conf"]["AUTH_USER_REGISTRATION"] is False
    assert "AUTH_USER_REGISTRATION_ROLE" not in payload["conf"]


@pytest.mark.parametrize(
    "auth_type",
    [AUTH_OAUTH, AUTH_SAML],
)
def test_federated_auth_with_self_registration_off(
    app_context: None,
    auth_type: int,
) -> None:
    """Federated auth (OAuth/SAML) with AUTH_USER_REGISTRATION=True but
    AUTH_USER_SELF_REGISTRATION=False should not expose registration UI."""
    from flask import current_app

    current_app.config["AUTH_TYPE"] = auth_type
    current_app.config["AUTH_USER_REGISTRATION"] = True
    current_app.config["AUTH_USER_SELF_REGISTRATION"] = False

    payload = _get_bootstrap()

    assert payload["conf"]["AUTH_USER_REGISTRATION"] is False
    assert "RECAPTCHA_PUBLIC_KEY" not in payload["conf"]
