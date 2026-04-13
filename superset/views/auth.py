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

import logging
from typing import Optional

from flask import current_app, g, redirect, session
from flask_appbuilder import expose
from flask_appbuilder.const import LOGMSG_ERR_SEC_NO_REGISTER_HASH
from flask_appbuilder.security.decorators import no_cache
from flask_appbuilder.security.views import AuthView, WerkzeugResponse
from flask_babel import lazy_gettext
from flask_login import logout_user

from superset.views.base import BaseSupersetView

logger = logging.getLogger(__name__)


class SupersetAuthView(BaseSupersetView, AuthView):
    route_base = "/login"

    @expose("/")
    @no_cache
    def login(self, provider: Optional[str] = None) -> WerkzeugResponse:
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)

        return super().render_app_template()

    @expose("/logout/")
    @no_cache
    def logout(self) -> WerkzeugResponse:
        """Override FAB's logout to invalidate the server-side session.

        The default FAB logout only calls ``logout_user()``, which clears
        the user identity from the in-flight session dict but does **not**
        destroy the session itself.  A previously-captured session cookie
        can therefore be replayed to restore an authenticated session.

        ``session.clear()`` wipes all session data so that:
        * Client-side cookies: Flask issues a new (empty) signed cookie,
          making any previously-captured cookie stale.
        * Server-side sessions: the backend store entry is deleted, so the
          old session ID no longer maps to any data.
        """
        # Capture user reference before logout clears it
        user = g.user
        # logout_user() first so flask-login's user_logged_out signal
        # fires with the real user rather than an anonymous user
        logout_user()
        # Destroy remaining session data to prevent cookie replay
        session.clear()
        # Preserve audit logging
        self.appbuilder.sm.on_user_logout(user)
        return redirect(self.appbuilder.get_url_for_index)


class SupersetRegisterUserView(BaseSupersetView):
    route_base = "/register"
    activation_template = ""
    error_message = lazy_gettext(
        "Not possible to register you at the moment, try again later"
    )
    false_error_message = lazy_gettext("Registration not found")

    @expose("/")
    @no_cache
    def register(self) -> WerkzeugResponse:
        if not current_app.config.get("AUTH_USER_SELF_REGISTRATION", False):
            return redirect(self.appbuilder.get_url_for_index)
        return super().render_app_template()

    @expose("/activation/<string:activation_hash>")
    def activation(self, activation_hash: str) -> WerkzeugResponse:
        """
        Endpoint to expose an activation url, this url
        is sent to the user by email, when accessed the user is inserted
        and activated
        """
        reg = self.appbuilder.sm.find_register_user(activation_hash)
        if not reg:
            logger.error(LOGMSG_ERR_SEC_NO_REGISTER_HASH, activation_hash)
            logger.error("Registration activation failed: %s", self.false_error_message)
            return redirect(self.appbuilder.get_url_for_index)
        if not self.appbuilder.sm.add_user(
            username=reg.username,
            email=reg.email,
            first_name=reg.first_name,
            last_name=reg.last_name,
            role=self.appbuilder.sm.find_role(
                self.appbuilder.sm.auth_user_registration_role
            ),
            hashed_password=reg.password,
        ):
            logger.error("User registration failed: %s", self.error_message)
            return redirect(self.appbuilder.get_url_for_index)
        else:
            self.appbuilder.sm.del_register_user(reg)
            return super().render_app_template(
                {
                    "username": reg.username,
                    "first_name": reg.first_name,
                    "last_name": reg.last_name,
                },
            )
