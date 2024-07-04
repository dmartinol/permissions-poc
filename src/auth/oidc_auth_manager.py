from auth.config import setup_permissions
from security.enforcer import PolicyEnforcer
from security.security_manager import (
    SecurityManager,
    _set_security_manager,
    _get_security_manager,
)
from security.role_manager import RoleManager
from fastapi import HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from auth.auth_manager import AuthManager
from jwt import PyJWKClient
import jwt
from typing import Any, Optional
from dotenv import load_dotenv
import os

OIDC_SERVER_URL: str = ""
REALM: str = ""
CLIENT_ID: str = ""

oauth_2_scheme = OAuth2AuthorizationCodeBearer(
    tokenUrl=f"{OIDC_SERVER_URL}/realms/{REALM}/protocol/openid-connect/token",
    authorizationUrl=f"{OIDC_SERVER_URL}/realms/{REALM}/protocol/openid-connect/auth",
    refreshUrl=f"{OIDC_SERVER_URL}/realms/{REALM}/protocol/openid-connect/token",
)


class OidcAuthManager(AuthManager):
    """
    An `AuthManager` implementation to use Keycload OIDC to retrieve user details.
    Uses the local `.env` file to load the OIDC server settings:
    - `OIDC_SERVER_URL`
    - `REALM`
    - `CLIENT_ID`
    """

    def init(self):
        sm = SecurityManager(
            role_manager=RoleManager(),
            policy_enforcer=PolicyEnforcer(),
            permissions=setup_permissions(),
        )
        _set_security_manager(sm)

        load_dotenv("../.env")
        global OIDC_SERVER_URL, REALM, CLIENT_ID
        OIDC_SERVER_URL = os.getenv("OIDC_SERVER_URL")
        REALM = os.getenv("REALM")
        CLIENT_ID = os.getenv("CLIENT_ID")

    async def inject_user_data(self, request: Request) -> Any:
        """
        Fetches an access token for the configured client, then decodes it to extract the
        user credential and roles.
        """

        access_token = await oauth_2_scheme(request=request)
        current_user, roles = self.user_details_from_access_token(access_token)
        sm = _get_security_manager()
        sm.set_current_user(current_user)
        sm.role_manager.clear()
        sm.role_manager.add_roles_for_user(current_user, roles)

    def user_details_from_access_token(
        self, access_token: Optional[str]
    ) -> (str, list[str]):
        global OIDC_SERVER_URL
        global REALM
        global CLIENT_ID
        url = f"{OIDC_SERVER_URL}/realms/{REALM}/protocol/openid-connect/certs"
        optional_custom_headers = {"User-agent": "custom-user-agent"}
        jwks_client = PyJWKClient(url, headers=optional_custom_headers)

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(access_token)
            data = jwt.decode(
                access_token,
                signing_key.key,
                algorithms=["RS256"],
                audience="account",
                options={"verify_exp": True},
            )

            current_user = data["preferred_username"]
            roles = data["resource_access"][f"{CLIENT_ID}"]["roles"]
            print(f"Running for user {current_user} with roles {roles}")
            return (current_user, roles)
        except jwt.exceptions.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Not authenticated")
