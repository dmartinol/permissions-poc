from auth.auth_manager import AuthManager
from auth.keycloak_auth_manager import KeycloakAuthManager
from auth.kubernetes_auth_manager import KubernetesAuthManager
import os
from typing import Any
from fastapi import Request

_auth_manager: AuthManager = None


def _init_auth_manager():
    global _auth_manager
    auth_manager = os.getenv("AUTH_MANAGER", "").lower()
    print(f"Creating AuthManager for {auth_manager}")
    if auth_manager == "keycloak":
        _auth_manager = KeycloakAuthManager()
    elif auth_manager == "k8s":
        _auth_manager = KubernetesAuthManager()
    else:
        _auth_manager = AuthManager()
    _auth_manager.init()


def get_auth_manager_instance() -> AuthManager:
    global _auth_manager
    if _auth_manager is None:
        raise RuntimeError(
            "AuthManager is not initialized. Call '_init_auth_manager()' first."
        )
    return _auth_manager


async def inject_user_data(request: Request) -> Any:
    return await get_auth_manager_instance().inject_user_data(request)


_init_auth_manager()
