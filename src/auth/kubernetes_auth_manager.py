from auth.config import setup_permissions
from security.enforcer import PolicyEnforcer
from security.security_manager import (
    SecurityManager,
    _set_security_manager,
    _get_security_manager,
)
from security.role_manager import _get_role_manager
from auth.auth_manager import AuthManager
from typing import List, Dict, Any
from fastapi import Request
from starlette.authentication import (
    AuthenticationError,
)
import binascii
import jwt
from kubernetes import client, config


class KubernetesAuthManager(AuthManager):
    def __init__(self):
        config.load_incluster_config()
        self.v1 = client.CoreV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()

    def init(self):
        sm = SecurityManager(
            role_manager=_get_role_manager(),
            policy_enforcer=PolicyEnforcer(),
            permissions=setup_permissions(),
        )
        _set_security_manager(sm)

    async def inject_user_data(self, request: Request) -> Any:
        sa_namespace, sa_name = decode_token(request)
        print(f"Received request from {sa_name} in {sa_namespace}")

        roles = self.get_roles(sa_namespace, sa_name)
        print(f"SA roles are: {roles}")

        sm = _get_security_manager()
        current_user = f"{sa_namespace}:{sa_name}"
        sm.set_current_user(current_user)
        sm.role_manager.clear()
        sm.role_manager.add_roles_for_user(current_user, roles)

    def get_roles(
        self, namespace: str, service_account_name: str
    ) -> Dict[str, List[str]]:
        role_bindings = self.rbac_v1.list_namespaced_role_binding(namespace)
        cluster_role_bindings = self.rbac_v1.list_cluster_role_binding()

        roles = []

        for binding in role_bindings.items:
            if binding.subjects is not None:
                for subject in binding.subjects:
                    if (
                        subject.kind == "ServiceAccount"
                        and subject.name == service_account_name
                    ):
                        roles.append(binding.role_ref.name)

        for binding in cluster_role_bindings.items:
            if binding.subjects is not None:
                for subject in binding.subjects:
                    if (
                        subject.kind == "ServiceAccount"
                        and subject.name == service_account_name
                        and subject.namespace == namespace
                    ):
                        roles.append(binding.role_ref.name)

        return set(roles)


def decode_token(request: Request) -> (str, str):
    if "Authorization" not in request.headers:
        raise AuthenticationError("Missing authorization header")

    auth = request.headers["Authorization"]
    try:
        scheme, token = auth.split()
        if scheme.lower() != "bearer":
            raise AuthenticationError(f"Expected Bearer schema, found {scheme}")

        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            subject: str = decoded_token["sub"]
            _, _, sa_namespace, sa_name = subject.split(":")
            return (sa_namespace, sa_name)
        except jwt.DecodeError as e:
            raise AuthenticationError(f"Error decoding JWT token: {e}")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise AuthenticationError("Invalid credentials")
