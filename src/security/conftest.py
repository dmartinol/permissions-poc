import pytest

from security.authzed_resource import AuthzedResource, AuthzedResourceType
from security.enforcer import PolicyEnforcer
from security.permissions import AuthzedAction, Permission
from security.policy import RoleBasedPolicy
from security.role_manager import RoleManager
from security.security_manager import SecurityManager, _set_security_manager


@pytest.fixture
def role_manager():
    rm = RoleManager()
    rm.add_roles_for_user("a-reader", ["a-reader"])
    rm.add_roles_for_user("b-manager", ["b-reader", "b-editor"])
    rm.add_roles_for_user("admin", ["a-reader", "a-editor", "b-reader", "b-editor"])
    return rm


@pytest.fixture
def permissions():
    permissions = []
    permissions.append(
        Permission(
            name="read-from-any-A",
            resources=[AuthzedResource(type=AuthzedResourceType.A)],
            policies=[RoleBasedPolicy(roles=["a-reader"])],
            actions=[AuthzedAction.READ],
        )
    )
    permissions.append(
        Permission(
            name="edit-any-A",
            resources=[AuthzedResource(type=AuthzedResourceType.A)],
            policies=[RoleBasedPolicy(roles=["a-editor"])],
            actions=[AuthzedAction.EDIT],
        )
    )
    permissions.append(
        Permission(
            name="all-to-any-B",
            resources=[AuthzedResource(type=AuthzedResourceType.B)],
            policies=[RoleBasedPolicy(roles=["b-reader", "b-editor"])],
            actions=[AuthzedAction.ALL],
        )
    )
    return permissions


@pytest.fixture
def security_manager(role_manager, permissions):
    sm = SecurityManager(
        role_manager=role_manager,
        policy_enforcer=PolicyEnforcer(),
        permissions=permissions,
    )
    _set_security_manager(sm)
    return sm
