import pytest

from security.authzed_resource import AuthzedResource, AuthzedResourceType
from security.enforcer import PolicyEnforcer
from security.permissions import AuthzedAction, Permission
from security.policy import RoleBasedPolicy
from security.security_manager import SecurityManager, _set_security_manager
from impl import ResourceA, ResourceB
from security.role_manager import _get_role_manager


@pytest.fixture
def role_manager():
    rm = _get_role_manager()
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


def test_a_reader_reads_from_A(security_manager, role_manager, permissions):
    security_manager.set_current_user("a-reader")

    a = ResourceA(name="a", tags=[])
    b = ResourceB(name="b", tags=[])

    a.read_protected()
    with pytest.raises(PermissionError):
        a.edit_protected()
    with pytest.raises(PermissionError):
        b.read_protected()
    with pytest.raises(PermissionError):
        b.edit_protected()


def test_b_manager_manages_B(security_manager, role_manager, permissions):
    security_manager.set_current_user("b-manager")

    a = ResourceA(name="a", tags=[])
    b = ResourceB(name="b", tags=[])

    a.unprotected()
    with pytest.raises(PermissionError):
        a.read_protected()
    with pytest.raises(PermissionError):
        a.edit_protected()
    b.read_protected()
    b.edit_protected()


def test_admin_executes_all(security_manager, role_manager, permissions):
    security_manager.set_current_user("admin")

    a = ResourceA(name="a", tags=[])
    b = ResourceB(name="b", tags=[])

    a.unprotected()
    a.read_protected()
    a.edit_protected()
    b.read_protected()
    b.edit_protected()


def test_unexisting_user_allowed_uprotected(
    security_manager, role_manager, permissions
):
    security_manager.set_current_user("foo")

    a = ResourceA(name="a", tags=[])
    b = ResourceB(name="b", tags=[])

    a.unprotected()

    with pytest.raises(PermissionError):
        a.read_protected()
    with pytest.raises(PermissionError):
        a.edit_protected()
    with pytest.raises(PermissionError):
        b.read_protected()
    with pytest.raises(PermissionError):
        b.edit_protected()
