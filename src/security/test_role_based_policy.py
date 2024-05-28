import assertpy
import pytest

from security.policy import RoleBasedPolicy
from security.role_manager import _get_role_manager


@pytest.fixture
def role_manager():
    rm = _get_role_manager()
    rm.add_roles_for_user("a", ["a1", "a2"])
    rm.add_roles_for_user("b", ["b1", "b2"])
    return rm


def test_has_roles(role_manager):
    policy = RoleBasedPolicy(["a1"])

    assertpy.assert_that(policy.validate_user("c")[0]).is_false()
    assertpy.assert_that(policy.validate_user("a")[0]).is_true()
    assertpy.assert_that(policy.validate_user("b")[0]).is_false()
