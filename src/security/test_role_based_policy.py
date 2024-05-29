import assertpy
import pytest

from security.policy import RoleBasedPolicy
from security.role_manager import RoleManager


@pytest.fixture
def role_manager():
    rm = RoleManager()
    rm.add_roles_for_user("a", ["a1", "a2"])
    rm.add_roles_for_user("b", ["b1", "b2"])
    return rm


def test_has_roles(role_manager):
    rm = role_manager
    policy = RoleBasedPolicy(["a1"])

    assertpy.assert_that(policy.validate_user("c", role_manager=rm)[0]).is_false()
    assertpy.assert_that(policy.validate_user("a", role_manager=rm)[0]).is_true()
    assertpy.assert_that(policy.validate_user("b", role_manager=rm)[0]).is_false()
