import assertpy

from security.policy import RoleBasedPolicy


def test_has_roles(role_manager):
    rm = role_manager
    policy = RoleBasedPolicy(["a-reader"])

    assertpy.assert_that(policy.validate_user("a-reader", role_manager=rm)[0]).is_true()
    assertpy.assert_that(
        policy.validate_user("b-manager", role_manager=rm)[0]
    ).is_false()
    assertpy.assert_that(
        policy.validate_user("missing-user", role_manager=rm)[0]
    ).is_false()
