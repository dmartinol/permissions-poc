from concurrent.futures import ThreadPoolExecutor
from security.security_manager import (
    _get_security_manager,
    _set_security_manager,
    SecurityManager,
)
from security.role_manager import RoleManager
from security.enforcer import PolicyEnforcer
from security.utils import (
    a_reader_reads_from_A,
    b_manager_manages_B,
    admin_executes_all,
    unexisting_user_allowed_uprotected,
)
import assertpy


def validate_current_user(user: str) -> bool:
    sm = _get_security_manager()
    sm.set_current_user(user)
    for i in range(1, 100):
        assertpy.assert_that(sm.current_user).is_equal_to(user)

    return True


def test_current_user():
    _set_security_manager(
        SecurityManager(
            role_manager=RoleManager(), permissions=[], policy_enforcer=PolicyEnforcer()
        )
    )
    n = 10
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        for i in range(n):
            futures.append(executor.submit(validate_current_user, f"user-{i}"))

        for i in range(n):
            result = futures[i].result()
            assertpy.assert_that(result).is_true()


def test_concurrent_security(security_manager):
    sm = security_manager
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        futures.append(
            executor.submit(
                a_reader_reads_from_A,
                sm,
                role_manager=sm.role_manager,
                permissions=sm.permissions,
            )
        )
        futures.append(
            executor.submit(
                b_manager_manages_B,
                sm,
                role_manager=sm.role_manager,
                permissions=sm.permissions,
            )
        )
        futures.append(
            executor.submit(
                admin_executes_all,
                sm,
                role_manager=sm.role_manager,
                permissions=sm.permissions,
            )
        )
        futures.append(
            executor.submit(
                unexisting_user_allowed_uprotected,
                sm,
                role_manager=sm.role_manager,
                permissions=sm.permissions,
            )
        )

        for f in futures:
            result = f.result()
            assertpy.assert_that(result).is_none()
