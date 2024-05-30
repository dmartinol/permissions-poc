from security.utils import (
    a_reader_reads_from_A,
    b_manager_manages_B,
    admin_executes_all,
    unexisting_user_allowed_uprotected,
)


def test_a_reader_reads_from_A(security_manager, role_manager, permissions):
    a_reader_reads_from_A(security_manager, role_manager, permissions)


def test_b_manager_manages_B(security_manager, role_manager, permissions):
    b_manager_manages_B(security_manager, role_manager, permissions)


def test_admin_executes_all(security_manager, role_manager, permissions):
    admin_executes_all(security_manager, role_manager, permissions)


def test_unexisting_user_allowed_uprotected(
    security_manager, role_manager, permissions
):
    unexisting_user_allowed_uprotected(security_manager, role_manager, permissions)
