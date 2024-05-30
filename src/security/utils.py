import pytest
from impl import ResourceA, ResourceB


def a_reader_reads_from_A(security_manager, role_manager, permissions):
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


def b_manager_manages_B(security_manager, role_manager, permissions):
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


def admin_executes_all(security_manager, role_manager, permissions):
    security_manager.set_current_user("admin")

    a = ResourceA(name="a", tags=[])
    b = ResourceB(name="b", tags=[])

    a.unprotected()
    a.read_protected()
    a.edit_protected()
    b.read_protected()
    b.edit_protected()


def unexisting_user_allowed_uprotected(security_manager, role_manager, permissions):
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
