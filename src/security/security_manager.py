from typing import List, Optional, Union

from security.enforcer import PolicyEnforcer
from security.permissions import AuthzedAction, Permission
from resources import Resource
from security.role_manager import RoleManager


def require_permissions(actions: Optional[List[AuthzedAction]] = [AuthzedAction.ALL]):
    """
    A decorator to define the actions that are executed from within the current class method and that must be protected
    against unauthorized access.

    The first parameter of the protected method must be `self`
    """

    def require_permissions_decorator(func):
        def permission_checker(*args, **kwargs):
            print(f"permission_checker for {args}, {kwargs}")
            resource = args[0]
            if issubclass(Resource, type(resource)):
                raise NotImplementedError(
                    f"First argument must be a Resource not {type(resource)}"
                )

            sm = _get_security_manager()
            if sm is None:
                return True

            sm.assert_permissions(
                resource=resource,
                actions=actions,
            )
            print(
                f"User {sm.current_user} can invoke {actions} on {resource.get_name()}:{resource.get_type()} "
            )
            result = func(*args, **kwargs)
            return result

        return permission_checker

    return require_permissions_decorator


class SecurityManager:
    """
    The security manager holds references to the security components (role manager, policy enforces) and the configured permissions.
    It is accessed and defined using the global functions :func:`_get_security_manager` and :func:`_set_security_manager`
    """

    def __init__(
        self,
        role_manager: RoleManager,
        policy_enforcer: PolicyEnforcer,
        permissions: List[Permission] = [],
    ):
        self._role_manager: RoleManager = role_manager
        self._policy_enforcer: PolicyEnforcer = policy_enforcer
        self._permissions: List[Permission] = permissions
        self._current_user: str = None

    def set_current_user(self, user: str):
        self._current_user = user

    @property
    def role_manager(self) -> RoleManager:
        return self._role_manager

    @property
    def policy_enforcer(self):
        return self._policy_enforcer

    @property
    def current_user(self) -> str:
        return self._current_user

    @property
    def permissions(self) -> List[Permission]:
        return self._permissions

    def assert_permissions(
        self,
        resource: Resource,
        actions: Union[AuthzedAction, List[AuthzedAction]],
    ):
        _actions = actions
        if isinstance(actions, AuthzedAction):
            _actions = [actions]

        result, explain = self._policy_enforcer.enforce_policy(
            role_manager=self._role_manager,
            permissions=self._permissions,
            user=self._current_user,
            actions=_actions,
            resource=resource,
        )
        if not result:
            raise PermissionError(explain)


_sm: SecurityManager = None


def _get_security_manager():
    global _sm
    return _sm


def _set_security_manager(sc: SecurityManager):
    global _sm
    _sm = sc
