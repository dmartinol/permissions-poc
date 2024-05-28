from abc import ABC, abstractmethod
from typing import List

from security.role_manager import _get_role_manager


class Policy(ABC):
    @abstractmethod
    def validate_user(self, user: str) -> (bool, str):
        raise NotImplementedError


class RoleBasedPolicy(Policy):
    def __init__(
        self,
        roles: List[str],
    ):
        self.roles = roles

    def get_roles(self):
        self.roles

    def validate_user(self, user: str) -> (bool, str):
        rm = _get_role_manager()
        result = rm.has_roles_for_user(user, self.roles)
        explain = "" if result else f"Requires roles {self.roles}"
        return (result, explain)
