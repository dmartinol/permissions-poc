from abc import ABC, abstractmethod
from typing import List


class Policy(ABC):
    """
    An abstract class to ensure that the current user matches the configured security policies.
    """

    @abstractmethod
    def validate_user(self, user: str, **kwargs) -> (bool, str):
        raise NotImplementedError


class RoleBasedPolicy(Policy):
    """
    An Policy class where the user roles must be enforced to grant access to the requested action.
    All the configured roles must be granted to the current user in order to allow the execution.
    """

    def __init__(
        self,
        roles: List[str],
    ):
        self.roles = roles

    def get_roles(self):
        self.roles

    def validate_user(self, user: str, **kwargs) -> (bool, str):
        rm = kwargs.get("role_manager")
        result = rm.has_roles_for_user(user, self.roles)
        explain = "" if result else f"Requires roles {self.roles}"
        return (result, explain)
