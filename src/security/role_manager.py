from typing import List


class RoleManager:
    """Roles management"""

    def __init__(self):
        self.roles_by_user = {}

    def add_roles_for_user(self, user: str, roles: List[str]):
        self.roles_by_user.setdefault(user, []).extend(roles)

    def clear(self) -> None:
        self.roles_by_user.clear()

    def has_roles_for_user(self, user: str, roles: List[str]) -> bool:
        print(
            f"Check {user} has all {roles}: currently {self.roles_by_user[user] if user in self.roles_by_user else[]}"
        )
        return user in self.roles_by_user and all(
            r in self.roles_by_user[user] for r in roles
        )


_rm: RoleManager = None


def _get_role_manager() -> RoleManager:
    global _rm
    if _rm is None:
        _rm = RoleManager()

    return _rm
