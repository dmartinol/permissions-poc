from typing import List, Tuple

from security.permissions import AuthzedAction, Permission
from resources import Resource
from security.role_manager import RoleManager


class PolicyEnforcer:
    def enforce_policy(
        self,
        role_manager: RoleManager,
        permissions: List[Permission],
        user: str,
        resource: Resource,
        actions: List[AuthzedAction],
    ) -> Tuple[bool, str]:
        if permissions == []:
            return (True, "")
        for p in permissions:
            print(f"Trying permission {p.name}")
            if p.match_resource(resource):
                print(f"Matches {resource.name}/{resource.get_type()}")
                if p.match_actions(actions):
                    print(f"Matches actions {actions}")
                    for policy in p.policies:
                        result, explain = policy.validate_user(user)
                        # TODO manage decision strategy
                        message = ""
                        if not result:
                            message = f"No permissions to execute {actions} on {resource.get_type()}:{resource.get_name()}. {explain}"
                            print(f"**PERMISSION ERROR**: {message}")
                        return (result, message)
                else:
                    message = f"No permissions defined to manage {actions} on {resource.get_type()}:{resource.get_name()}."
                    print(f"**PERMISSION ERROR**: {message}")
                # TODO: manage multiple matching permissions
        return (False, "")


_enforcer = None


def _get_enforcer() -> PolicyEnforcer:
    global _enforcer
