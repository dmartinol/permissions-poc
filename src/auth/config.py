from security.permissions import (
    AuthzedAction,
    AuthzedResource,
    AuthzedResourceType,
    Permission,
)
from security.policy import RoleBasedPolicy


def setup_permissions():
    permissions = []
    permissions.append(
        Permission(
            name="read-from-any-A",
            resources=[AuthzedResource(type=AuthzedResourceType.A)],
            policies=[RoleBasedPolicy(roles=["a-reader"])],
            actions=[AuthzedAction.READ],
        )
    )
    permissions.append(
        Permission(
            name="edit-any-A",
            resources=[AuthzedResource(type=AuthzedResourceType.A)],
            policies=[RoleBasedPolicy(roles=["a-editor"])],
            actions=[AuthzedAction.EDIT],
        )
    )
    permissions.append(
        Permission(
            name="all-to-any-B",
            resources=[AuthzedResource(type=AuthzedResourceType.B)],
            policies=[RoleBasedPolicy(roles=["b-reader", "b-editor"])],
            actions=[AuthzedAction.ALL],
        )
    )
    return permissions
