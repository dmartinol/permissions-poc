from resources import Resource
from security.security_manager import require_permissions
from security.authzed_resource import AuthzedResourceType
from security.permissions import AuthzedAction


class ResourceA(Resource):
    def __init__(self, name, tags):
        super().__init__(name, tags)

    def get_type(self) -> AuthzedResourceType:
        return AuthzedResourceType.A

    @require_permissions(actions=[AuthzedAction.READ])
    def read_protected(self):
        print(f"Calling read_protected on {self.name}")

    @require_permissions(actions=[AuthzedAction.EDIT])
    def edit_protected(self):
        print(f"Calling edit_protected on {self.name}")

    def unprotected(self):
        print(f"Calling unprotected on {self.name}")


class ResourceB(Resource):
    def __init__(self, name, tags):
        super().__init__(name, tags)

    def get_type(self) -> AuthzedResourceType:
        return AuthzedResourceType.B

    @require_permissions(actions=[AuthzedAction.READ])
    def read_protected(self):
        print(f"Calling read_protected on {self.name}")

    @require_permissions(actions=[AuthzedAction.EDIT])
    def edit_protected(self):
        print(f"Calling edit_protected on {self.name}")

    def unprotected(self):
        print(f"Calling unprotected on {self.name}")
