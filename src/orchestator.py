from impl import ResourceA, ResourceB
from security.permissions import AuthzedAction
from security.security_manager import SecurityManager
from typing import List


class Orchestrator:
    def __init__(self, sm: SecurityManager) -> None:
        self.sm = sm

    def do_something(self, a: ResourceA, b: ResourceB) -> List[str]:
        messages: List[str] = []
        # Read from A
        try:
            print(f"Trying read from {a}")
            self.sm.assert_permissions(a, AuthzedAction.READ)
            a.read_protected()
            messages.append("DONE a.read_protected()")
        except PermissionError as e:
            messages.append(f"{e}")

        try:
            print(f"Trying read from {b}")
            self.sm.assert_permissions(b, AuthzedAction.READ)
            b.read_protected()
            messages.append("DONE b.read_protected()")
        except PermissionError as e:
            messages.append(f"{e}")

        try:
            print(f"Trying edit of {a}")
            self.sm.assert_permissions(a, AuthzedAction.EDIT)
            a.edit_protected()
            messages.append("DONE a.edit_protected()")
        except PermissionError as e:
            messages.append(f"{e}")

        try:
            print(f"Trying edit of {b}")
            self.sm.assert_permissions(b, AuthzedAction.EDIT)
            b.edit_protected()
            messages.append("DONE b.edit_protected()")
        except PermissionError as e:
            messages.append(f"{e}")

        return messages
