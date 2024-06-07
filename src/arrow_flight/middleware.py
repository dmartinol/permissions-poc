import pyarrow.flight as fl
import os
from auth import get_auth_manager_instance
from typing import List


class AuthorizationMiddlewareFactory(fl.ServerMiddlewareFactory):
    def __init__(self):
        pass

    def start_call(self, info, headers):
        auth_manager = os.getenv("AUTH_MANAGER", "").lower()
        if auth_manager != "":
            access_token = None
            for header in headers:
                if header.lower() == "authorization":
                    auth_header = headers[header][0]
                    _, _, access_token = auth_header.partition(" ")
                    break
            # TODO token validation

            current_user, roles = (
                get_auth_manager_instance().user_details_from_access_token(access_token)
            )
            return AuthorizationMiddleware(current_user=current_user, roles=roles)


class AuthorizationMiddleware(fl.ServerMiddleware):
    def __init__(self, current_user: str, roles: List[str]):
        self.current_user = current_user
        self.roles = roles

    def call_completed(self, exception):
        if exception:
            print(f"Middleware received {exception}")
