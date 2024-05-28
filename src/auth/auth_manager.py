from fastapi import Request
from typing import Any


class AuthManager:
    def init(self):
        """
        Initialize the AuthManager instance (invoked once at startup time)
        """
        pass

    async def inject_user_data(self, request: Request) -> Any:
        """
        A function to initialize the user details (e.g. extract authentication token and obtain
        user ID and roles to be propagated to the security layer)
        """
        pass
