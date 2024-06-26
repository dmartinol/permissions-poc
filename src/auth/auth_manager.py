from fastapi import Request
from typing import Any
from abc import ABC, abstractmethod


class AuthManager(ABC):
    def init(self):
        """
        Initialize the AuthManager instance (invoked once at startup time).
        """
        pass

    @abstractmethod
    async def inject_user_data(self, request: Request) -> Any:
        """
        A function to initialize the user details (e.g. extract authentication token and obtain
        user ID and roles to be propagated to the security layer).
        """
        pass


class AllowAll(AuthManager):
    def init(self) -> None:
        from security.security_manager import (
            DefaultSecurityManager,
            _set_security_manager,
        )

        _set_security_manager(DefaultSecurityManager())

    async def inject_user_data(self, request: Request) -> Any:
        return True
