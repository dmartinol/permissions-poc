from abc import ABC, abstractmethod

from security.authzed_resource import AuthzedResourceType


class Resource(ABC):
    def __init__(self, name: str, tags: dict[str, str]):
        self.name = name
        self.tags = tags

    def get_name(self) -> str:
        return self.name

    @abstractmethod
    def get_type(self) -> AuthzedResourceType:
        raise NotImplementedError

    def get_tags(self) -> list[str]:
        return self.tags
