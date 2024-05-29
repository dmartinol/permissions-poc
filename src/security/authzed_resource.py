import enum
from typing import List, Optional, Dict


class AuthzedResourceType(enum.Enum):
    """
    An enum with all the protected resource typoes
    """

    ALL = "all"
    A = "A"
    B = "B"


class AuthzedResource:
    """
    The AuthzedResource identifies the protected resources by class type and optional filters
    based on the resource name and tags
    """

    def __init__(
        self,
        type: AuthzedResourceType,
        name_patterns: Optional[List[str]] = [],
        required_tags: Optional[Dict[str, str]] = {},
    ):
        self.type = type
        self.name_patterns = name_patterns
        self.required_tags = required_tags
