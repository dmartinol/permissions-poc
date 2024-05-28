import enum
from typing import List, Optional, Dict


class AuthzedResourceType(enum.Enum):
    ALL = "all"
    A = "A"
    B = "B"


class AuthzedResource:
    def __init__(
        self,
        type: AuthzedResourceType,
        name_patterns: Optional[List[str]] = [],
        required_tags: Optional[Dict[str, str]] = {},
    ):
        self.type = type
        self.name_patterns = name_patterns
        self.required_tags = required_tags
