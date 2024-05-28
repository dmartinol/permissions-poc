import enum
from typing import Dict, List, Optional

from security.authzed_resource import AuthzedResource, AuthzedResourceType
from security.policy import Policy, RoleBasedPolicy
from resources import Resource


class AuthzedAction(enum.Enum):
    ALL = "all"
    READ = "read"
    EDIT = "edit"


class DecisionStrategy(enum.Enum):
    UNANIMOUS = "unanimous"
    AFFIRMATIVE = "affirmative"
    CONSENSUS = "consensus"


class Permission:
    def __init__(
        self,
        name: str,
        resources: List[AuthzedResource] = [AuthzedResource(AuthzedResourceType.ALL)],
        actions: Optional[List[AuthzedAction]] = [AuthzedAction.ALL],
        policies: Optional[List[Policy]] = [],  # Equivalent to allow-all
        decision_strategy: Optional[DecisionStrategy] = DecisionStrategy.UNANIMOUS,
    ):
        self._name = name
        self._resources = resources
        self._actions = actions
        self._policies = policies
        self._decision_strategy = decision_strategy

    @property
    def name(self):
        return self._name

    @property
    def resources(self):
        return self._resources

    @property
    def actions(self):
        return self._actions

    @property
    def policies(self):
        return self._policies

    @property
    def decision_strategy(self):
        return self._decision_strategy

    @classmethod
    def with_permission_to_read(
        cls,
        name: str,
        roles: List[str],
        name_patterns: Optional[List[str]] = [],
        required_tags: Optional[Dict[str, str]] = {},
        decision_strategy: Optional[DecisionStrategy] = DecisionStrategy.AFFIRMATIVE,
    ):
        return cls(
            name=name,
            resources=[
                AuthzedResource(
                    type=AuthzedResourceType.ALL,
                    name_patterns=name_patterns,
                    required_tags=required_tags,
                )
            ],
            actions=[AuthzedAction.READ],
            policies=[RoleBasedPolicy(roles)],
            decision_strategy=decision_strategy,
        )

    @classmethod
    def with_permission_to_write(
        cls,
        name: str,
        roles: List[str],
        name_patterns: Optional[List[str]] = [],
        required_tags: Optional[Dict[str, str]] = {},
        decision_strategy: Optional[DecisionStrategy] = DecisionStrategy.AFFIRMATIVE,
    ):
        return cls(
            name=name,
            resources=[
                AuthzedResource(
                    type=AuthzedResourceType.ALL,
                    name_patterns=name_patterns,
                    required_tags=required_tags,
                )
            ],
            actions=[AuthzedAction.EDIT],
            policies=[RoleBasedPolicy(roles)],
            decision_strategy=decision_strategy,
        )

    def match_resource(self, resource: Resource) -> bool:
        for r in self._resources:
            if r.type == AuthzedResourceType.ALL or resource.get_type() == r.type:
                # TODO name and tags match
                return True
        return False

    def match_actions(self, actions: List[AuthzedAction]):
        if AuthzedAction.ALL in self._actions:
            return True

        return all(a in actions for a in self._actions)
