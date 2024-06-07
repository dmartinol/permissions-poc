import ast

import pyarrow as pa
import json
import pyarrow.flight as fl
import os

from impl import ResourceA, ResourceB
from resources import Resource
from security.authzed_resource import AuthzedResourceType
from security.security_manager import _get_security_manager
from auth import get_auth_manager_instance
from arrow_flight.middleware import AuthorizationMiddlewareFactory

# class NoOpAuthHandler(pa.flight.ServerAuthHandler):
#     def authenticate(self, outgoing, incoming):
#         pass

#     def is_valid(self, token):
#         return ""


class PocFlightServer(fl.FlightServerBase):
    resources = ["A", "B"]

    def __init__(self, location="grpc://0.0.0.0:8815", **kwargs):
        super(PocFlightServer, self).__init__(
            location,
            # auth_handler=NoOpAuthHandler(),
            middleware={
                "auth": AuthorizationMiddlewareFactory(),
            },
            **kwargs,
        )
        self._location = location

    def descriptor_to_key(descriptor):
        return (
            descriptor.descriptor_type.value,
            descriptor.command,
            tuple(descriptor.path or tuple()),
        )

    def _make_flight_info(self, resource):
        schema = pa.schema([("name", pa.string()), ("message", pa.string())])
        endpoints = [fl.FlightEndpoint(repr(resource), [self._location])]
        return fl.FlightInfo(
            schema, fl.FlightDescriptor.for_command(resource), endpoints, 1, 1
        )

    def list_flights(self, context, criteria):
        for resource in PocFlightServer.resources:
            yield self._make_flight_info(resource)

    def get_flight_info(self, context, descriptor):
        resource = descriptor.command.decode("utf-8")
        return self._make_flight_info(resource)

    def do_put(self, context, descriptor, reader, writer):
        pass

    def do_get(self, context, ticket):
        auth_manager = os.getenv("AUTH_MANAGER", "").lower()
        print(f"auth_manager is {auth_manager}")
        if auth_manager != "":
            auth_middleware = context.get_middleware("auth")
            sm = _get_security_manager()
            sm.set_current_user(auth_middleware.current_user)
            sm.role_manager.clear()
            sm.role_manager.add_roles_for_user(
                auth_middleware.current_user, auth_middleware.roles
            )

        command = json.loads(ast.literal_eval(ticket.ticket.decode()))
        resource = command["resource"].split(".")[1]
        if resource not in PocFlightServer.resources:
            print(f"Unknown resource {resource}")
            return None

        api = command["api"]

        print(f"Executing API {api} on {resource}")
        resource: Resource
        try:
            if resource == AuthzedResourceType.A.value:
                resource = ResourceA("a", [])

                if api == "read":
                    resource.read_protected()
                elif api == "edit":
                    resource.edit_protected()
            elif resource == AuthzedResourceType.B.value:
                resource = ResourceB("b", [])

                if api == "read":
                    resource.read_protected()
                elif api == "edit":
                    resource.edit_protected()
            else:
                raise NotImplementedError
        except PermissionError as pe:
            message = str(pe)
            raise fl.FlightUnauthorizedError(message=message)

        return self.return_result(resource, api)

    def return_result(self, resource: Resource, api: str):
        table = pa.Table.from_arrays(
            [
                pa.array([f"{resource.get_type()}:{resource.get_name()}"]),
                pa.array([api]),
            ],
            names=["name", "message"],
        )
        return pa.flight.RecordBatchStream(table)

    def list_actions(self, context):
        return []

    def do_action(self, context, action):
        raise NotImplementedError

    def do_drop_dataset(self, dataset):
        pass


if __name__ == "__main__":
    am = get_auth_manager_instance()
    print(f"am is {am}")
    server = PocFlightServer()
    server.serve()

am = get_auth_manager_instance()
print(f"am is {am}")
server = PocFlightServer()
server.serve()
