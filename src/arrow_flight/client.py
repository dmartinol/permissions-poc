import pyarrow.flight as fl
import requests
from dotenv import load_dotenv

import json
import os
from security.authzed_resource import AuthzedResourceType


def _test_api(client: fl.FlightClient, resource_type: AuthzedResourceType, api: str):
    command = {
        "resource": resource_type,
        "api": api,
    }
    descriptor = fl.FlightDescriptor.for_command(
        json.dumps(
            command,
        )
    )

    flight = client.get_flight_info(descriptor, options=opts)
    ticket = flight.endpoints[0].ticket

    print(f"*** Trying {api} on {resource_type}")
    try:
        reader = client.do_get(ticket=ticket, options=opts)
        result = reader.read_all()
        df = result.to_pandas()
        first_row_dict = df.iloc[0].to_dict()
        json_object = json.dumps(first_row_dict, indent=4)
        print(json_object)
    except fl.FlightUnauthorizedError as e:
        message = str(e).split(". Detail")[0]
        print(message)


def get_access_token(username: str) -> str:
    load_dotenv("../.env")
    payload = {
        "grant_type": "password",
        "client_id": os.getenv("CLIENT_ID"),
        "client_secret": os.getenv("CLIENT_SECRET"),
        "username": username,
        "password": os.getenv("PASSWORD"),
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_url = "{}/realms/{}/protocol/openid-connect/token".format(
        os.getenv("OIDC_SERVER_URL"),
        os.getenv("REALM"),
    )
    response = requests.post(token_url, data=payload, headers=headers)

    if response.status_code == 200:
        token_data = response.json()
        print(f"Got token for {username}")
        return token_data.get("access_token")
    else:
        print(f"From {token_url}, got error: {response.status_code}")
        raise Exception("Not authenticated")


opts: fl.FlightCallOptions = None
auth_manager = os.getenv("AUTH_MANAGER", "").lower()
if auth_manager == "oidc":
    username = input("Please enter the user name: ")
    token = get_access_token(username)
    auth_header = (b"authorization", f"Bearer {token}".encode("utf-8"))
    opts = fl.FlightCallOptions(headers=[auth_header])

port = 8815
client = fl.FlightClient(f"grpc://localhost:{port}")
# actions = list(client.list_actions(options=opts))
# print(f"*** actions is {actions}")
# flights = list(client.list_flights(options=opts))
# print(f"*** flights is {flights}")

result = _test_api(
    client=client,
    resource_type=str(AuthzedResourceType.A),
    api="read",
)
result = _test_api(
    client=client,
    resource_type=str(AuthzedResourceType.A),
    api="edit",
)
result = _test_api(
    client=client,
    resource_type=str(AuthzedResourceType.B),
    api="read",
)
result = _test_api(
    client=client,
    resource_type=str(AuthzedResourceType.B),
    api="edit",
)
