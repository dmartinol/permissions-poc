import requests
import json
from dotenv import set_key

OIDC_SERVER_URL = "http://0.0.0.0:8080"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

access_token: str = ""


def get_token():
    token_url = f"{OIDC_SERVER_URL}/realms/master/protocol/openid-connect/token"

    token_data = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD,
    }

    token_response = requests.post(token_url, data=token_data)
    if token_response.status_code == 200:
        global access_token
        access_token = token_response.json()["access_token"]
        return access_token
    else:
        print(
            f"Failed to obtain access token: {token_response.status_code} - {token_response.text}"
        )
        raise Exception("Not authenticated")


def keycloak_post(endpoint, data=None):
    url = f"{OIDC_SERVER_URL}/admin/{endpoint}"
    print(f"Creating {endpoint}")
    global access_token
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }
    response = requests.request("POST", url, headers=headers, data=json.dumps(data))
    print(f"POST response.status_code is {response.status_code}")
    return response.status_code


def keycloak_get(endpoint):
    url = f"{OIDC_SERVER_URL}/admin/{endpoint}"
    global access_token
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }
    response = requests.request("GET", url, headers=headers)
    print(f"GET response.status_code is {response.status_code}")
    return response.json()


def create_realm(realm_name):
    data = {"realm": realm_name, "enabled": "true"}
    keycloak_post("realms", data=data)
    response = keycloak_get(f"realms/{realm_name}")
    return response["id"]


def create_client(realm_name, client_name):
    data = {
        "clientId": client_name,
        "enabled": "true",
        "redirectUris": [
            "http://localhost:8000/*",
            "http://127.0.0.1:8000/*",
            "http://0.0.0.0:8000/*",
        ],
        "publicClient": False,
        "authorizationServicesEnabled": True,
        "protocol": "openid-connect",
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True,
    }
    keycloak_post(f"realms/{realm_name}/clients", data=data)
    response = keycloak_get(f"realms/{realm_name}/clients")
    client = None
    for c in response:
        if c["clientId"] == client_name:
            client = c
            break
    client_id = client["id"]
    client_secret = client["secret"]
    return client_id, client_secret


def create_client_roles(realm_name, client_id, roles):
    for role_name in roles:
        data = {"name": role_name, "clientRole": True}
        keycloak_post(f"realms/{realm_name}/clients/{client_id}/roles", data=data)

    response = keycloak_get(f"realms/{realm_name}/clients/{client_id}/roles")
    roles_by_name = dict((role["name"], role["id"]) for role in response)
    print(roles_by_name)
    return roles_by_name


def create_user_with_roles(
    realm_name, username, password, client_id, roles_by_name, roles
):
    data = {
        "username": username,
        "enabled": True,
        "email": f"{username}@poc.com",
        "emailVerified": True,
        "firstName": "user",
        "lastName": f"{username}",
        "credentials": [{"type": "password", "value": password}],
        "realmRoles": [],
    }
    keycloak_post(f"realms/{realm_name}/users", data=data)
    response = keycloak_get(f"realms/{realm_name}/users")
    user = None
    for u in response:
        if u["username"] == username:
            user = u
            break
    user_id = user["id"]

    data = [
        {
            "id": roles_by_name[role_name],
            "name": role_name,
        }
        for role_name in roles
    ]
    keycloak_post(
        f"realms/{realm_name}/users/{user_id}/role-mappings/clients/{client_id}",
        data=data,
    )


if __name__ == "__main__":
    get_token()

    realm_name = "poc"
    client_name = "app"
    password = "poc"

    realm_id = create_realm(realm_name)
    client_id, client_secret = create_client(realm_name, client_name)

    roles_by_name = create_client_roles(
        realm_name, client_id, ["a-reader", "b-reader", "a-editor", "b-editor"]
    )

    create_user_with_roles(
        realm_name, "a-reader", password, client_id, roles_by_name, ["a-reader"]
    )
    create_user_with_roles(
        realm_name,
        "b-manager",
        password,
        client_id,
        roles_by_name,
        ["b-reader", "b-editor"],
    )
    create_user_with_roles(
        realm_name,
        "admin",
        password,
        client_id,
        roles_by_name,
        ["a-reader", "b-reader", "a-editor", "b-editor"],
    )

    print(f"Realm {realm_name} setup completed.")
    print(
        f"Client {client_name} created with ID {client_id} and secret {client_secret}"
    )

    env_file = ".env"
    with open(env_file, "w") as file:
        pass

    # Write property P=1 to the .env file
    set_key(env_file, "OIDC_SERVER_URL", OIDC_SERVER_URL)
    set_key(env_file, "REALM", realm_name)
    set_key(env_file, "CLIENT_ID", client_name)
    set_key(env_file, "CLIENT_SECRET", client_secret)
    set_key(env_file, "PASSWORD", password)
    print(f"Settings configured in {env_file}")
