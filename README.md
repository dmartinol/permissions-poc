
# Permissions POC
Scope of this POC is to validate a fine grained python permission model to:
* Create permissions on protected objects identified by type and optional filtering criteria
* Define method level permissions using decorators
* Define a pluggable authorization manager to connect to external identity providers (IDP):
  * OIDC, using Keycloak
  * K8s RBAC

## Permission model
The `Permission` class defines the permission model in [permissions](./src/security/permissions.py) module and includes:
* The protected `resources`, using the `AuthzedResource` model in [](./src/security/authzed_resource.py)
  * The `type` of protected resources
  * An optional `name_patterns` to filter the resource instances by name [**NOT IMPLEMENTED in this POC**]
  * An optional `required_tags` field to filter the resource instances by tags [**NOT IMPLEMENTED in this POC**]
* The authorized `actions`, defined by the `AuthzedAction` enum in [permissions](./src/security/permissions.py) module
* The authorization `policies`, defined by the `Policy` and `RoleBasedPolicy` in [policy](./src/security/policy.py) module
  * `RoleBasedPolicy` specifies the roles that must be granted to the user to permit the execution of the given action(s)
* The `decision strategy` to adopt in case of multiple matching policies [**NOT IMPLEMENTED in this POC**]

Example of `Permission` to specify that resources of type `A` requires the user to grant the `a-reader` role in order to execute
the `READ` action:
```py
    Permission(
        name="read-from-any-A",
        resources=[AuthzedResource(type=AuthzedResourceType.A)],
        policies=[RoleBasedPolicy(roles=["a-reader"])],
        actions=[AuthzedAction.READ],
    )
```

## Protected domain
Two resources are available, namely `ResourceA` and `ResourceB`, both in the [impl](./src/impl.py) module.
They extend from a generic `Resource` class to expose `get_name`, `get_type` and `get_tags` methods.

Example of security configuration:
```py
    @require_permissions(actions=[AuthzedAction.READ])
    def read_protected(self):
        print(f"Calling read_protected on {self.name}")
```

The decorator defines the actions that must be permitted to the user.

**Note**: even if not used in the POC, a programmatic security can be applied when the decorator pattern cannot be used, with the
APIs defined in the `SecurityManager` class, in [security_manager](./src/security/security_manager.py) module

## Permission configuration
The POC models the following methods:

|Resource type|Method|Protected by action|
|-------------|------|-------------------|
|`ResourceA`    |`read_protected`|`READ` |
|`ResourceA`    |`edit_protected`|`EDIT` |
|`ResourceA`    |`unprotected`|          |
|`ResourceB`    |`read_protected`|`READ` |
|`ResourceB`    |`edit_protected`|`EDIT` |
|`ResourceB`    |`unprotected`|          |

The realm modelled by the test environment is made of the following users:
|User|Role|Allowed actions|
|----|----|---------------|
|`a-reader`|`a-reader`| `READ` on `ResourceA`|
|`b-manager`|`b-reader`, `b-editor`| `READ` and `EDIT` on `ResourceB`|
|`admin`|`a-reader`, `a-editor`, `b-reader`, `b-editor`| All actions on any resource|

## Configuring the python environment
Create virtual env:
```console
python -m venv venv
source venv/bin/activate
```

Install requirements:
```console
pip install -r requirements.txt
```

Validate the app with unit tests:
```console
make test
```

## Run the insecure app
```console
AUTH_MANAGER="" make run-app
```

Follow the interactive instructions and test with:
```console
make run-test
```
Output example (all services are allowed, there is no current user in place):
```bash
Is it a secured service? (y/n): n

Enter the service path, e.g. '/a' (RETURN to stop): /a
Trying GET http://localhost:8000/a
{"message":"read_A"}
Trying POST http://localhost:8000/a
{"message":"edit_A"}

Enter the service path, e.g. '/a' (RETURN to stop): /b
Trying GET http://localhost:8000/b
{"message":"read_B"}
Trying POST http://localhost:8000/b
{"message":"edit_B"}

Enter the service path, e.g. '/a' (RETURN to stop): / 
Trying GET http://localhost:8000/
{"message":"read_unprotected"}
Trying POST http://localhost:8000/
{"message":"post_unprotected"}
```

## Run app secured by Keycloak

### Setup Keycloak
Start Keycloak from a container image and initialize a `poc` realm with `app` client and some users:
```
make start-keycloak
make setup-keycloak
cat.env
```
The content of `.env` is used by the `KeycloakAuthManager` in [keycloak_auth_manager](./src/auth/keycloak_auth_manager.py) to:
* Validate the authentication bearer token
* Extract the user credentials and roles from the token
* Populate the `RoleManager` with the given roles for the current user with `sm.role_manager.add_roles_for_user(current_user, roles)`

Example of access token:
```json
{
...
  "aud": "account",
...
  "typ": "Bearer",
  "azp": "app",
...
  "resource_access": {
    "app": {
      "roles": [
        "a-reader"
      ]
    },
...
  },
...
  "name": "user a-reader",
  "preferred_username": "a-reader",
  "given_name": "user",
  "family_name": "a-reader",
  "email": "a-reader@poc.com"
}
```

### Run app with Keycloak OIDC
Use the `AUTH_MANAGER` variable to setup the Keycloak authentication manager:
```console
AUTH_MANAGER=keycloak make run-app
```

Test with:
```console
make run-test
```

Output example for user `a-reader` (allowed to `GET \a`):
```bash
Is it a secured service? (y/n): y
Enter your username: a-reader

Enter the service path, e.g. '/a' (RETURN to stop): /a
Trying GET http://localhost:8000/a
{"message":"read_A"}
Trying POST http://localhost:8000/a
{"message":"No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']"}

Enter the service path, e.g. '/a' (RETURN to stop): /b
Trying GET http://localhost:8000/b
{"message":"No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']"}
Trying POST http://localhost:8000/b
{"message":"No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']"}
```

Output example for user `b-manager` (allowed to `GET \a` and `POST \b`):
```bash
Is it a secured service? (y/n): y
Enter your username: b-manager

Enter the service path, e.g. '/a' (RETURN to stop): /a
Trying GET http://localhost:8000/a
{"message":"No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.A:a. Requires roles ['a-reader']"}
Trying POST http://localhost:8000/a
{"message":"No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']"}

Enter the service path, e.g. '/a' (RETURN to stop): /b
Trying GET http://localhost:8000/b
{"message":"read_B"}
Trying POST http://localhost:8000/b
{"message":"edit_B"}
```

## Run app secured by Kubernetes tokens
### Architecture of KubernetesAuthManager
This authentication manager is made of two components, both running in the same cluster:
* The client invokes REST services sending the token of the associated `ServiceAccount` in the authorization bearer (*)
* The server, implemented by `KubernetesAuthManager` defined in [kubernetes_auth_manager](./src/auth/kubernetes_auth_manager.py) is in chanrge of:
  * Detect the `ServiceAccount` name and namespace from the JWT token
  * Identify the `Role`s and `ClusterRole`s bound to the `ServiceAccount` (**)
  * Populate the `RoleManager` with the given roles for the current user with `sm.role_manager.add_roles_for_user(current_user, roles)`

Example of decoded JWT token:
```json
{
  ...
 'kubernetes.io': {'namespace': 'feast',
  'pod': {'name': 'feast-notebook-0', ...},
  'serviceaccount': {'name': 'feast-notebook', ...},
  ...},
 ...
 'sub': 'system:serviceaccount:feast:feast-notebook'}
```
`sub` field (e.g. `subject`) identifies the `ServiceAccount` with name `feast-notebook` in namwespace `feast`

(*) **Note**: we could define a module to enrich the `Feast` clients with an extension to automatically include the bearer token in every
request to the server. This could result in an extra option in the repository configuration:
```yaml
offline_store:
    type: remote
    host: localhost
    port: 8815
    auth:
        type: kubernetes
```
The same may apply for the servers protected by Keycloak OIDC, so that the client requests can automatically add the authentication token:
```yaml
offline_store:
    type: remote
    host: localhost
    port: 8815
    auth:
        type: keycloak
        server: 'http://0.0.0.0:8080'
        realm: 'poc'
        client-id: 'app'
        client-secret: 'mqAzX7zDalQ1a3BZRWs7Pi5JRqCq7h4z'
        username: 'username'
        password: 'password'
```
(*) **Note**: because of the need to retrieve the `ClusterRole`s, the server needs to run with a Role allowing to fecth such instances.
For now, we're using the `admin ClusterRole`

### Deploying the POC app in kubernetes
Use the provided [app.yaml](./app.yaml) to create the required resources in the current namespace:
* A `poc-app` deployment
* All the managed `Role`s
* The `app` `ServiceAccount` bound to the `cluster-admin` `ClusterRole`
* The `poc-app` service
```console
oc apply -f app.yaml
```

The `poc-app` deployment runs a python 3.9 image with a never ending loop where we can install our application:
```console
zip -r app.zip Makefile requirements.txt src test.sh
POD_NAME=$(oc get pods -l app=poc-app -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
oc cp app.zip $POD_NAME:/tmp
oc rsh $POD_NAME
```

Once in the Pod console, run the following to initialize the environment:
```console
cd /tmp
mkdir app
cd app
unzip ../app.zip
python -m venv venv
pip install -r requirements.txt
```

Then start the server with:
```console
AUTH_MANAGER=k8s make run-app
```

A client notebook [poc-client.ipynb](./poc-client.ipynb) is provided for your convenience to run the client code.
Install it on a Notebook in the same cluster and run the test to validate that a `Forbidden` error (403) is raised when
we invoke a service wiythout having the required role.




