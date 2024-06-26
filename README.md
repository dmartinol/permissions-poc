
# Permissions POC
Scope of this POC is to validate a fine grained python permission model to:
* Create permissions on protected objects identified by type and optional filtering criteria
* Define method level permissions using decorators or authorization API
* Define a pluggable authorization manager to connect to external identity providers (IDP):
  * OIDC, using Keycloak as an initial example
  * K8s RBAC

This POC is designed to propose an implementation for the `Feast Security model`, as defined in 
[issue #4198](https://github.com/feast-dev/feast/issues/4198)

## Permission model
The `Permission` class defines the permission model in the [permissions](./src/security/permissions.py) module and includes:
* The protected `resources`, using the `AuthzedResource` model in [authzed_resource](./src/security/authzed_resource.py)
  * The `type` of protected resources
  * An optional `name_patterns` to filter the resource instances by name [**NOT IMPLEMENTED in this POC**]
  * An optional `required_tags` field to filter the resource instances by tags [**NOT IMPLEMENTED in this POC**]
* The authorized `actions`, defined by the `AuthzedAction` enum in [permissions](./src/security/permissions.py) module
* The authorization `policies`, defined by the abstract class `Policy` in the [policy](./src/security/policy.py) module
  * The same module defines the `RoleBasedPolicy` implementation, where the authorization policy is determined by the user roles 
  required to execute the given action(s).
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
Two resource types are available, namely `ResourceA` and `ResourceB`, both in the [impl](./src/impl.py) module.
They extend a generic `Resource` class to expose `get_name`, `get_type` and `get_tags` methods.

An `Orchestrator` class is defined in the [orchestrator](./src/orchestator.py) module with a method
```py
def do_something(self, a: ResourceA, b: ResourceB) -> List[str]:
```

to invoke all the available methods on `a` and `b`, catching errors and returning a summarized execution report, like:
```json
[
  "DONE a.read_protected()",
  "No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']",
  "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']",
  "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']"
]
```

## Protecting resources with decorators
Example of security configuration using decorators:
```py
    @require_permissions(actions=[AuthzedAction.READ])
    def read_protected(self):
        print(f"Calling read_protected on {self.name}")
```

The `require_permissions` decorator defines the actions that must be permitted to the user.

## Protecting resources with API
A programmatic security can be applied when the decorator pattern cannot be used, with the
APIs defined in the `SecurityManager` class, in [security_manager](./src/security/security_manager.py) module:

```py
    a : ResourceA = ...
    sm = _get_seccurity_manager()
    self.sm.assert_permissions(a, AuthzedAction.EDIT)
```

## Security modules
The security modules include:
* The `RoleManager` class, to manage the roles of the users requesting the access to protected methods and functions.
* The `Policy` and `RoleBasedPolicy` classes, to validate the authorization grants for a given user.
* The `PolicyEnforcer` class, to evaluate the authorization decision for a given user request.
* The `SecurityManager` class, to act as a global manager to all the security components.
* The `require_permissions` decorator.

## Authorization modules
The authorization modules are designed to be used in applications exposing HTTP services:
* The `AuthManager` abstract class, with an `inject_user_data` global function to extract the user details from the current request.
* The `OidcAuthManager` implementation, using a configurable OIDC server to extract the user details.
* The `KubernetesAuthManager` implementation, using the Kubernetes RBAC resources to extract the user details.

Example of authorization configuration in a REST endpoint:
```py
@app.get("/a", dependencies=[Depends(inject_user_data)])
async def read_A():
    a.read_protected()

    return {"message": "read_A"}
```

Similarly, this implementation can be adapted for use with gRPC-based servers [**NOT IMPLEMENTED in this POC**].

## Running the POC
### Permission configuration
The POC defines the following resources and methods:

|Resource type|Method|Protected by action|
|-------------|------|-------------------|
|`ResourceA`    |`read_protected`|`READ` |
|`ResourceA`    |`edit_protected`|`EDIT` |
|`ResourceA`    |`unprotected`|          |
|`ResourceB`    |`read_protected`|`READ` |
|`ResourceB`    |`edit_protected`|`EDIT` |
|`ResourceB`    |`unprotected`|          |

The realm modelled by the test environment is made of the following users:
|User|Roles|Allowed actions|
|----|----|---------------|
|`a-reader`|`a-reader`| `READ` on `ResourceA`|
|`b-manager`|`b-reader`, `b-editor`| `READ` and `EDIT` on `ResourceB`|
|`admin`|`a-reader`, `a-editor`, `b-reader`, `b-editor`| All actions on any resource|

Finally, the configured permissions are:
|Name|Resource type|Allowed actions|Required roles|
|----|-------------|---------------|--------------|
|`read-from-any-A` |`ResourceA`    | `READ`|`a-reader`|
|`edit-any-A`      |`ResourceA`    | `EDIT`|`a-editor`|
|`all-to-any-B`    |`ResourceB`    | `ALL` |`b-reader`, `b-editor`|

### Configuring the python environment
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

### Securing a REST service (with FastAPI)
#### Overview of service endpoints
The [app](./src/app.py) module creates a `FastAPI` application with the following endpoints:
* `GET /a`: invokes `read_protected` on an instance of `ResourceA`
* `GET /b`: invokes `read_protected` on an instance of `ResourceB`
* `POST /a`: invokes `edit_protected` on an instance of `ResourceA`
* `POST /b`: invokes `edit_protected` on an instance of `ResourceB`
* `GET /` and `POST /`: invoke `unprotected` on an instance of `ResourceA` and then `ResourceB`
* `POST /do`: invoke the `do_something` method on an instance of `Orchestrator`

#### Run the insecure app
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
{
  "message": "read_A"
}

Trying POST http://localhost:8000/a
{
  "message": "edit_A"
}

Enter the service path, e.g. '/a' (RETURN to stop): /b
Trying GET http://localhost:8000/b
{
  "message": "read_B"
}

Trying POST http://localhost:8000/b
{
  "message": "edit_B"
}

Enter the service path, e.g. '/a' (RETURN to stop): /do

Trying POST http://localhost:8000/do
[
  "DONE a.read_protected()",
  "DONE b.read_protected()",
  "DONE a.edit_protected()",
  "DONE b.edit_protected()"
]

Enter the service path, e.g. '/a' (RETURN to stop): /
Trying GET http://localhost:8000/
{
  "message": "read_unprotected"
}

Trying POST http://localhost:8000/
{
  "message": "post_unprotected"
}
```

#### Run app secured by Keycloak OIDC

##### Setup Keycloak
Start Keycloak from a container image and initialize a `poc` realm with `app` client and some users:
```
make start-keycloak
make setup-keycloak
cat.env
```
The content of `.env` is used by the `OidcAuthManager` in [oidc_auth_manager](./src/auth/oidc_auth_manager.py) to:
* Validate the authentication bearer token
* Extract the user credentials and roles from the token
* Populate the `RoleManager` with the given roles for the current user with `sm.role_manager.add_roles_for_user(current_user, roles)`

Example of access token:
```
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

##### Run app with Keycloak OIDC
Use the `AUTH_MANAGER` variable to setup the OIDC authentication manager:
```console
AUTH_MANAGER=oidc make run-app
```

Test with:
```console
make run-test
```

Output example for user `a-reader` (allowed to `GET \a`):
```bash
Is it a secured service? (y/n): y
Enter your username: a-reader
Got token!

Enter the service path, e.g. '/a' (RETURN to stop): /a
Trying GET http://localhost:8000/a
{
  "message": "read_A"
}

Trying POST http://localhost:8000/a
{
  "message": "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']"
}

Enter the service path, e.g. '/a' (RETURN to stop): /b
Trying GET http://localhost:8000/b
{
  "message": "No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']"
}

Trying POST http://localhost:8000/b
{
  "message": "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']"
}

Enter the service path, e.g. '/a' (RETURN to stop): /do

Trying POST http://localhost:8000/do
[
  "DONE a.read_protected()",
  "No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']",
  "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']",
  "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']"
]
```

Output example for user `b-manager` (allowed to `GET \b` and `POST \b`):
```bash
Is it a secured service? (y/n): y
Enter your username: b-manager
Got token!

Enter the service path, e.g. '/a' (RETURN to stop): /a
Trying GET http://localhost:8000/a
{
  "message": "No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.A:a. Requires roles ['a-reader']"
}

Trying POST http://localhost:8000/a
{
  "message": "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']"
}

Enter the service path, e.g. '/a' (RETURN to stop): /b
Trying GET http://localhost:8000/b
{
  "message": "read_B"
}

Trying POST http://localhost:8000/b
{
  "message": "edit_B"
}

Enter the service path, e.g. '/a' (RETURN to stop): /do

Trying POST http://localhost:8000/do
[
  "No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.A:a. Requires roles ['a-reader']",
  "DONE b.read_protected()",
  "No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']",
  "DONE b.edit_protected()"
]
```

#### Run app secured by Kubernetes tokens
##### Architecture of KubernetesAuthManager
This authentication manager is made of two components, both running in the same cluster:
* The client invokes REST services sending the token of the associated `ServiceAccount` in the authorization bearer (*)
* The server, implemented by `KubernetesAuthManager` defined in [kubernetes_auth_manager](./src/auth/kubernetes_auth_manager.py) is in charge of:
  * Detect the `ServiceAccount` name and namespace from the JWT token
  * Identify the `Role`s and `ClusterRole`s bound to the `ServiceAccount` (**)
  * Populate the `RoleManager` with the given roles for the current user with `sm.role_manager.add_roles_for_user(current_user, roles)`

Example of decoded JWT token:
```
{
...
 'kubernetes.io': {'namespace': 'feast',
  'pod': {'name': 'feast-notebook-0'},
  'serviceaccount': {'name': 'feast-notebook'},
...
  },
...
 'sub': 'system:serviceaccount:feast:feast-notebook'
}
```
`sub` field (e.g. `subject`) identifies the `ServiceAccount` with name `feast-notebook` in namespace `feast`

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
        type: oidc
        server: 'http://0.0.0.0:8080'
        realm: 'poc'
        client-id: 'app'
        client-secret: 'mqAzX7zDalQ1a3BZRWs7Pi5JRqCq7h4z'
        username: 'username'
        password: 'password'
```
(*) **Note**: because of the need to retrieve the `ClusterRole`s, the server needs to run with a role allowing it to fetch such instances.
For now, we are using `admin ClusterRole`, but a dedicated `Role` can be revised and specifically defined.

##### Deploying the POC app in kubernetes
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
bash
cd /tmp
mkdir app
cd app
unzip ../app.zip
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Then start the server with:
```console
AUTH_MANAGER=k8s make run-app
```

A client notebook [poc-client.ipynb](./poc-client.ipynb) is provided for your convenience to run the client code.
Install it on a Notebook in the same cluster and run the test to validate that a `Forbidden` error (403) is raised when
we invoke a service wiythout having the required role.

### Securing an ArrowFlight grpc service
#### Solution overview
The proposed implementation uses an implementation of [ServerMiddlewareFactory](https://arrow.apache.org/docs/python/generated/pyarrow.flight.ServerMiddlewareFactory.html)
to intercept a request, extract the `authorization` bearer token and use the `OidcAuthManager` instance to extract the user
credentials and roles. This data is then passed to a middleware instance that can be used at the begin of the protected endpoints 
(e.g. in `do_get`) to apply the authentication context to the current thread.

Proposed implementation is in [server](./src/arrow_flight/server.py) and [middleware](./src/arrow_flight/middleware.py) modules.

#### Overview of service endpoints
The [server](./src/arrow_flight/server.py) module creates an `ArrowFlight` application with the following endpoints:
* `do_get`: given a command including a JSON payload like:
```json
{
  "resource": "A",
  "api": "read",
}
```

it invokes the requested `api` on a new instance of the given `resource` type
* `do_put`, `do_action`: not implemented

#### Run the insecure app
```console
AUTH_MANAGER="" make run-arrow-server
```

Follow the interactive instructions and test with:
```console
AUTH_MANAGER="" make run-arrow-client
```

Output example (all services are allowed, there is no current user in place):
```bash
*** Trying read on AuthzedResourceType.A
{
    "name": "AuthzedResourceType.A:a",
    "message": "read"
}
*** Trying edit on AuthzedResourceType.A
{
    "name": "AuthzedResourceType.A:a",
    "message": "edit"
}
*** Trying read on AuthzedResourceType.B
{
    "name": "AuthzedResourceType.B:b",
    "message": "read"
}
*** Trying edit on AuthzedResourceType.B
{
    "name": "AuthzedResourceType.B:b",
    "message": "edit"
}
```

##### Run app with Keycloak OIDC
Use the `AUTH_MANAGER` variable to setup the OIDC authentication manager:
```console
AUTH_MANAGER="oidc" make run-arrow-server
```

Test with:
```console
AUTH_MANAGER="oidc" make run-arrow-client
```

Output example for user `a-reader` (allowed to read from A):
```bash
Please enter the user name: a-reader
Got token for a-reader
*** Trying read on AuthzedResourceType.A
{
    "name": "AuthzedResourceType.A:a",
    "message": "read"
}
*** Trying edit on AuthzedResourceType.A
No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']
*** Trying read on AuthzedResourceType.B
No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']
*** Trying edit on AuthzedResourceType.B
No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.B:b. Requires roles ['b-reader', 'b-editor']
```

Output example for user `b-manager` (allowed to read and edit from B):
```bash
Please enter the user name: b-manager
Got token for b-manager
*** Trying read on AuthzedResourceType.A
No permissions to execute [<AuthzedAction.READ: 'read'>] on AuthzedResourceType.A:a. Requires roles ['a-reader']
*** Trying edit on AuthzedResourceType.A
No permissions to execute [<AuthzedAction.EDIT: 'edit'>] on AuthzedResourceType.A:a. Requires roles ['a-editor']
*** Trying read on AuthzedResourceType.B
{
    "name": "AuthzedResourceType.B:b",
    "message": "read"
}
*** Trying edit on AuthzedResourceType.B
{
    "name": "AuthzedResourceType.B:b",
    "message": "edit"
}
```

## What's next-Possible extensions
* The proposed Security Model is meant to define the policies to permit the execution of given actions on the selected resources.
  Do we also need a policy to deny the execution instead, based on the same selection criteria? E.g. do we need a `decision` field to model
  the behavior?
```py
    Permission(
        name="deny-from-any-A",
        decision=PermissionDecision.DENY
        resources=[AuthzedResource(type=AuthzedResourceType.A)],
        policies=[RoleBasedPolicy(roles=["basic-user"])],
        actions=[AuthzedAction.ALL],
    )
```
* Given a request to execute an action on a protected resource, we may have multiple permissions matching a resource instance (by type
  and additional name and tags filters). What is the behavior of the permission authorization in this case? Do we need another `decision_strategy`
  field at global level that can be used in the feature store configuration to dictate the behavior?
```py
    permission.set_global_decision_strategy(DecisionStrategy.UNANIMOUS)
```
