from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from impl import ResourceA, ResourceB
from auth import inject_user_data
from orchestator import Orchestrator
from security.security_manager import _get_security_manager

app = FastAPI()


@app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError):
    """
    Exception handler to transform PermissionError exceptions into HTTP 403 Forbidden responses,
    including the original error message in the response.
    """
    print(f"permission_error_handler {exc}")
    return JSONResponse(
        status_code=403,
        content={"message": f"{exc}"},
    )


app.add_exception_handler(PermissionError, permission_error_handler)


a = ResourceA("a", [])
b = ResourceB("b", [])


@app.get("/")
async def read_unprotected():
    a.unprotected()
    b.unprotected()
    return {"message": "read_unprotected"}


@app.get("/a", dependencies=[Depends(inject_user_data)])
async def read_A():
    a.read_protected()

    return {"message": "read_A"}


@app.get("/b", dependencies=[Depends(inject_user_data)])
async def read_B():
    b.read_protected()
    return {"message": "read_B"}


@app.post("/")
async def post_unprotected():
    a.unprotected()
    b.unprotected()
    return {"message": "post_unprotected"}


@app.post("/a", dependencies=[Depends(inject_user_data)])
async def edit_A():
    a.edit_protected()
    return {"message": "edit_A"}


@app.post("/b", dependencies=[Depends(inject_user_data)])
async def edit_B():
    b.edit_protected()
    return {"message": "edit_B"}


@app.post("/do", dependencies=[Depends(inject_user_data)])
async def do_something():
    orchestrator = Orchestrator(_get_security_manager())

    messages = orchestrator.do_something(a, b)
    return messages
