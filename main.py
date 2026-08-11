```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import os

app = FastAPI()

WORKSPACE = "prod-t0mczs"

REQUIRED_LABELS = {
    "owner": "student-g2mgc",
    "environment": "production",
    "cost_center": "cc-aftn",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
ALLOWED_ACTIONS = {"create", "update", "delete"}
DESTRUCTIVE_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}


def result(decision: str, reason: str):
    return {"decision": decision, "reason": reason}


def is_bool(value):
    # bool must be an actual JSON boolean, not 0/1 or a string.
    return type(value) is bool


def is_string(value):
    return type(value) is str


@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    # JSON/body/type validation
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if type(body) is not dict:
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    # Top-level fields must have the required types.
    if not is_string(body.get("environment")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if type(body.get("state")) is not dict:
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if not is_string(body.get("providerVersion")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if not is_bool(body.get("destroyApproved")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    resource = body.get("resource")
    if type(resource) is not dict:
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    # State types
    state = body["state"]

    if not is_string(state.get("backend")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if not is_bool(state.get("locked")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    # Resource types
    if not is_string(resource.get("address")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if not is_string(resource.get("type")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if not is_string(resource.get("action")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if type(resource.get("labels")) is not dict:
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    # secret is null or string
    secret = resource.get("secret")
    if secret is not None and not is_string(secret):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    if not is_bool(resource.get("forceDestroy")):
        return JSONResponse(
            status_code=200,
            content=result("reject", "INVALID_PLAN")
        )

    # Every label value must be a string.
    for key, value in resource["labels"].items():
        if not is_string(key) or not is_string(value):
            return JSONResponse(
                status_code=200,
                content=result("reject", "INVALID_PLAN")
            )

    # ---------------------------------------------------------
    # POLICY RULES — MUST STAY IN THIS ORDER
    # ---------------------------------------------------------

    # 1. Environment
    if body["environment"] != WORKSPACE:
        return JSONResponse(
            status_code=200,
            content=result("reject", "ENVIRONMENT_MISMATCH")
        )

    # 2. State safety
    if (
        state["backend"] not in ALLOWED_BACKENDS
        or state["locked"] is not True
    ):
        return JSONResponse(
            status_code=200,
            content=result("reject", "STATE_UNSAFE")
        )

    # 3. Provider pinning
    provider = body["providerVersion"]

    provider_ok = (
        provider in {"6.2.1", "= 6.2.1"}
        or provider == "~> 6.0"
    )

    if not provider_ok:
        return JSONResponse(
            status_code=200,
            content=result("reject", "UNPINNED_PROVIDER")
        )

    # 4. Required labels
    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return JSONResponse(
                status_code=200,
                content=result("reject", "MISSING_LABELS")
            )

    # 5. Secret handling
    #
    # Valid:
    #   null
    #   secret://anything-non-empty
    #
    # Invalid:
    #   ""
    #   "password"
    #   "my-secret"
    #   "plaintext..."
    if secret is not None:
        if not secret.startswith("secret://") or len(secret) <= len("secret://"):
            return JSONResponse(
                status_code=200,
                content=result("reject", "PLAINTEXT_SECRET")
            )

    # 6. Destructive delete approval
    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_TYPES
        and body["destroyApproved"] is not True
    ):
        return JSONResponse(
            status_code=200,
            content=result("reject", "DELETE_NOT_APPROVED")
        )

    # 7. Production storage bucket force-destroy
    if (
        resource["type"] == "storage_bucket"
        and labels.get("environment") == "production"
        and resource["forceDestroy"] is True
    ):
        return JSONResponse(
            status_code=200,
            content=result("reject", "FORCE_DESTROY")
        )

    # Everything passed.
    return JSONResponse(
        status_code=200,
        content=result("approve", "APPROVE")
    )


@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
```
