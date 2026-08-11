from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Assigned production workspace
WORKSPACE = "prod-t0mczs"

# Required cost-ownership labels
REQUIRED_LABELS = {
    "owner": "student-g2mgc",
    "environment": "production",
    "cost_center": "cc-aftn",
}

# Allowed Terraform remote-state backends
ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

# Resource types for which deletion requires approval
DESTRUCTIVE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def reject(reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "decision": "reject",
            "reason": reason,
        },
    )


def approve():
    return JSONResponse(
        status_code=200,
        content={
            "decision": "approve",
            "reason": "APPROVE",
        },
    )


def is_string(value):
    return type(value) is str


def is_bool(value):
    return type(value) is bool


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    # =========================================================
    # RULE 1: Request and nested objects must have shown types
    # =========================================================

    try:
        body = await request.json()
    except Exception:
        return reject("INVALID_PLAN")

    if type(body) is not dict:
        return reject("INVALID_PLAN")

    # Top-level types
    if not is_string(body.get("environment")):
        return reject("INVALID_PLAN")

    if type(body.get("state")) is not dict:
        return reject("INVALID_PLAN")

    if not is_string(body.get("providerVersion")):
        return reject("INVALID_PLAN")

    if not is_bool(body.get("destroyApproved")):
        return reject("INVALID_PLAN")

    if type(body.get("resource")) is not dict:
        return reject("INVALID_PLAN")

    state = body["state"]
    resource = body["resource"]

    # State types
    if not is_string(state.get("backend")):
        return reject("INVALID_PLAN")

    if not is_bool(state.get("locked")):
        return reject("INVALID_PLAN")

    # Resource types
    if not is_string(resource.get("address")):
        return reject("INVALID_PLAN")

    if not is_string(resource.get("type")):
        return reject("INVALID_PLAN")

    if not is_string(resource.get("action")):
        return reject("INVALID_PLAN")

    if type(resource.get("labels")) is not dict:
        return reject("INVALID_PLAN")

    if not is_bool(resource.get("forceDestroy")):
        return reject("INVALID_PLAN")

    # secret may be null or string
    secret = resource.get("secret")

    if secret is not None and not is_string(secret):
        return reject("INVALID_PLAN")

    # Label keys and values must be strings
    for key, value in resource["labels"].items():
        if not is_string(key) or not is_string(value):
            return reject("INVALID_PLAN")

    # =========================================================
    # RULE 2: Environment must exactly match workspace
    # =========================================================

    if body["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # =========================================================
    # RULE 3: State must be a supported backend and locked
    # =========================================================

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # =========================================================
    # RULE 4: Provider must be pinned
    #
    # Accepted:
    #   6.2.1
    #   = 6.2.1
    #   ~> 6.0
    #
    # Rejected:
    #   >= 6.0
    #   *
    #   latest
    # =========================================================

    provider = body["providerVersion"]

    if provider not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return reject("UNPINNED_PROVIDER")

    # =========================================================
    # RULE 5: Required labels must have exact values
    # =========================================================

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return reject("MISSING_LABELS")

    # =========================================================
    # RULE 6: Secret must be null or non-empty secret:// reference
    # =========================================================

    if secret is not None:

        if not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

        # "secret://" alone is not a valid non-empty reference
        if len(secret) <= len("secret://"):
            return reject("PLAINTEXT_SECRET")

    # =========================================================
    # RULE 7: Destructive deletes require approval
    # =========================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_TYPES
    ):
        if body["destroyApproved"] is not True:
            return reject("DELETE_NOT_APPROVED")

    # =========================================================
    # RULE 8: Production storage bucket cannot force destroy
    # =========================================================

    if (
        resource["type"] == "storage_bucket"
        and labels.get("environment") == "production"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # =========================================================
    # ALL CHECKS PASSED
    # =========================================================

    return approve()


@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "terraform-policy",
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
    }
