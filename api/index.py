from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

WORKSPACE = "prod-t0mczs"

REQUIRED_LABELS = {
    "owner": "student-g2mgc",
    "environment": "production",
    "cost_center": "cc-aftn",
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

ALLOWED_ACTIONS = {
    "create",
    "update",
    "delete",
}

DESTRUCTIVE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def response(decision, reason):
    return JSONResponse(
        status_code=200,
        content={
            "decision": decision,
            "reason": reason,
        },
    )


def reject(reason):
    return response("reject", reason)


def approve():
    return response("approve", "APPROVE")


def is_string(value):
    return type(value) is str


def is_bool(value):
    return type(value) is bool


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    # =========================================================
    # 1. SCHEMA / TYPE VALIDATION
    # =========================================================

    # Valid JSON object required.
    try:
        body = await request.json()
    except Exception:
        return reject("INVALID_PLAN")

    if type(body) is not dict:
        return reject("INVALID_PLAN")

    # Required top-level fields.
    required_top_level = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top_level.issubset(body.keys()):
        return reject("INVALID_PLAN")

    # Top-level types.
    if not is_string(body["environment"]):
        return reject("INVALID_PLAN")

    if type(body["state"]) is not dict:
        return reject("INVALID_PLAN")

    if not is_string(body["providerVersion"]):
        return reject("INVALID_PLAN")

    if not is_bool(body["destroyApproved"]):
        return reject("INVALID_PLAN")

    if type(body["resource"]) is not dict:
        return reject("INVALID_PLAN")

    state = body["state"]
    resource = body["resource"]

    # ---------------------------------------------------------
    # State schema
    # ---------------------------------------------------------

    required_state = {
        "backend",
        "locked",
    }

    if not required_state.issubset(state.keys()):
        return reject("INVALID_PLAN")

    if not is_string(state["backend"]):
        return reject("INVALID_PLAN")

    if not is_bool(state["locked"]):
        return reject("INVALID_PLAN")

    # ---------------------------------------------------------
    # Resource schema
    # ---------------------------------------------------------

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return reject("INVALID_PLAN")

    if not is_string(resource["address"]):
        return reject("INVALID_PLAN")

    if not is_string(resource["type"]):
        return reject("INVALID_PLAN")

    if not is_string(resource["action"]):
        return reject("INVALID_PLAN")

    if resource["action"] not in ALLOWED_ACTIONS:
        return reject("INVALID_PLAN")

    if type(resource["labels"]) is not dict:
        return reject("INVALID_PLAN")

    if not is_bool(resource["forceDestroy"]):
        return reject("INVALID_PLAN")

    # secret must be either null or a string.
    secret = resource["secret"]

    if secret is not None and not is_string(secret):
        return reject("INVALID_PLAN")

    # Label keys and values must be strings.
    for key, value in resource["labels"].items():
        if not is_string(key):
            return reject("INVALID_PLAN")

        if not is_string(value):
            return reject("INVALID_PLAN")

    # =========================================================
    # 2. ENVIRONMENT
    # =========================================================

    if body["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # =========================================================
    # 3. STATE SAFETY
    # =========================================================

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # =========================================================
    # 4. PROVIDER PINNING
    # =========================================================

    provider = body["providerVersion"]

    if provider not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return reject("UNPINNED_PROVIDER")

    # =========================================================
    # 5. REQUIRED LABELS
    # =========================================================

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return reject("MISSING_LABELS")

    # =========================================================
    # 6. SECRET PROTECTION
    # =========================================================

    if secret is not None:

        # Must begin with secret://
        if not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

        # secret:// alone is not a valid non-empty reference.
        if len(secret) == len("secret://"):
            return reject("PLAINTEXT_SECRET")

    # =========================================================
    # 7. DELETE APPROVAL
    # =========================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_TYPES
    ):
        if body["destroyApproved"] is not True:
            return reject("DELETE_NOT_APPROVED")

    # =========================================================
    # 8. FORCE DESTROY
    # =========================================================

    if (
        resource["type"] == "storage_bucket"
        and labels.get("environment") == "production"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # =========================================================
    # APPROVED
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
