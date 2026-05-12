import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agents.aria.agent import AriaAgent
from agents.base_agent import AgentTrigger, SecurityLevel, WorkflowName
from apis.accounts import router as accounts_router
from apis.admin import router as admin_router
from apis.auth import router as auth_router
from apis.financial import router as financial_router
from apis.lab import router as v1_lab_router
from apis.internal import router as internal_router
from apis.kyc import router as kyc_router
from apis.loans import router as loans_router
from apis.staff import router as staff_router
from apis.tickets import router as tickets_router
from apis.transactions import router as transactions_router
from config.security_level_store import security_level_store
from config.settings import settings
from gateway.logger import audit_middleware
from gateway.rate_limiter import rate_limit_middleware
from gateway.router import router as gateway_router
from lab.router import router as lab_router
from llm.ollama_provider import resolve_ollama_url, validate_ollama_models

logger = logging.getLogger(__name__)

app = FastAPI(title="NexaBank Agent Security Lab API", version="0.0.0")

@app.on_event("startup")
async def _startup_checks() -> None:
    security_level_store.set(SecurityLevel.low)
    # Prefer host machine Ollama when available.
    if (settings.llm_provider or "").strip().lower() == "ollama":
        try:
            url = await resolve_ollama_url()
            await validate_ollama_models(url)
        except Exception as e:  # noqa: BLE001
            logger.error("Ollama startup validation failed: %s", e)
            raise SystemExit(1) from e

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(rate_limit_middleware)
app.middleware("http")(audit_middleware)

app.include_router(gateway_router)
app.include_router(lab_router)
app.include_router(v1_lab_router)
app.include_router(auth_router)
app.include_router(accounts_router)
app.include_router(transactions_router)
app.include_router(loans_router)
app.include_router(kyc_router)
app.include_router(tickets_router)
app.include_router(financial_router)
app.include_router(staff_router)
app.include_router(admin_router)
app.include_router(internal_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


class SupportTicketIn(BaseModel):
    customer_id: str = Field(min_length=3)
    subject: str = Field(min_length=3, max_length=120)
    message: str = Field(min_length=1, max_length=8000)


@app.post("/api/support/tickets")
async def create_support_ticket(body: SupportTicketIn, request: Request) -> dict:
    agent = AriaAgent()
    trigger = AgentTrigger(
        workflow=WorkflowName.support_ticket,
        actor_id=request.headers.get("x-actor-id", body.customer_id),
        request_id=request.headers.get("x-request-id", str(uuid.uuid4())),
        metadata={"source": "portal_form"},
    )
    result = await agent.run(
        trigger=trigger,
        payload={"subject": body.subject, "message": body.message},
        security_level=security_level_store.get().level,
    )
    return {"ok": True, "result": result.output, "flag": result.flag}

