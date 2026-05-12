param(
    [Parameter(Position = 0)]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"

switch ($Command) {
    "check-apis" {
        docker compose exec backend python /app/apis/healthcheck.py
    }
    "check-lab" {
        docker compose exec backend python /app/apis/lab_healthcheck.py
    }
    "check-rag" {
        docker compose exec backend python /app/memory/healthcheck.py
    }
    "check-max" {
        docker compose exec backend python /app/agents/max/healthcheck.py
    }
    "check-leo" {
        docker compose exec backend python /app/agents/leo/healthcheck.py
    }
    "check-vera" {
        docker compose exec backend python /app/agents/vera/healthcheck.py
    }
    "check-finn" {
        docker compose exec backend python /app/agents/finn/healthcheck.py
    }
    "check-ops" {
        docker compose exec backend python /app/agents/ops/healthcheck.py
    }
    "check-tasks" {
        docker compose exec backend python /app/tasks/healthcheck.py
    }
    "check-all" {
        docker compose exec backend python /app/db/healthcheck.py
        docker compose exec backend python /app/llm/healthcheck.py
        docker compose exec backend python /app/agents/finn/healthcheck.py
        docker compose exec backend python /app/agents/aria/healthcheck.py
        docker compose exec backend python /app/agents/max/healthcheck.py
        docker compose exec backend python /app/agents/leo/healthcheck.py
        docker compose exec backend python /app/agents/vera/healthcheck.py
        docker compose exec backend python /app/agents/ops/healthcheck.py
        docker compose exec backend python /app/apis/healthcheck.py
        docker compose exec backend python /app/memory/healthcheck.py
        docker compose exec backend python /app/tasks/healthcheck.py
    }
    "help" {
        Write-Host "Usage: .\run.ps1 <command>"
        Write-Host "  check-apis  Run NexaBank API vulnerability smoke checks inside the backend container."
        Write-Host "  check-lab   Run lab panel API smoke checks (scenarios, flags, telemetry, progress)."
        Write-Host "  check-rag   Run RAG pipeline healthcheck inside the backend container."
        Write-Host "  check-max   Run Max fraud agent healthcheck inside the backend container."
        Write-Host "  check-leo   Run Leo loan agent healthcheck inside the backend container."
        Write-Host "  check-vera  Run Vera KYC verification agent healthcheck inside the backend container."
        Write-Host "  check-finn  Run Finn financial advisor agent healthcheck inside the backend container."
        Write-Host "  check-ops   Run Ops internal IT agent healthcheck inside the backend container."
        Write-Host "  check-tasks Run Celery task + Beat schedule healthcheck inside the backend container."
        Write-Host "  check-all   Run all backend healthchecks in sequence."
    }
    default {
        Write-Host "Unknown command: $Command"
        exit 1
    }
}
