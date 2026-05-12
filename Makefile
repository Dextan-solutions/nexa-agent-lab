up:
	docker compose up --build

up-ollama:
	docker compose --profile ollama up --build

down:
	docker compose down

fresh:
	docker compose down -v
	docker compose up --build

fresh-ollama:
	docker compose down -v
	docker compose --profile ollama up --build

logs:
	docker compose logs --tail=50

logs-init:
	docker compose logs db-init

logs-worker:
	docker compose logs worker --tail=50

shell-backend:
	docker compose exec backend sh

check-db:
	docker compose exec backend python /app/db/healthcheck.py

check-provider:
	docker compose exec backend python /app/llm/healthcheck.py

check-aria:
	docker compose exec backend python /app/agents/aria/healthcheck.py

check-apis:
	docker compose exec backend python /app/apis/healthcheck.py

check-rag:
	docker compose exec backend python /app/memory/healthcheck.py

check-max:
	docker compose exec backend python /app/agents/max/healthcheck.py

check-leo:
	docker compose exec backend python /app/agents/leo/healthcheck.py

check-vera:
	docker compose exec backend python /app/agents/vera/healthcheck.py

check-finn:
	docker compose exec backend python /app/agents/finn/healthcheck.py

check-ops:
	docker compose exec backend python /app/agents/ops/healthcheck.py

check-tasks:
	docker compose exec backend python /app/tasks/healthcheck.py

check-lab:
	docker compose exec backend python /app/apis/lab_healthcheck.py

check-all:
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

test:
	docker compose exec backend python -m pytest tests/ -v

status:
	docker compose ps -a

