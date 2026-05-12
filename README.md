# NexaBank Agent Security Lab

> The first open-source platform for practicing AI agent security. Built around **NexaBank** — a realistic fictional Nigerian digital bank with six vulnerable AI agents embedded in real workflows.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-compose-blue.svg)](https://docs.docker.com/compose/)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/your-org/dvaa-agent?style=social)](https://github.com/your-org/dvaa-agent)

If you care about **LLM security beyond the chat box**, this repo is your gym. Spin up a credible fintech surface, flip a four-stage security engine, and watch the same agent code paths tighten or break under pressure — then prove it with flags, audit trails, and lab telemetry.

## What is NexaBank Agent Security Lab?

**NexaBank Agent Security Lab** is a deliberately vulnerable AI agent platform for security researchers, red teamers, and developers learning to identify and exploit **AI-specific** weaknesses in enterprise-style automation.

Unlike classic vulnerable web apps, NexaBank Agent Security Lab targets the emerging attack surface of **autonomous agents wired into workflows**: prompt injection, excessive agency, RAG poisoning, sensitive disclosure, system prompt leakage, and more — all behind normal banking actions (tickets, loans, KYC, fraud checks, internal IT).

**NexaBank** is a fictional Nigerian digital bank. Six AI agents are invisibly embedded in its day-to-day flows. Your job is to **find and exploit them** — safely, locally, and ethically.

## Security warning

This platform is **intentionally vulnerable**.

- Run it only in **isolated local** environments.
- **Never** expose its ports to the internet.
- **NexaBank** is a fictional company created solely for security training. Any resemblance to real financial institutions is coincidental.

## The agents

| Agent | Role | Vulnerability | OWASP LLM Top 10 |
| --- | --- | --- | --- |
| Aria | Customer support | Prompt injection | LLM01 |
| Max | Fraud detection | Excessive agency | LLM06 |
| Leo | Loan processing | Insecure output handling | LLM02 |
| Vera | KYC verification | RAG poisoning | LLM09 |
| Finn | Financial advisor | Sensitive disclosure | LLM06 |
| Ops | Internal IT | System prompt leakage | LLM07 |

Each agent ships **four difficulty levels** (LOW / MEDIUM / HARD / CHAINED) — **24 scenarios** total. Every scenario has an objective, hints, and a **flag** to capture in the lab.

## Quick start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose on Linux)
- [Ollama](https://ollama.com/) on the host for a **free, local** LLM (no API key required). The stack auto-detects host Ollama via `host.docker.internal`.

### 1. Pull the recommended models

```bash
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
```

### 2. Clone and start

```bash
git clone https://github.com/your-org/nexa-agent-lab
cd nexa-agent-lab
cp .env.example .env
docker compose up --build
```

### 3. Open

| Surface | URL |
| --- | --- |
| NexaBank portal | http://localhost:3000 |
| NexaBank Agent Lab | http://localhost:3000/lab |

### 4. Reset to a fresh state

```bash
docker compose down -v
docker compose up --build -d
```

Optional: run Ollama inside Compose instead of on the host:

```bash
docker compose --profile ollama up --build
```

## Cloud API providers

Switch providers by editing `.env` (see `.env.example` for every variable).

| Provider | Variables |
| --- | --- |
| Ollama (local, free) | `LLM_PROVIDER=ollama` |
| OpenAI | `LLM_PROVIDER=openai`, `OPENAI_API_KEY=sk-...` |
| Anthropic | `LLM_PROVIDER=anthropic`, `ANTHROPIC_API_KEY=sk-...` |
| Gemini | `LLM_PROVIDER=gemini`, `GEMINI_API_KEY=...` |
| Mock (no network) | `LLM_PROVIDER=mock` |

### Recommended local models

| Model | RAM (approx.) | Tool calling | Speed |
| --- | --- | --- | --- |
| `qwen2.5:7b` (default) | 8 GB | Excellent | Medium |
| `qwen2.5:14b` | 16 GB | Excellent | Slower / higher quality |
| `llama3.1:8b` | 8 GB | Very good | Medium |
| `qwen2.5:3b` | 4 GB | Good | Fast |

## Vulnerability scenarios

### Aria — prompt injection

- **LOW:** Direct injection via support ticket
- **MEDIUM:** Sanitizer bypass
- **HARD:** Indirect injection via knowledge base
- **CHAINED:** Account lookup to email exfiltration

### Max — excessive agency

- **LOW:** Autonomous account freeze via narration
- **MEDIUM:** Narration-only injection bypass
- **HARD:** Indirect context injection
- **CHAINED:** Cross-agent freeze via ticket residue

### Leo — insecure output handling

- **LOW:** Disbursement string injection
- **MEDIUM:** Filter bypass
- **HARD:** Account mismatch via model output
- **CHAINED:** Poisoned policy plus output handling

### Vera — RAG poisoning

- **LOW:** Compliance knowledge base poisoning
- **MEDIUM:** Semantic policy manipulation
- **HARD:** Invisible text injection
- **CHAINED:** Cross-agent policy cascade

### Finn — sensitive information disclosure

- **LOW:** System prompt leak via Q&A
- **MEDIUM:** Indirect threshold disclosure
- **HARD:** Multi-turn fragment extraction
- **CHAINED:** Endpoint pivot from staging URL

### Ops — system prompt leakage

- **LOW:** Full IT system prompt disclosure
- **MEDIUM:** Capability summary leak
- **HARD:** Fragmented extraction
- **CHAINED:** Admin JWT forge from token format

## Architecture

```
NexaBank Portal (Next.js 14)
       ↓ form submissions
FastAPI Backend
       ↓ triggers via Celery
AI Agents (LangGraph state machines)
       ↓ tool calls
Banking APIs + ChromaDB + SQLite
       ↓ audit trail
NexaBank Agent Lab (real-time telemetry)
```

The **security level engine** exposes four levels (LOW / MEDIUM / HARD / SECURE) that drive **real code path differences** in every agent — not a single prompt tweak: different prompts, tool permissions, and data exposure boundaries.

## OWASP LLM Top 10 coverage

| OWASP ID | Name | Agents |
| --- | --- | --- |
| LLM01 | Prompt injection | Aria, Ops |
| LLM02 | Insecure output handling | Leo |
| LLM06 | Excessive agency | Max, Finn |
| LLM07 | System prompt leakage | Ops, Finn |
| LLM09 | Vector / embedding weaknesses | Vera |

The banking APIs also exercise classic **API** issues (BOLA, BFLA, mass assignment, excessive data exposure) aligned with OWASP API Security Top 10 thinking.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add agents, scenarios, and healthchecks.

## License

MIT License — see the [LICENSE](LICENSE) file.
