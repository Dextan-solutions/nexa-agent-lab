# Contributing to NexaBank Agent Security Lab

Thank you for helping improve a deliberately vulnerable training platform. Keep changes focused, documented, and covered by the existing healthcheck pattern.

The open-source repository is **nexa-agent-lab** on GitHub; the product name is **NexaBank Agent Security Lab**.

## Git commits

- Use plain commits only: `git commit -m "your message here"`.
- Do **not** add `--trailer "Co-authored-by: Cursor <cursoragent@cursor.com>"` or other Co-authored-by trailers unless a maintainer explicitly requests it for a specific merge.

From the repository root (where `.git` lives), you can optionally enforce stripping of any accidental Cursor trailer:

```bash
git config core.hooksPath .githooks
```

## Repository layout

Application code runs under `/app` inside the backend container. Import paths are flat (`db`, `agents`, `llm`, `tools`, …). Do not introduce a nested `backend/` package or manipulate `sys.path`.

## How to add a new agent

1. Copy `backend/agents/aria/` as a template directory (graph, tools, manifests).
2. Implement the agent class by subclassing `BaseAgent` and filling in required methods.
3. Create **four** `VulnerabilityManifest` objects (one per difficulty).
4. Add your agent key to `backend/config/security_levels.yaml` (follow existing agent blocks).
5. Add `backend/agents/<name>/healthcheck.py` following existing agents (tool list, manifest count, LOW exploit, SECURE non-exploit).
6. Register a Celery task in `backend/tasks/__init__.py` and route it in `backend/celery_app.py` if it needs a dedicated queue.
7. Run **`make check-all`** inside a running Compose stack; **all healthchecks must pass** before opening a PR.

## How to add a vulnerability scenario

1. Add or extend a `VulnerabilityManifest` on an existing agent.
2. Implement flag detection in the agent’s `_compute_flag()` (or equivalent) so the lab can record captures.
3. Add assertions to that agent’s `healthcheck.py` (and API checks in `apis/healthcheck.py` if HTTP surfaces change).
4. Update `backend/config/security_levels.yaml` for the new scenario and affected levels.

## Verification (Docker only)

Do not rely on host Python against `backend/` for verification — dependencies and `PYTHONPATH` match the container.

```bash
docker compose exec backend python /app/agents/<agent>/healthcheck.py
```

Makefile targets such as `check-aria`, `check-apis`, and `make check-all` wrap these commands.

## Code standards

- Format Python with **Black**.
- Use **type hints** on all new or touched functions.
- **No `sys.path` manipulation.**
- Prefer small, explicit changes over drive-by refactors.

## License

By contributing, you agree your contributions are licensed under the same terms as the project (MIT).
