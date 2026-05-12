FROM python:3.11-slim

WORKDIR /app

# PYTHONSAFEPATH: avoid prepending the script dir (e.g. /app/agents/max) ahead of PYTHONPATH,
# which would make `tools` resolve to agents/max/tools.py instead of the /app/tools package.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PYTHONSAFEPATH=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

# Build-time guard: fail if nested backend/ or duplicate module roots exist.
RUN test ! -d /app/backend || (echo "ERROR: duplicate backend folder still exists" >&2 && exit 1)
RUN python -c "import pathlib, sys; import db.sqlite; \
  dup = pathlib.Path('/app/backend/db/sqlite.py'); \
  (print('ERROR: duplicate module roots detected', file=sys.stderr) or sys.exit(1)) if dup.is_file() else None; \
  print('Module structure: OK')"

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

