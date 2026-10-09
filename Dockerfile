# Single-stage build: Python slim base, install deps, copy app source,
# serve with uvicorn. No multi-stage split since this is a small FastAPI
# service, not a compiled/bundled artifact.
FROM python:3.11-slim

WORKDIR /app

# Copied and installed separately from the rest of the source so Docker's
# layer cache can skip the (slow) pip install step on rebuilds that only
# change application code, not dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Runs main.py's FastAPI `app` object directly with uvicorn; --host 0.0.0.0
# is required for the port to be reachable from outside the container.
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
