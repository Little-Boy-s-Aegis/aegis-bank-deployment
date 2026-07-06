FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code files
COPY main.py .
COPY config.py .
COPY schema_validator.py .
COPY db_verifier.py .
COPY orchestrator.py .
COPY playbook_executor.py .

ENTRYPOINT ["python", "main.py"]
