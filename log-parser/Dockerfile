FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY parser.py .
COPY classifier.py .
COPY llm_agent.py .
COPY event_schema.py .
COPY static_rules.py .
COPY threshold_rules.py .
COPY agent_routing_rules.json .

ENTRYPOINT ["python", "parser.py"]
