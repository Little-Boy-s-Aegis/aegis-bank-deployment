FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY parser.py .
COPY classifier.py .
COPY llm_agent.py .

ENTRYPOINT ["python", "parser.py"]
