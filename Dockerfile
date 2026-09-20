FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY domains.txt .

RUN mkdir -p /data

ENV DOMAINS_FILE=/app/domains.txt
ENV STATE_FILE=/data/status.json

CMD ["python", "/app/app/monitor.py"]
