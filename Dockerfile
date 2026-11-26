# Hauseigenes Basisbild (docker/basis-image, ZIELBILD 46 B3): python:3.13-slim mit der
# Upgrade-Schicht, jede Nacht frisch gebaut. Ein Bau mit --pull holt den Stand der Nacht.
FROM 127.0.0.1:5000/homelab/python:3.13

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

RUN useradd -m -u 1000 service && chown -R service:service /app
USER service

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
