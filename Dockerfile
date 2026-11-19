FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client ca-certificates tzdata && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 --create-home appuser
COPY server.py schema.sql index.html portal.html setup.html manifest.json sw.js apple-touch-icon.png favicon.ico backup.py restore_archive.py reset_admin_password.py ./
COPY static ./static
RUN mkdir -p /app/uploads /backups && chown -R appuser:appuser /app /backups
USER appuser
EXPOSE 8000
CMD ["gunicorn", "--worker-class", "gthread", "--workers", "1", "--threads", "36", "--timeout", "1800", "--bind", "0.0.0.0:8000", "server:app"]
