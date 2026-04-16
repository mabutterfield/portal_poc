FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8443

# Single worker — in-memory auth_state dict must be consistent.
# Threads handle concurrent requests safely (GIL protects dict ops).
CMD ["gunicorn", \
     "--certfile=/certs/portal.crt", \
     "--keyfile=/certs/portal.key", \
     "--bind", "0.0.0.0:8443", \
     "--workers", "1", \
     "--threads", "4", \
     "--timeout", "30", \
     "--log-level", "info", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
