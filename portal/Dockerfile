FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 443

# Gunicorn serves the app directly over TLS.
# Certs are expected at /certs/portal.crt and /certs/portal.key
# (mounted from host via docker-compose volume)
CMD ["gunicorn", \
     "--certfile=/certs/portal.crt", \
     "--keyfile=/certs/portal.key", \
     "--bind", "0.0.0.0:443", \
     "--workers", "2", \
     "--timeout", "30", \
     "--log-level", "info", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
