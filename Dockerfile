# ---------------------------
# Stage 1: Builder
# ---------------------------
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------
# Stage 2: Runtime
# ---------------------------
FROM python:3.12-slim

ENV TZ=UTC
WORKDIR /app

# Install cron and timezone data
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder (site-packages path may vary)
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application files
COPY . /app

# Install cron job (ensure cron/seed.cron exists)
RUN chmod 0644 /cron/seed.cron || true && crontab /cron/seed.cron || true

# Create mount points
RUN mkdir -p /data /cron && chmod 755 /data /cron

EXPOSE 8080

# Start cron and the Flask app (development server; OK for testing)
CMD service cron start && python app.py --host 0.0.0.0 --port 8080
