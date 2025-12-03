#!/bin/sh
# entrypoint.sh - start cron and gunicorn

# start cron in background
service cron start

# ensure /cron exists for logs
mkdir -p /cron

# start gunicorn serving app: use 4 workers
exec gunicorn --bind 0.0.0.0:8080 --workers 4 --threads 2 app:app
