#!/bin/sh
set -e

FLAG_PATH="${FLAG_FILE:-/flag.txt}"
FLAG="${FLAG:-FLAG{example_placeholder_change_me}}"

echo "$FLAG" > "$FLAG_PATH"
chmod 644 "$FLAG_PATH"

exec gosu appuser gunicorn \
  --bind 0.0.0.0:5000 \
  --workers 2 \
  --threads 4 \
  --timeout 30 \
  app:app
