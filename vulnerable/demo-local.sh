#!/bin/sh
set -e
cd "$(dirname "$0")"
export FLAG_FILE="$(pwd)/flag.txt"
export PORT="${PORT:-5000}"

if [ ! -f "$FLAG_FILE" ]; then
  echo "FLAG{example_placeholder_change_me}" > "$FLAG_FILE"
fi

exec python3 app.py
