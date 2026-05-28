#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Reuse the hik project's venv (has FastAPI? let's install if needed)
VENV=/mnt/agent/hikvision_e2e/venv

if [ ! -x "$VENV/bin/python3" ]; then
    echo "venv missing — run: python3 -m venv $VENV" >&2
    exit 1
fi

"$VENV/bin/python3" -c "import fastapi, uvicorn" 2>/dev/null || \
    "$VENV/bin/pip" install -q fastapi 'uvicorn[standard]'

exec "$VENV/bin/python3" -m uvicorn server:app \
    --host 0.0.0.0 \
    --port 8766 \
    --log-level info \
    "$@"
