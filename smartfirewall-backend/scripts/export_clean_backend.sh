#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/smart-envo"
PROJECT="smartfirewall-backend"
OUTDIR="$ROOT/exports"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTFILE="$OUTDIR/smart-envo-backend-clean-$STAMP.tar.gz"

mkdir -p "$OUTDIR"

cd "$ROOT"

tar \
  --exclude="$PROJECT/venv" \
  --exclude="$PROJECT/iot.db" \
  --exclude="$PROJECT/__pycache__" \
  --exclude="$PROJECT/.gunicorn" \
  --exclude="$PROJECT/*.pyc" \
  --exclude="$PROJECT/app/__pycache__" \
  --exclude="$PROJECT/app/routes/__pycache__" \
  --exclude="$PROJECT/app/services/__pycache__" \
  -czf "$OUTFILE" "$PROJECT"

echo "Created clean backend archive:"
echo "$OUTFILE"
