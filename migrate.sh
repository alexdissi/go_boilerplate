#!/usr/bin/env bash
set -euo pipefail

# Ajouter PostgreSQL au PATH
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"

echo "🚀 Début des migrations..."

# Charger DATABASE_URL depuis l'env, ou fallback sur .env si non défini
if [ -z "${DATABASE_URL:-}" ] && [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

if [ -z "${DATABASE_URL:-}" ]; then
  echo "❌ DATABASE_URL manquant (exporte DATABASE_URL ou ajoute-le dans .env)"
  exit 1
fi
echo "🔧 Using DATABASE_URL"

# ----- Pré-requis -----
if ! command -v psql >/dev/null 2>&1; then
  echo "❌ psql non installé. Installe le client PostgreSQL."
  exit 1
fi
if ! command -v goose >/dev/null 2>&1; then
  echo "❌ goose non installé:"
  echo "   go install github.com/pressly/goose/v3/cmd/goose@latest"
  exit 1
fi

# ----- Vérifier la connexion -----
echo -n "🔄 Test connexion... "
if psql "${DATABASE_URL}" -c '\q' >/dev/null 2>&1; then
  echo "✅ OK"
else
  echo "❌ Échec de connexion"
  exit 1
fi

echo "📊 Goose version:"
goose -version

COMMAND="${1:-up}"
echo "🚀 goose ${COMMAND}"
goose -dir ./migrations postgres "${DATABASE_URL}" "${COMMAND}"

echo "📋 Statut:"
goose -dir ./migrations postgres "${DATABASE_URL}" status

echo "✅ Migrations OK."