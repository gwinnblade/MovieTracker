#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
node scripts/init-local.mjs
node scripts/configure-local-network.mjs
docker compose up -d --force-recreate "$@"
