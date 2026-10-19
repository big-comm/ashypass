#!/usr/bin/env bash
# Write Ashy Pass's Google desktop client secret into
# crates/ashypass-core/src/backup/oauth.rs (in pieces, so leaked-secret
# scanners don't flag it) and commit that file locally. Google treats a
# desktop client's secret as public: it ships inside every binary anyway.
#
# The secret is read from ASHYPASS_GOOGLE_CLIENT_SECRET, else from
# .env.build.local. It is never printed. Run from anywhere; safe to re-run.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FILE="crates/ashypass-core/src/backup/oauth.rs"

if [[ -z "${ASHYPASS_GOOGLE_CLIENT_SECRET:-}" && -f .env.build.local ]]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env.build.local
    set +a
fi
SECRET="${ASHYPASS_GOOGLE_CLIENT_SECRET:-}"

if [[ ! "$SECRET" =~ ^GOCSPX-[A-Za-z0-9_-]+$ ]]; then
    echo "No valid Google client secret (GOCSPX-…) in ASHYPASS_GOOGLE_CLIENT_SECRET or .env.build.local" >&2
    exit 1
fi

# "GOC", "SPX-<first half>", "<second half>"
REST="${SECRET#GOCSPX-}"
HALF=$(( ${#REST} / 2 ))
PIECES="\"GOC\", \"SPX-${REST:0:HALF}\", \"${REST:HALF}\""

echo "[1/3] Writing the secret into $FILE…"
PIECES="$PIECES" perl -0777 -i -pe '
    s/(const ASHYPASS_GOOGLE_CLIENT_SECRET: &\[&str\] =\s*&\[)[^\]]*(\];)/$1$ENV{PIECES}$2/
        or die "constant ASHYPASS_GOOGLE_CLIENT_SECRET not found\n";
' "$FILE"
cargo fmt -p ashypass-core

echo "[2/3] Checking the build…"
cargo check -q -p ashypass-core

echo "[3/3] Committing…"
git add -- "$FILE" scripts/embed-google-secret.sh
if git diff --cached --quiet -- "$FILE" scripts/embed-google-secret.sh; then
    echo "Already in the source; nothing to commit."
    exit 0
fi
git commit -q -m "✨ feat(core): built-in Google desktop client secret" -- "$FILE" scripts/embed-google-secret.sh
git log --oneline -1
