#!/usr/bin/env bash
# Regenerate locale/ashypass.pot from the Rust sources, merge the diff into
# every locale/*.po, and compile usr/share/locale/<lang>/LC_MESSAGES/ashypass.mo
# so the dev `cargo run` build (which probes that path) picks them up.
#
# Requirements: gettext (xgettext, msgmerge, msgfmt).

set -euo pipefail

cd "$(dirname "$0")/.."

LOCALE_DIR="locale"
POT="$LOCALE_DIR/ashypass.pot"
MO_ROOT="usr/share/locale"

# Source files: every .rs in the app crate. The tr! macro expands to
# tr_static(literal), and xgettext picks up tr! / tr_static as keywords.
mapfile -d '' SOURCES < <(find crates/ashypass-app/src -name '*.rs' -print0)

echo "[1/3] Extracting strings from ${#SOURCES[@]} files → $POT"
xgettext \
    --from-code=UTF-8 \
    --language=Rust \
    --keyword='tr!' \
    --keyword=tr \
    --keyword=tr_static \
    --package-name=ashypass \
    --copyright-holder="Ashy Pass contributors" \
    --add-comments=TRANSLATORS \
    --no-location \
    --sort-output \
    --output="$POT" \
    "${SOURCES[@]}"

echo "[2/3] Merging $POT into existing .po files"
shopt -s nullglob
for po in "$LOCALE_DIR"/*.po; do
    [ "$(basename "$po")" = "ashypass.pot" ] && continue
    msgmerge --quiet --update --backup=none --no-fuzzy-matching "$po" "$POT"
done

echo "[3/3] Compiling .mo into $MO_ROOT/<lang>/LC_MESSAGES/ashypass.mo"
for po in "$LOCALE_DIR"/*.po; do
    lang=$(basename "$po" .po)
    # Skip the .pot template if it accidentally has a .po extension.
    [ "$lang" = "ashypass" ] && continue
    dest="$MO_ROOT/$lang/LC_MESSAGES"
    mkdir -p "$dest"
    msgfmt --check --output-file="$dest/ashypass.mo" "$po"
done

echo "Done. $(find "$MO_ROOT" -name 'ashypass.mo' | wc -l) catalogs compiled."
