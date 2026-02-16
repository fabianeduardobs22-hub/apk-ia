#!/usr/bin/env bash
set -euo pipefail

APPDIR=dist/AppDir
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications"
cp bin/sentinel-x "$APPDIR/usr/bin/"
cp packaging/sentinel-x.desktop "$APPDIR/usr/share/applications/"

echo "Preparado AppDir en $APPDIR. Usa appimagetool para generar AppImage."
