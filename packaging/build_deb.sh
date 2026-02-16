#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(pwd)
PKG_DIR="$ROOT_DIR/dist/sentinel-x_0.1.0"
mkdir -p "$PKG_DIR/DEBIAN" "$PKG_DIR/usr/local/bin"

cat > "$PKG_DIR/DEBIAN/control" <<EOF
Package: sentinel-x
Version: 0.1.0
Section: net
Priority: optional
Architecture: all
Depends: python3, python3-pip
Maintainer: Sentinel X Team
Description: SENTINEL X DEFENSE SUITE
EOF

cp bin/sentinel-x "$PKG_DIR/usr/local/bin/sentinel-x"
chmod 755 "$PKG_DIR/usr/local/bin/sentinel-x"

dpkg-deb --build "$PKG_DIR"
echo "Paquete generado en dist/"
