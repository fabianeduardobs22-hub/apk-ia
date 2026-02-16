#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install -e .

mkdir -p ~/.local/share/applications
cp packaging/sentinel-x.desktop ~/.local/share/applications/

echo "SENTINEL X instalado correctamente"
