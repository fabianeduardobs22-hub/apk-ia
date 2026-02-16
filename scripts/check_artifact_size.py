#!/usr/bin/env python3
"""Valida el tamaño de artefactos de build por perfil."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

SIZE_RANGES = {
    "core": (0, 5 * 1024 * 1024),
    "extended": (0, 15 * 1024 * 1024),
}


def _human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size_bytes} B"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Chequea tamaño final de artefacto según perfil de build."
    )
    parser.add_argument(
        "--profile",
        required=True,
        choices=sorted(SIZE_RANGES.keys()),
        help="Perfil de build evaluado.",
    )
    parser.add_argument(
        "--artifact",
        required=True,
        type=Path,
        help="Ruta al artefacto generado (wheel/tar.gz/AppImage/etc.).",
    )
    parser.add_argument(
        "--min-bytes",
        type=int,
        default=None,
        help="Sobrescribe el mínimo permitido para este job de CI.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Sobrescribe el máximo permitido para este job de CI.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.artifact.exists():
        print(f"ERROR: no existe el artefacto: {args.artifact}")
        return 2

    size_bytes = args.artifact.stat().st_size
    default_min, default_max = SIZE_RANGES[args.profile]
    min_allowed = args.min_bytes if args.min_bytes is not None else default_min
    max_allowed = args.max_bytes if args.max_bytes is not None else default_max

    print(
        f"Artifact: {args.artifact}\n"
        f"Profile: {args.profile}\n"
        f"Size: {size_bytes} bytes ({_human_size(size_bytes)})\n"
        f"Allowed range: {min_allowed}..{max_allowed} bytes"
    )

    if min_allowed <= size_bytes <= max_allowed:
        print("OK: tamaño dentro del rango acordado para el perfil.")
        return 0

    print("FAIL: tamaño fuera del rango acordado para el perfil.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
