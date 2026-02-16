from pathlib import Path
import os

from setuptools import find_packages, setup

BASE_DIR = Path(__file__).parent.resolve()
PROFILE_ENV = "SENTINELX_BUILD_PROFILE"
DEFAULT_PROFILE = "core"
SUPPORTED_PROFILES = {"core", "extended"}
PACKAGE_NAME = "sentinel_x_defense_suite"


def _load_profile_manifest(profile: str) -> list[str]:
    manifest_path = BASE_DIR / "packaging" / f"profile-{profile}.txt"
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"No existe el manifiesto de build para el perfil '{profile}': {manifest_path}"
        )

    entries: list[str] = []
    for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def _package_data_from_manifest(entries: list[str]) -> list[str]:
    package_prefix = f"{PACKAGE_NAME}/"
    package_artifacts = []

    for entry in entries:
        if entry.startswith(package_prefix):
            package_artifacts.append(entry.removeprefix(package_prefix))

    return sorted(set(package_artifacts))


build_profile = os.getenv(PROFILE_ENV, DEFAULT_PROFILE).strip().lower()
if build_profile not in SUPPORTED_PROFILES:
    supported = ", ".join(sorted(SUPPORTED_PROFILES))
    raise ValueError(
        f"Perfil de build inválido '{build_profile}'. Perfiles soportados: {supported}."
    )

profile_entries = _load_profile_manifest(build_profile)
package_data = _package_data_from_manifest(profile_entries)

base_requires = [
    "PyYAML>=6.0",
    "requests>=2.32",
]
extended_requires = [
    "PyQt6>=6.7",
    "scapy>=2.5",
]

install_requires = base_requires.copy()
if build_profile == "extended":
    install_requires.extend(extended_requires)

setup(
    name="sentinel-x-defense-suite",
    version="0.1.0",
    description="Defensive Linux desktop suite for network monitoring and forensics",
    packages=find_packages(exclude=("tests", "docs")),
    include_package_data=False,
    package_data={PACKAGE_NAME: package_data},
    python_requires=">=3.10",
    install_requires=install_requires,
    extras_require={"extended": extended_requires},
    entry_points={
        "console_scripts": [
            "sentinel-x=sentinel_x_defense_suite.cli.app:main",
            "decktroy=decktroy.decktroy_cli:main",
            "Decktroy=decktroy.decktroy_cli:main",
        ]
    },
)
