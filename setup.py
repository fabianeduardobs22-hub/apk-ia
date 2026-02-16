from setuptools import find_packages, setup

setup(
    name="sentinel-x-defense-suite",
    version="0.1.0",
    description="Defensive Linux desktop suite for network monitoring and forensics",
    packages=find_packages(exclude=("tests", "docs")),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "PyYAML>=6.0",
        "requests>=2.32",
        "PyQt6>=6.7",
        "scapy>=2.5",
    ],
    entry_points={
        "console_scripts": [
            "sentinel-x=sentinel_x_defense_suite.cli.app:main",
            "decktroy=decktroy.decktroy_cli:main",
            "Decktroy=decktroy.decktroy_cli:main",
        ]
    },
)
