"""Inspect release-candidate wheel and sdist contents without installing them."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path


def _forbidden(name: str) -> bool:
    normalized_name = name.replace("\\", "/").lower()
    normalized = f"/{normalized_name}/"
    return any(
        part in normalized
        for part in (
            "/.git/",
            "/.release-venv/",
            "/.test-tmp",
            "/.venv/",
            "/__pycache__/",
            "/build/",
            "/dist/",
        )
    ) or normalized.endswith((".pyc/", ".pyo/"))


def inspect(dist: Path) -> None:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("expected exactly one wheel and one .tar.gz sdist")

    with zipfile.ZipFile(wheels[0]) as archive:
        wheel_names = set(archive.namelist())
    if any(_forbidden(name) for name in wheel_names):
        raise SystemExit("wheel contains a forbidden local/build artifact")
    required_wheel = {"landmine/__init__.py", "landmine/cli.py"}
    if not required_wheel <= wheel_names:
        raise SystemExit(f"wheel is missing: {sorted(required_wheel - wheel_names)}")
    if any(name.startswith(("tests/", "skills/", ".codex-plugin/")) for name in wheel_names):
        raise SystemExit("wheel incorrectly contains tests or agent-plugin files")
    if not any(name.endswith(".dist-info/METADATA") for name in wheel_names):
        raise SystemExit("wheel metadata is missing")
    if not any(".dist-info/licenses/LICENSE" in name for name in wheel_names):
        raise SystemExit("wheel license is missing")

    with tarfile.open(sdists[0], mode="r:gz") as archive:
        sdist_names = set(archive.getnames())
    if any(_forbidden(name) for name in sdist_names):
        raise SystemExit("sdist contains a forbidden local/build artifact")
    roots = {name.split("/", 1)[0] for name in sdist_names if "/" in name}
    if len(roots) != 1:
        raise SystemExit("sdist does not have one archive root")
    root = next(iter(roots))
    required_sdist = {
        f"{root}/CHANGELOG.md",
        f"{root}/LICENSE",
        f"{root}/README.md",
        f"{root}/SECURITY.md",
        f"{root}/pyproject.toml",
        f"{root}/schemas/result-v1.schema.json",
        f"{root}/src/landmine/cli.py",
    }
    if not required_sdist <= sdist_names:
        raise SystemExit(f"sdist is missing: {sorted(required_sdist - sdist_names)}")

    print(f"wheel: {wheels[0].name} ({len(wheel_names)} files)")
    print(f"sdist: {sdists[0].name} ({len(sdist_names)} entries)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()
    inspect(args.dist)


if __name__ == "__main__":
    main()
