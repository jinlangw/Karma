#!/usr/bin/env python3
"""Structural validator for a ported KARMA case.

Usage: python scripts/validate_ported_case.py <service> <case_name>

Checks (no cluster needed):
  1. The case normalizes via karma.definitions.cases.
  2. Every resource file / directory referenced by the test.yaml exists.
  3. Every referenced oracle/precondition .py compiles.
  4. Every resource *.yaml parses as YAML.
  5. No residual ${BENCH_...} or {{params...}} tokens remain in resource files.
Exits non-zero (and prints PROBLEMS) on any failure.
"""
from __future__ import annotations

import py_compile
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from karma.definitions.cases import load_case_file, normalize_case  # noqa: E402

RES = Path("cases/tests")


def main() -> int:
    service, case = sys.argv[1], sys.argv[2]
    case_dir = RES / service / case
    problems: list[str] = []

    # 1. normalize
    try:
        data = load_case_file(RES, service, case)
        normalize_case(data, service, case)
    except Exception as exc:  # noqa: BLE001
        problems.append(f"normalize failed: {exc}")
        data = {}

    text = (case_dir / "test.yaml").read_text()

    # 2. referenced paths exist (explicit files + whole-dir applies)
    for ref in sorted(set(re.findall(r"cases/[A-Za-z0-9_./-]+\.(?:yaml|py|sh)", text))):
        if not Path(ref).exists():
            problems.append(f"referenced file missing: {ref}")
    for ref in sorted(set(re.findall(r"cases/[A-Za-z0-9_./-]+/resource/(?:\s|\"|')", text))):
        d = ref.strip("\"' \t\r\n")
        if not Path(d).is_dir() or not any(Path(d).glob("*.yaml")):
            problems.append(f"referenced resource dir empty/missing: {d}")

    # A manifest must be final, token-free YAML ONLY when it is applied via a
    # plain `kubectl apply -f <file>` (or `-f <dir>/`). Manifests expanded at
    # apply time (`envsubst`/`sed`), embedded+applied by a setup .py, or handed
    # to the agent as templates may legitimately keep ${BENCH_*}/{{TOKEN}}
    # placeholders and need not parse as final YAML. Collect the plainly-applied
    # files and directories so we only strict-check those.
    plain_files: set[str] = set()
    plain_dirs: set[str] = set()
    for line in text.splitlines():
        if "apply -f" not in line:
            continue
        if "envsubst" in line or re.search(r"\bsed\b", line):
            continue  # substituted at apply time
        for ref in re.findall(r"cases/[A-Za-z0-9_./-]+\.(?:yaml)", line):
            plain_files.add(str(Path(ref).resolve()))
        for ref in re.findall(r"cases/[A-Za-z0-9_./-]+/resource/?(?=[\s\"'])", line):
            plain_dirs.add(str(Path(ref.rstrip("/")).resolve()))

    def _strict(y: Path) -> bool:
        return str(y.resolve()) in plain_files or str(y.parent.resolve()) in plain_dirs

    # 3. compile every .py in the case dir
    for py in case_dir.rglob("*.py"):
        try:
            py_compile.compile(str(py), doraise=True)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"compile failed {py}: {exc}")

    # 4 + 5. parse + token-check only plainly-applied manifests
    for y in case_dir.rglob("*.yaml"):
        if y.name == "test.yaml" or not _strict(y):
            continue
        raw = y.read_text()
        try:
            list(yaml.safe_load_all(raw))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"YAML parse failed {y}: {exc}")
        if "${BENCH" in raw or "$BENCH" in raw:
            problems.append(f"residual ${{BENCH}} token in {y}")
        if "{{params" in raw:
            problems.append(f"residual {{{{params}}}} token in {y}")

    if problems:
        print(f"PROBLEMS in {service}/{case}:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"OK: {service}/{case} (normalizes, all refs present, compiles, parses, no tokens)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
