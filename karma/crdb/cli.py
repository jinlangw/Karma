"""Small command-line surface for inspecting and checking an existing CRDB."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from .adapter import KubectlAdapter
from .library import CrdbLibrary
from .types import AcceptedState, CrdbError, Lifecycle, Requirement, TLSMode, WorkloadRef


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m karma.crdb", description="Inspect and verify an existing CockroachDB workload.")
    parser.add_argument(
        "action",
        choices=("inspect", "probe", "reconcile", "capture", "verify", "health-endpoint", "prepare-health-probes"),
    )
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--statefulset", required=True)
    parser.add_argument("--container")
    parser.add_argument("--context")
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--lifecycle", choices=tuple(item.value for item in Lifecycle), default=Lifecycle.DEPLOYED.value)
    parser.add_argument("--minimum-nodes", type=int)
    parser.add_argument("--tls", choices=(TLSMode.INSECURE.value, TLSMode.TLS.value))
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--accepted-state", type=Path, help="JSON file written by capture; only used by verify/reconcile")
    parser.add_argument("--health-path", choices=("/health", "/health?ready=1"), default="/health?ready=1")
    return parser


def _json_default(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _read_accepted_state(path: Path) -> AcceptedState:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        value["tls_mode"] = TLSMode(value["tls_mode"])
        for key in ("node_ids", "sql_versions", "pvc_identities", "certificate_fingerprints", "service_routing"):
            value[key] = tuple(tuple(item) if isinstance(item, list) else item for item in value[key])
        return AcceptedState(**value)
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise ValueError("accepted-state file is invalid or incomplete") from error


def _emit(value: Any) -> None:
    print(json.dumps(asdict(value) if hasattr(value, "__dataclass_fields__") else value, default=_json_default, indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        ref = WorkloadRef(args.namespace, args.statefulset, args.container)
        adapter = KubectlAdapter(kubectl=args.kubectl, context=args.context)
        library = CrdbLibrary(adapter)
        requirement = Requirement(
            lifecycle=Lifecycle(args.lifecycle),
            minimum_nodes=args.minimum_nodes,
            tls_mode=TLSMode(args.tls) if args.tls else None,
        )
        if args.action == "inspect":
            _emit(library.inspect(ref))
        elif args.action == "probe":
            assessment = library.probe(ref, requirement)
            _emit(assessment)
            return 0 if assessment.status.value == "satisfied" else 1
        elif args.action == "reconcile":
            accepted = _read_accepted_state(args.accepted_state) if args.accepted_state else None
            result = library.reconcile(
                ref,
                requirement,
                timeout=args.timeout,
                poll_interval=args.poll_interval,
                accepted_state=accepted,
            )
            _emit(result)
            return 0 if result.assessment.status.value == "satisfied" else 1
        elif args.action == "capture":
            accepted = library.capture_accepted_state(ref)
            print(json.dumps(asdict(accepted), default=_json_default, indent=2, sort_keys=True))
        elif args.action == "verify":
            if not args.accepted_state:
                raise ValueError("verify requires --accepted-state")
            _emit(library.verify_accepted_state(ref, _read_accepted_state(args.accepted_state)))
        elif args.action == "health-endpoint":
            results = library.probe_health_endpoint(ref, path=args.health_path)
            print(json.dumps(results, indent=2))
            return 0 if all(result[2] for result in results) else 1
        elif args.action == "prepare-health-probes":
            result = library.prepare_health_recovery_probes(
                ref,
                timeout=args.timeout,
                poll_interval=args.poll_interval,
            )
            _emit(result)
            return 0 if result.verified.status.value == "satisfied" else 1
        return 0
    except (CrdbError, ValueError) as error:
        print(f"{getattr(getattr(error, 'code', None), 'value', 'invalid_input')}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
