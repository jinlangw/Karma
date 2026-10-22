"""
HTTP routes, SSE, static file serving, and the thin backend layer.

This module is intentionally thin. All execution is delegated to
``interfaces.http.jobs`` and ``runtime.service``. No orchestration logic
lives here.

Routes::

    GET  /                          serve index.html
    GET  /webui/<path>             serve static files
    POST /api/run                   submit a case or workflow run
    GET  /api/run/<run_id>/status   poll run status
    GET  /api/run/<run_id>/stream   SSE stream of stage events
    POST /api/run/<run_id>/cancel   cancel a running job
    GET  /api/cases                 list available cases by service
    GET  /api/agents                list registered agents
    POST /api/judge                 trigger judge on a completed run
"""

from __future__ import annotations

import json
import queue
from pathlib import Path
from typing import Any

from .jobs import submit_job, get_job_status, cancel_job, list_jobs
from .events import hub
from . import catalog
from . import judging
from . import cli_preview
from ...definitions.workflows import parse_and_normalize_workflow
from ...runtime import manual
from ...agents.registry import list_agents


def create_app(
    *,
    resources_dir: Path,
    runs_dir: Path,
    workflows_dir: Path | None = None,
    static_dir: Path | None = None,
) -> Any:
    """Create and return the Flask application instance.

    Registers all REST and SSE routes. Run and judge progress both stream
    through the single shared :data:`events.hub`; the SSE endpoints subscribe
    to it by run/job id. Static files are served from *static_dir*.

    Parameters
    ----------
    resources_dir:
        Root resources directory used for case discovery.
    runs_dir:
        Root runs directory used for artifact storage.
    workflows_dir:
        Directory of saved workflow files (defaults to ``workflows/``).
    static_dir:
        Directory from which static files are served. Defaults to the
        repository-root ``webui/``.
    """
    try:
        from flask import Flask, jsonify, request, Response, send_from_directory
    except ImportError:
        raise RuntimeError(
            "Flask is required for the HTTP interface. "
            "Install it with: pip install flask"
        )

    if static_dir is None:
        # server.py lives at karma/interfaces/http/; the web UI dir (webui/) is at
        # the repository root, i.e. three levels above the karma package.
        static_dir = Path(__file__).resolve().parents[3] / "webui"
    if workflows_dir is None:
        workflows_dir = Path("workflows")

    app = Flask(__name__, static_folder=None)

    @app.route("/")
    def index():  # type: ignore[return]
        idx = Path(static_dir) / "index.html"
        if idx.exists():
            return idx.read_text(), 200, {"Content-Type": "text/html"}
        return "<h1>KARMA</h1>", 200

    @app.route("/webui/<path:filename>")
    def static_files(filename):
        return send_from_directory(str(static_dir), filename)

    @app.route("/api/run", methods=["POST"])
    def api_run():
        payload = request.get_json(force=True, silent=True) or {}
        try:
            run_id = submit_job(
                payload,
                runs_dir=runs_dir,
                resources_dir=resources_dir,
                workflows_dir=Path(workflows_dir),
            )
        except (ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"run_id": run_id}), 201

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/run/<run_id>/status")
    def api_run_status(run_id):
        status = get_job_status(run_id)
        if status is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(status)

    @app.route("/api/run/<run_id>/stream")
    def api_run_stream(run_id):
        # Serve only when the hub still holds this run's event buffer, or the run
        # is a live job whose first event may be tens of seconds away (the just-
        # submitted race). A finished run whose buffer the hub evicted -- or an
        # unknown run -- would never emit 'done', so 404 instead of hanging the
        # feed forever (SS-9). See _run_stream_available.
        if not _run_stream_available(run_id):
            return jsonify({"error": "not found"}), 404
        return Response(
            _sse_stream(run_id),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Access-Control-Allow-Origin": "*",
            },
        )

    @app.route("/api/run/<run_id>/stages/<stage_id>")
    def api_run_stage(run_id, stage_id):
        try:
            return jsonify(catalog.get_stage_detail(Path(runs_dir), run_id, stage_id))
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/run/<run_id>/cancel", methods=["POST"])
    def api_run_cancel(run_id):
        if not cancel_job(run_id):
            return jsonify({"error": "not found"}), 404
        return jsonify({"run_id": run_id, "status": "cancelled"})

    @app.route("/api/cases")
    def api_cases():
        return jsonify(catalog.list_cases_by_service(Path(resources_dir)))

    @app.route("/api/services")
    def api_services():
        return jsonify({
            "services": catalog.list_services(Path(resources_dir)),
            "cluster": catalog.cluster_status(),
        })

    @app.route("/api/cases/<service>/<case_name>")
    def api_case_detail(service, case_name):
        try:
            detail = catalog.get_case_detail(Path(resources_dir), service, case_name)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 404
        return jsonify(detail)

    @app.route("/api/runs")
    def api_runs():
        # History from disk, overlaid with live in-memory jobs so a running run
        # appears (and shows "running") before its run.json is written.
        by_id = {r["run_id"]: r for r in catalog.list_runs(Path(runs_dir))}
        for job in list_jobs():
            rid = job.get("run_id")
            if not rid:
                continue
            if rid in by_id:
                if job.get("status"):
                    by_id[rid]["status"] = job["status"]
            else:
                by_id[rid] = {
                    "run_id": rid, "status": job.get("status", "running"),
                    "passed": 0, "failed": 0, "judged": False,
                }
        runs = sorted(by_id.values(), key=lambda r: r["run_id"], reverse=True)
        return jsonify(runs)

    @app.route("/api/run/<run_id>")
    def api_run_detail(run_id):
        try:
            detail = catalog.get_run_detail(Path(runs_dir), run_id)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 404
        # Overlay live status while the run is still active (run.json is only
        # written at the end), so the detail view knows to stream + offer Cancel.
        job = get_job_status(run_id)
        if job and job.get("status"):
            detail["status"] = job["status"]
        return jsonify(detail)

    @app.route("/api/workflows", methods=["GET", "POST"])
    def api_workflows():
        if request.method == "POST":
            payload = request.get_json(force=True, silent=True) or {}
            try:
                res = catalog.save_workflow(
                    Path(workflows_dir), Path(resources_dir),
                    str(payload.get("yaml_text") or ""), payload.get("name"),
                )
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400
            return jsonify(res), 201
        return jsonify(
            catalog.list_workflow_files(Path(workflows_dir), Path(resources_dir))
        )

    @app.route("/api/workflows/<path:name>")
    def api_workflow_detail(name):
        try:
            return jsonify(catalog.get_workflow_detail(
                Path(workflows_dir), Path(resources_dir), name))
        except (RuntimeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/jobs")
    def api_jobs():
        return jsonify(list_jobs())

    @app.route("/api/agents")
    def api_agents():
        return jsonify(list_agents())

    @app.route("/api/config")
    def api_config():
        # Lets the UI warn before a run when the default harness system prompt
        # is unavailable (e.g. docs/ not deployed) so agents won't silently run
        # without it. False = the default file is missing/empty.
        from ...runtime.service import _default_system_prompt
        return jsonify({
            "default_system_prompt_available": bool(_default_system_prompt()),
        })

    @app.route("/api/judge", methods=["POST"])
    def api_judge():
        from ...judge.engine import run_judge, run_judge_batch
        payload = request.get_json(force=True, silent=True) or {}
        run_dir_str = str(payload.get("run_dir") or "")
        if not run_dir_str:
            return jsonify({"error": "run_dir is required"}), 400
        run_dir_path = Path(run_dir_str)
        # Confine to runs_dir: this route accepts a raw path, so reject anything
        # resolving outside the runs directory -- otherwise it is an arbitrary
        # host-filesystem read (preview) / judge.json write (C5).
        try:
            run_dir_path.resolve().relative_to(Path(runs_dir).resolve())
        except ValueError:
            return jsonify({"error": "run_dir must be inside the runs directory"}), 400
        if not run_dir_path.exists():
            return jsonify({"error": "run_dir not found"}), 404
        stage_id = payload.get("stage_id")
        try:
            if stage_id:
                result = run_judge(
                    run_dir_path, str(stage_id),
                    judge_model=payload.get("model"),
                )
            else:
                result = run_judge_batch(
                    run_dir_path, judge_model=payload.get("model")
                )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify(result)

    @app.route("/api/judge/preview", methods=["POST"])
    def api_judge_preview():
        # Assemble the judge input (oracle + evidence + rubric + prompt) without
        # calling the LLM, so the UI can show exactly what would be sent.
        from ...judge.engine import run_judge, run_judge_batch
        payload = request.get_json(force=True, silent=True) or {}
        run_dir_str = str(payload.get("run_dir") or "")
        if not run_dir_str:
            return jsonify({"error": "run_dir is required"}), 400
        run_dir_path = Path(run_dir_str)
        # Confine to runs_dir: this route accepts a raw path, so reject anything
        # resolving outside the runs directory -- otherwise it is an arbitrary
        # host-filesystem read (preview) / judge.json write (C5).
        try:
            run_dir_path.resolve().relative_to(Path(runs_dir).resolve())
        except ValueError:
            return jsonify({"error": "run_dir must be inside the runs directory"}), 400
        if not run_dir_path.exists():
            return jsonify({"error": "run_dir not found"}), 404
        stage_id = payload.get("stage_id")
        try:
            if stage_id:
                result = run_judge(run_dir_path, str(stage_id), dry_run=True)
            else:
                result = run_judge_batch(run_dir_path, dry_run=True)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500
        return jsonify(result)

    @app.route("/api/judge/start", methods=["POST"])
    def api_judge_start():
        payload = request.get_json(force=True, silent=True) or {}
        # Optional rubric: the UI sends the file's content as a YAML/JSON string;
        # an already-parsed mapping is also accepted. When present, oracle-passing
        # stages are LLM-scored against it instead of flat full marks.
        rubric = None
        raw_rubric = payload.get("rubric")
        try:
            if isinstance(raw_rubric, str) and raw_rubric.strip():
                from ...judge.rubric import load_rubric_text
                rubric = load_rubric_text(raw_rubric)
            elif isinstance(raw_rubric, dict):
                from ...judge.rubric import normalize_rubric
                rubric = normalize_rubric(raw_rubric)
            elif payload.get("use_default_rubric"):
                # "Judge w/ Rubric" with no custom file -> the bundled example.
                from ...judge.rubric import load_rubric_file
                default_path = Path(__file__).resolve().parents[3] / "docs" / "example-rubric.yaml"
                rubric = load_rubric_file(default_path)
        except Exception as exc:
            return jsonify({"error": f"invalid rubric: {exc}"}), 400
        try:
            job_id = judging.start_judge_job(
                str(payload.get("target_type") or "run"),
                str(payload.get("target_path") or ""),
                runs_dir=Path(runs_dir),
                judge_model=payload.get("model"),
                rubric=rubric,
                dry_run=bool(payload.get("dry_run")),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"job_id": job_id}), 201

    @app.route("/api/judge/jobs")
    def api_judge_jobs():
        return jsonify(judging.list_judge_jobs())

    @app.route("/api/judge/jobs/<job_id>")
    def api_judge_job(job_id):
        job = judging.get_judge_job(job_id)
        if job is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(job)

    @app.route("/api/judge/jobs/<job_id>/cancel", methods=["POST"])
    def api_judge_job_cancel(job_id):
        if not judging.request_judge_cancel(job_id):
            return jsonify({"error": "job not found or not running"}), 404
        return jsonify({"job_id": job_id, "status": "cancelling"})

    @app.route("/api/judge/jobs/<job_id>/stream")
    def api_judge_job_stream(job_id):
        if not hub.is_known(job_id):
            return jsonify({"error": "not found"}), 404
        return Response(
            _sse_stream(job_id),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Access-Control-Allow-Origin": "*",
            },
        )

    @app.route("/api/judge/runs")
    def api_judge_runs():
        return jsonify(judging.list_judge_runs(Path(runs_dir)))

    @app.route("/api/judge/batches")
    def api_judge_batches():
        return jsonify(judging.list_judge_batches(Path(runs_dir)))

    # --- Manual operator run lifecycle --------------------------------------
    @app.route("/api/manual/start", methods=["POST"])
    def api_manual_start():
        payload = request.get_json(force=True, silent=True) or {}
        service = str(payload.get("service") or "").strip()
        case_name = str(payload.get("case_name") or "").strip()
        if not service or not case_name:
            return jsonify({"error": "service and case_name are required"}), 400
        try:
            run_id = manual.start_manual_run(
                service,
                case_name,
                runs_dir=Path(runs_dir),
                resources_dir=Path(resources_dir),
                param_overrides=payload.get("params") or None,
                namespace_roles=payload.get("namespace_roles") or None,
                environment_provider=payload.get("environment_provider"),
            )
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"run_id": run_id}), 201

    @app.route("/api/manual/<run_id>/status")
    def api_manual_status(run_id):
        status = manual.get_manual_status(run_id)
        if status is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(status)

    @app.route("/api/manual/<run_id>/submit", methods=["POST"])
    def api_manual_submit(run_id):
        try:
            return jsonify(manual.submit_manual_run(run_id))
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409

    @app.route("/api/manual/<run_id>/cleanup", methods=["POST"])
    def api_manual_cleanup(run_id):
        return jsonify(manual.cleanup_manual_run(run_id))

    @app.route("/api/manual/<run_id>/adversary/deploy", methods=["POST"])
    def api_manual_adversary_deploy(run_id):
        payload = request.get_json(force=True, silent=True) or {}
        scenario = str(payload.get("scenario") or "").strip()
        if not scenario:
            return jsonify({"error": "scenario is required"}), 400
        try:
            return jsonify(manual.deploy_manual_adversary(
                run_id, scenario, param_overrides=payload.get("params") or None,
            ))
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409

    @app.route("/api/manual/<run_id>/adversary/lift", methods=["POST"])
    def api_manual_adversary_lift(run_id):
        payload = request.get_json(force=True, silent=True) or {}
        scenario = str(payload.get("scenario") or "").strip()
        if not scenario:
            return jsonify({"error": "scenario is required"}), 400
        try:
            return jsonify(manual.lift_manual_adversary(run_id, scenario))
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409

    # --- CLI preview, workflow import, adversary catalog, proxy status ------
    @app.route("/api/cli/options")
    def api_cli_options():
        return jsonify(cli_preview.get_cli_options())

    @app.route("/api/cli/preview", methods=["POST"])
    def api_cli_preview():
        payload = request.get_json(force=True, silent=True) or {}
        return jsonify(cli_preview.build_preview(payload))

    @app.route("/api/workflow/import", methods=["POST"])
    def api_workflow_import():
        payload = request.get_json(force=True, silent=True) or {}
        try:
            workflow = parse_and_normalize_workflow(
                payload.get("yaml_text") or "", Path(resources_dir))
        except ValueError as exc:
            return jsonify({"ok": False, "errors": [str(exc)]})
        return jsonify({"ok": True, "workflow": workflow})

    @app.route("/api/workflow/preview", methods=["POST"])
    def api_workflow_preview():
        # Fully resolve a workflow (normalize + load cases + adversary) and
        # summarize the stages that would run, without executing anything.
        payload = request.get_json(force=True, silent=True) or {}
        try:
            preview = catalog.preview_workflow(
                payload.get("yaml_text") or "", Path(resources_dir))
        except (ValueError, RuntimeError) as exc:
            return jsonify({"ok": False, "errors": [str(exc)]})
        return jsonify({"ok": True, **preview})

    @app.route("/api/adversary/scenarios")
    def api_adversary_scenarios():
        return jsonify(catalog.list_adversary_scenarios(Path(resources_dir)))

    @app.route("/api/proxy/status")
    def api_proxy_status():
        import shutil
        return jsonify({
            "mode": "per-run",
            "status": "ok",
            "kubectl_available": shutil.which("kubectl") is not None,
            "detail": "kubectl proxy is launched per stage; no standalone daemon",
        })

    return app


_HEARTBEAT_INTERVAL = 15.0


def _run_stream_available(run_id: str) -> bool:
    """True when the run's SSE stream should be served, False to 404.

    Served when the hub still holds the run's event buffer, or the run is a
    live (``"running"``) job whose first event may not have fired yet (the
    just-submitted race). A finished run whose buffer the hub has evicted -- or
    an unknown run -- is NOT served: it has nothing to stream and would never
    emit a ``done`` sentinel, so the feed would hang open forever (SS-9). The
    judge stream 404s the same way.
    """
    if hub.is_known(run_id):
        return True
    status = get_job_status(run_id)
    return bool(status) and status.get("status") == "running"


def _sse_stream(stream_id: str) -> Any:
    """Yield SSE-formatted strings for *stream_id* from the shared hub.

    Subscribes to :data:`events.hub`, which first replays the buffered
    history (so a late or reconnecting client sees prior events) and then
    delivers live events. A comment heartbeat is emitted whenever the
    stream is idle for ``_HEARTBEAT_INTERVAL`` seconds so intermediaries do
    not drop the connection. The ``None`` sentinel ends the stream with a
    terminal ``done`` event. The subscription is always released on exit.
    """
    q = hub.subscribe(stream_id)
    try:
        while True:
            try:
                event = q.get(timeout=_HEARTBEAT_INTERVAL)
            except queue.Empty:
                yield ": heartbeat\n\n"
                continue
            if event is None:
                yield f"data: {json.dumps({'type': 'done', 'run_id': stream_id})}\n\n"
                break
            yield f"data: {json.dumps(event)}\n\n"
    finally:
        hub.unsubscribe(stream_id, q)


def main(
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    resources_dir: Path | None = None,
    runs_dir: Path | None = None,
) -> None:
    """Start the HTTP server.

    Called by ``main.py``. Reads ``KARMA_HOST``, ``KARMA_PORT``,
    ``KARMA_RESOURCES_DIR``, and ``KARMA_RUNS_DIR`` from the environment
    when the corresponding keyword argument is ``None``.
    """
    import os

    resolved_resources = resources_dir or Path(
        os.environ.get("KARMA_RESOURCES_DIR", "cases/tests")
    )
    resolved_runs = runs_dir or Path(os.environ.get("KARMA_RUNS_DIR", "runs"))
    resolved_workflows = Path(os.environ.get("KARMA_WORKFLOWS_DIR", "workflows"))
    resolved_host = os.environ.get("KARMA_HOST", host)
    resolved_port = int(os.environ.get("KARMA_PORT", port))

    # Runs marked "running" on disk are orphans from a previous process (a
    # restart kills their background thread); flag them so they don't show as
    # running forever.
    from .jobs import reconcile_stale_runs
    n = reconcile_stale_runs(Path(resolved_runs))
    if n:
        print(f"reconciled {n} interrupted run(s) from a previous session")

    app = create_app(
        resources_dir=resolved_resources,
        runs_dir=resolved_runs,
        workflows_dir=resolved_workflows,
    )
    app.run(host=resolved_host, port=resolved_port)
