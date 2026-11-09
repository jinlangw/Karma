# Benchmark preparation and recovery

When refactoring benchmark cases or shared preparation code, preserve each case and workflow’s intended setup, cleanup, recovery, and reset behavior. Cleanup, Pod restarts, store resets, and cluster recreation are valid when expected or permitted by the case, workflow, or task.

Before replacing recovery logic, trace the healthy-reuse, recovery, and recreation paths and identify the state each path must carry forward. Separate shared health and connection inspection from case-owned recovery policy. Distinguish connection, configuration, API, and transient failures from an observed inability to meet the required health state; apply only the case’s bounded policy for that state.

When recreation is required, build from authoritative case or workflow configuration, including required TLS, authentication, version, topology, and settings. Discard fixture data when the case defines it as disposable. When state must continue across recovery, define and verify its preservation or reconstruction explicitly. Scope cleanup to the selected fixture and preserve unrelated resources.

Keep deliberate policy changes distinct from refactors and explain their effect. Validate both healthy reuse and the expected unhealthy recovery or reset path before calling a refactor behavior-preserving; report any unvalidated path separately.

Separate the two goals: move common operations into the shared library while preserving each case’s behavior, then make behavior changes only for a specific chainability improvement. Document and test each such change independently.

Treat the original case/workflow preconditions and recovery branches as the behavioral baseline; do not change them just to simplify extraction.

The immediate stage oracle determines that stage’s pass or fail. The final regression sweep is diagnostic and can flag expected drift from later stages. Report the results separately and investigate the cause before classifying a sweep failure as a regression. Keep the stage assertions intact when rerunning them in the sweep.

Prefer existing checks. Add a unit test only to cover distinct shared-library or framework behavior. Keep case and workflow correctness checks separate from unit coverage.
