## Summary
The manuscript presents IoT-Access-Sentinel, a two-stage IoT access-control pipeline that combines deterministic validation (token/ACL/time/network/sanitization checks) with multi-agent LLM reasoning for semantically ambiguous alerts. The repository does contain supporting artifacts for the main quantitative claims: `results/results_comparison.json`, `results/statistical_analysis_report.json`, `results/safety_metrics.json`, `results/red_team_results.json`, `results/stress_test_results.json`, and the evaluation scripts under `scripts/`.

The paper is strongest when it frames the system as defense-in-depth with a deterministic containment boundary and when it reports paired accuracy/safety statistics rather than accuracy alone. However, several numeric claims in the manuscript are either under-supported by the stored artifacts or conflate distinct benchmark subsets, especially around red-team evaluation, latency/resource reporting, and the interpretation of the Layer 0 bypass/cost-savings numbers.

## Strengths
- [S1] The evaluation package is unusually complete for a short systems paper: the manifest (`evaluation/benchmark_manifest_204.txt`), result JSONs under `results/`, and scripts (`scripts/02_evaluate_system.py`, `scripts/03_analyze_results.py`, `scripts/05_run_stress_test.py`, `scripts/07_generate_unmitigated_red_team.py`) are all present and align with the reproducibility section.
- [S2] The manuscript reports paired statistics and safety metrics, not just raw accuracy; these are supported by `results/statistical_analysis_report.json` and `results/safety_metrics.json`.
- [S3] The defense-in-depth story is coherent and code-backed: Layer 0 validation and JWT/ACL checks are implemented in `common/validation.py` and `decision_engine/validators/user_auth_validator.py`, which matches the system description in the manuscript.

## Weaknesses
- [W1] **MAJOR:** The manuscript conflates two different “red-team” evaluations. The 71.4% figure in the Results section (`10/14 correct`) comes from the 7 red-team files in `evaluation/benchmark_manifest_204.txt` duplicated into 14 runs in `results/results_comparison.json`, not from the separate 105-scenario adversarial robustness suite in `results/red_team_results.json`. The text should explicitly distinguish these benchmarks; otherwise the reader can easily misread the 71.4% result as covering the 105-attack suite.
- [W2] **MAJOR:** The claimed Layer 0 decomposition is not supported by the stored red-team artifact. The manuscript says the 70 blocked attacks were split into “40” sanitization/pattern-matching cases and “30” auth/JWT failures, but `results/red_team_results.json` records a different reason breakdown (e.g., `Invalid device_type format`, `Invalid device_id format`, `Invalid user_id format`, `Injection detected: prompt_injection`, `role_hijack`, `sql_tautology`) and does not expose a separate auth/JWT bucket. Likewise, the “46% bypass” / “without LLM invocation” language is inferred from `results/ablation_results.json`, not directly measured from routing logs.
- [W3] **MAJOR:** The runtime/resource claims are only partially evidenced. `results/stress_test_results.json` supports 97 ms average latency, 31.5 RPS, and 34 timeouts, but the manuscript’s camera/sensor breakdown (156 ms / 38 ms) and resource numbers (94 MB memory, <1% CPU) do not appear in any JSON under `results/`. Moreover, `scripts/05_run_stress_test.py` hard-codes average latency/throughput in simulate mode, so these are synthetic replay traces rather than independently instrumented measurements.
- [W4] **MAJOR:** The baseline is not a plain RBAC baseline, but a much stronger `RBAC+Rules Baseline` including auth-token checks, user-device ACLs, CIDR/time rules, and regex-based signature filters. That is defensible if positioned as a hardened gateway baseline, but it weakens the manuscript’s implicit comparison to “traditional RBAC” and should be presented more carefully to avoid overstating the improvement.
- [W5] **MINOR:** The benchmark scope is under-specified: `evaluation/synthetic/summary.json` reports 145 generated scenarios, while the manuscript only discusses 102 general benchmark scenarios. The manifest (`evaluation/benchmark_manifest_204.txt`) pins the 102 used files, but the paper does not explain the selection rule from the larger generator corpus. This makes the 102-scenario claim reproducible only if the reader infers the subset from the manifest.

## Questions for Authors
- [Q1] Which artifact contains the camera-vs-sensor latency breakdown and the 94 MB / <1% CPU measurements? If none exists, should those numbers be removed or clearly labeled as unpublished console output?
- [Q2] Can you provide direct routing evidence for the “46% of requests resolved without LLM invocation” claim, rather than inferring it from the baseline correct-DENY count in `results/ablation_results.json`?
- [Q3] How were the 102 benchmark scenarios selected from the 145 scenarios reported in `evaluation/synthetic/summary.json`? Was the subset fixed before evaluation, or derived post hoc?
- [Q4] Should the paper rename the 7-file manifest subset to avoid reusing “red-team” for both the 14-run comparison and the 105-scenario attack suite?

## Verdict
Overall: weak reject / major revision. Confidence: 0.87. The artifact package is promising and the core accuracy/safety numbers are mostly reproducible, but the manuscript currently overreaches on several evidence-linked claims. It would likely be borderline for a workshop/short-paper venue after clarification, but not ready for a stronger venue in its current form.

## Revision Plan
1. Separate the two red-team benchmarks throughout the paper: the 14-run manifest subset vs. the 105-scenario adversarial suite.
2. Replace or qualify unsupported latency/resource claims, or add a machine-readable artifact that records them.
3. Recompute or restate the Layer 0 bypass/cost-savings narrative using direct routing logs, not baseline-derived inference.
4. Reframe the baseline as a hardened rules+auth gateway, or add a truly plain-RBAC baseline for context.
5. Document how the 102 benchmark scenarios were selected from the 145-scenario synthetic generator corpus.

## Inline Annotations

> "The 102 general benchmark scenarios were balanced with 45 ALLOW and 57 DENY scenarios."
**[W5] MINOR:** The repository also contains `evaluation/synthetic/summary.json`, which reports 145 generated scenarios. Please explain how the 102 benchmark cases were selected from the larger corpus, or archive the exact selection script/output so this is reproducible.

> "On the adversarial red-team dataset under standard rule checks, both systems achieved 71.4\% accuracy (10/14 correct), as the baseline's basic signature filters successfully blocked direct prompt injections, SQLi, and RTLO obfuscations that matched regex patterns."
**[W1] MAJOR:** This is a different dataset from the 105-scenario attack suite in `results/red_team_results.json`. The 71.4% figure comes from the 7 manifest red-team files duplicated into 14 runs via `evaluation/benchmark_manifest_204.txt` / `results/results_comparison.json`. Please rename or split the benchmark language so readers do not conflate the two.

> "This block rate is due to two distinct mechanisms: ... 40 out of the 70 cases ... the remaining 30 blocked requests failed the User-Device ACL checks or JWT verification pre-checks, triggering an immediate fail-secure DENY."
**[W2] MAJOR:** `results/red_team_results.json` does not support this 40/30 decomposition. The stored reasons are validation failures such as `Invalid device_type format`, `Invalid device_id format`, `Invalid user_id format`, and injection detections; there is no separate auth/JWT bucket in the artifact.

> "The latency breakdown shows that 46\% of requests are resolved in under 1ms via deterministic validation, whereas camera scenarios requiring full LLM context analysis average 156ms. Sensor scenarios, involving simpler policies, complete in 38ms. The 31.5 RPS throughput observed in the simulated load harness suggests that the system can process moderate concurrent request volumes on a single gateway node, and the low resource usage (94MB memory, $<$1\% CPU) indicates feasibility on modest hardware."
**[W3] MAJOR:** Only the 97 ms / 31.5 RPS / 34-timeout replay is stored in `results/stress_test_results.json`; the camera/sensor split and memory/CPU numbers are not present in `results/`, and `scripts/05_run_stress_test.py` hard-codes the simulated averages. Treat these as synthetic traces unless you add a raw measurement artifact.

> "This baseline represents a modern, security-hardened API gateway capability, rather than a plain RBAC model that only evaluates user roles."
**[W4] MAJOR:** This is fine as positioning, but it is not a plain RBAC baseline. The manuscript should avoid implying a direct RBAC-vs-LLM comparison when the baseline also includes authentication, ACLs, time/network rules, and regex signatures.

> "The reported metrics correspond to repository commit hash \texttt{8e322ee} and scenario-generation seed \texttt{42}."
**[Q3]:** The commit hash appears to exist, but the paper should still point readers to the exact files that encode the benchmark subset and generation procedure, not just the hash and seed.

## Sources
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/manuscript/main_ceur.tex
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/results_comparison.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/results_comparison_single_agent.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/statistical_analysis_report.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/safety_metrics.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/red_team_results.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/red_team_results_unmitigated.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/ablation_results.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/stress_test_results.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/evaluation/benchmark_manifest_204.txt
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/evaluation/synthetic/summary.json
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/scripts/02_evaluate_system.py
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/scripts/03_analyze_results.py
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/scripts/05_run_stress_test.py
- file:///home/lagha/PhD/projects/IoT-Access-Sentinel/scripts/07_generate_unmitigated_red_team.py
