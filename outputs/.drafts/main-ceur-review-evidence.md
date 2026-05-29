# Evidence Notes: main-ceur

## Sources inspected
- `manuscript/main_ceur.tex`
- `README.md`
- `results/results_comparison.json`
- `results/ablation_results.json`
- `results/red_team_results.json`
- `results/safety_metrics.json`
- `results/statistical_analysis_report.json`
- `decision_engine/decision_pipeline.py`
- `decision_engine/validators/user_auth_validator.py`
- `decision_engine/agents/context_agent.py`
- `decision_engine/agents/policy_agent.py`
- `decision_engine/baseline_rbac.py`
- `common/validation.py`
- `enforcer/actions.py`
- `evaluation/run_tests.sh`

## Manuscript claims observed
- The paper proposes **IoT-Access-Sentinel**, a hybrid framework combining deterministic validation with multi-agent LLM reasoning for IoT access control.
- It claims a **synthetic benchmark** with **102 test scenarios** plus **105 red-team scenarios**.
- It reports **82.4%** accuracy for an RBAC baseline and **94.1%** for the hybrid system, with **192/204** correct decisions for the hybrid and **168/204** for baseline.
- It reports **McNemar’s test** with **chi-square 16.53** and **p < 0.001**, plus 95% confidence intervals.
- It claims **105/105** red-team attacks were blocked after mitigation, with **70/105** blocked in Layer 0 and **35/105** handled by the policy agent.
- It claims **46%** of requests were resolved by deterministic validation without LLM use.
- It claims **34 API timeouts (24.8%)** under high concurrency, with fail-secure DENY behavior.
- It claims code, benchmark scenarios, and analysis scripts are publicly released at `https://github.com/ahmed-fouad-lagha/IoT-Access-Sentinel`.

## Cross-checks against local artifacts
- `results/results_comparison.json` matches the main accuracy claim:
  - deterministic_only: **82.3529%**, **168/204**
  - hybrid: **94.1176%**, **192/204**
  - synergy/cost_savings: **11.7647%** / **46.0784%**
- `results/safety_metrics.json` matches the safety metrics table:
  - baseline precision **78.7234%**, recall **82.2222%**, false permit rate **17.5439%**
  - hybrid precision **100.0%**, recall **86.6667%**, false permit rate **0.0%**, false deny rate **13.3333%**
- `results/statistical_analysis_report.json` matches the manuscript’s test statistics:
  - chi-square **16.53125**, p-value **< 0.001**, statistically_significant **true**
  - baseline 95% CI approximately **[76.54, 86.97]**; hybrid approximately **[90.00, 96.60]**
- `results/red_team_results.json` matches the adversarial claim at the aggregate level:
  - total **105**, blocked_by_layer0 **70**, detected_by_llm **35**, failed_to_detect **0**, accuracy **1.0**
- `decision_engine/decision_pipeline.py` supports the architecture description:
  - deterministic user-auth pre-check before LLM reasoning
  - TTL semantic cache (`ttl=3600`)
  - fail-secure DENY on context or policy agent exceptions
  - deterministic time/network checks before or alongside the LLM path
- `decision_engine/validators/user_auth_validator.py` shows deterministic user/device authorization and JWT verification.
- `common/validation.py` includes Unicode normalization / RTLO / hidden-character detection consistent with the manuscript’s Layer 0 description.
- `decision_engine/agents/context_agent.py` and `policy_agent.py` show two distinct LLM roles with JSON outputs.
- `enforcer/actions.py` shows Wazuh active response / firewall-drop enforcement.
- `evaluation/run_tests.sh` is a simpler test runner for 8 scenarios and does not appear to generate the paper’s reported 204-run metrics.

## Important observations and gaps
- The manuscript’s headline metrics are **consistent with the local result JSON files**, but I did **not rerun** the benchmark end-to-end in this review.
- The **34 API timeouts** / **24.8%** availability claim appears in the manuscript and README, but I did not find a dedicated machine-readable results artifact for it in `results/`.
- The paper describes the baseline as “RBAC”, but `decision_engine/baseline_rbac.py` is broader than pure RBAC: it also includes token checks and simple attack-pattern detection. That matters for fairness/labeling.
- The red-team suite is synthetic and the manuscript’s narrative sometimes attributes all 70 Layer-0 blocks to normalization/blocklists, but `user_auth_validator.py` also denies missing user IDs, invalid tokens, and device-policy mismatches. The explanation is directionally right but not fully decomposed.
- The paper’s reproducibility statement is better than average because code and result artifacts exist locally, but it does not give a commit hash, dataset seed, or a single canonical script that obviously regenerates every reported number.
