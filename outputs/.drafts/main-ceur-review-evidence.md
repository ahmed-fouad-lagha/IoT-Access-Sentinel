# Evidence Notes: main-ceur

## Sources inspected
- `manuscript/main_ceur.tex`
- `README.md`
- `scripts/02_evaluate_system.py`
- `scripts/03_analyze_results.py`
- `evaluation/benchmark_manifest_204.txt`
- `results/results_comparison.json`
- `results/safety_metrics.json`
- `results/red_team_results.json`
- `results/statistical_analysis_report.json`
- `results/stress_test_results.json`

## Manuscript claims observed
- The paper proposes **IoT-Access-Sentinel**, a hybrid framework combining deterministic validation with multi-agent LLM reasoning for IoT access control.
- It claims a **synthetic benchmark** with **102 test scenarios** plus **105 red-team scenarios**.
- It reports **82.4%** accuracy for an RBAC+Rules baseline and **94.1%** for the hybrid system, with **192/204** correct decisions for the hybrid and **168/204** for baseline.
- It reports **McNemar's test** with **chi-square 16.53** and **p < 0.001**, plus 95% confidence intervals.
- It claims **105/105** red-team attacks were blocked after mitigation, with **70/105** blocked in Layer 0 and **35/105** handled by the policy agent.
- It claims **46%** of requests were resolved by deterministic validation without LLM use.
- It claims **34 API timeouts (24.8%)** under high concurrency, with fail-secure DENY behavior.
- It claims code, benchmark scenarios, and analysis scripts are publicly released at `https://github.com/ahmed-fouad-lagha/IoT-Access-Sentinel`.

## Cross-checks against local artifacts
- `results/results_comparison.json` matches the main accuracy claim:
  - deterministic_only / baseline: **82.3529%**, **168/204**
  - hybrid: **94.1176%**, **192/204**
- `results/safety_metrics.json` matches the safety metrics table:
  - baseline precision **78.7234%**, recall **82.2222%**, false permit rate **17.5439%**
  - hybrid precision **100.0%**, recall **86.6667%**, false permit rate **0.0%**, false deny rate **13.3333%**
- `results/statistical_analysis_report.json` matches the manuscript’s test statistics:
  - chi-square **16.53125**, p-value **< 0.001**, statistically_significant **true**
  - baseline 95% CI approximately **[76.54, 86.97]**; hybrid approximately **[90.00, 96.60]**
- `results/red_team_results.json` matches the adversarial claim at the aggregate level:
  - total **105**, blocked_by_layer0 **70**, detected_by_llm **35**, failed_to_detect **0**, accuracy **1.0**
- `results/stress_test_results.json` matches the synthetic replay claim:
  - total_requests **137**, api_timeouts **34**, availability_rate **75.18%**, average_latency **97.0 ms**, throughput **31.5 RPS**
- `scripts/02_evaluate_system.py` now uses the explicit manifest `evaluation/benchmark_manifest_204.txt` for the RBAC comparison, which makes scenario selection reproducible.
- `evaluation/benchmark_manifest_204.txt` contains **102** scenario files only, with no metadata file mixed in.
- `scripts/03_analyze_results.py` shows that the statistical report and safety metrics are derived from `results/results_comparison.json`, and the current JSON files are consistent with the manuscript’s headline numbers.

## Important observations and gaps
- The benchmark-manifest issue has been fixed: the 204-run comparison is now explicit and scenario-only.
- The manuscript’s quantitative claims are currently synchronized with the checked-in result artifacts.
- The stress-test section correctly distinguishes the simulated replay from a live load test, which is methodologically more honest.
- The renamed `RBAC+Rules Baseline` is still a richer baseline than plain RBAC, but the manuscript explains that explicitly.
- The repository also contains newly generated single-agent result files, but the manuscript does not currently rely on them.
