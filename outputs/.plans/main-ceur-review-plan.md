# Review Plan: main-ceur

## Artifact
- **Identifier:** `manuscript/main_ceur.tex`
- **Source type:** Local LaTeX manuscript
- **Related artifacts inspected:** `README.md`, `scripts/02_evaluate_system.py`, `scripts/03_analyze_results.py`, `evaluation/benchmark_manifest_204.txt`, `results/results_comparison.json`, `results/safety_metrics.json`, `results/red_team_results.json`, `results/statistical_analysis_report.json`, `results/stress_test_results.json`

## Review Criteria
1. **Novelty** — whether the contribution is meaningfully distinct from prior LLM-assisted access control and whether the framing overclaims originality.
2. **Empirical rigor** — whether the benchmark design, measurement setup, and reported statistics are sufficiently described and credible.
3. **Baselines** — whether the comparison set is fair, relevant, and close enough to prior art.
4. **Reproducibility** — whether the paper exposes enough artifact detail to rerun or audit the results.
5. **Claims validity** — whether the narrative claims match the code/results artifacts and whether any numbers are unsupported or inconsistent.
6. **Figures/tables** — whether figures and tables are internally consistent with the text and data artifacts.
7. **Metrics** — whether the reported accuracy, statistical tests, latency, and safety metrics are explained and traceable.
8. **Related work** — whether the paper positions itself correctly against the most relevant literature and prior systems.
9. **Writing quality** — whether the manuscript is clear, precise, and free of misleading phrasing.

## Verification Checks
- Trace headline quantitative claims against local result artifacts or code:
  - accuracy values, McNemar test, confidence intervals, adversarial detection rates, cost savings, latency, throughput, timeout counts
- Check whether the baseline is fairly defined and whether the renamed `RBAC+Rules Baseline` is consistent with the code.
- Verify whether the benchmark scenario selection is pinned by the manifest and whether the manifest contains only scenario files.
- Check whether figure/table values and text are aligned with the current artifact state.
- Inspect linked code and analysis scripts that materially affect the claims.
- Record unverified or blocked items explicitly rather than inferring them.
