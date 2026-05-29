# Review: `manuscript/main_ceur.tex`

## Summary Assessment
This is a technically plausible systems paper with a coherent architecture: deterministic pre-checks, LLM-based contextual reasoning, and Wazuh integration. The supporting code and result artifacts are present, and the benchmark selection is now reproducible through an explicit manifest.

Unlike the earlier draft state, the current manuscript is now **consistent with the checked-in result artifacts**. The headline numbers in the Results section align with `results/results_comparison.json`, `results/safety_metrics.json`, `results/red_team_results.json`, and `results/statistical_analysis_report.json`. The stress-test section is also appropriately framed as a simulated replay rather than a live load test.

My overall assessment is **positive but cautious**: the engineering is real, the reproducibility story is much better than before, and the quantitative claims are now internally supported by the repository. The main remaining caution is that the evidence is still synthetic/simulated rather than a live deployment evaluation.

## Strengths
- **Clear system design.** The Observe → Decide → Act decomposition is easy to follow, and the code supports it directly.
- **Deterministic containment is a good design choice.** The Layer 0 pre-checks are a defensible way to reduce exposure of the LLM path.
- **Reproducibility improved materially.** The benchmark selection is pinned by an explicit 102-file scenario manifest, which is a substantial quality improvement.
- **Reported metrics align with the stored artifacts.** The accuracy, safety, adversarial, and statistical claims match the current JSON result files.
- **The manuscript now states limitations more honestly.** It acknowledges synthetic evaluation and the lack of live edge/hardware validation.

## Critical Issues
1. **The evaluation remains synthetic rather than field-tested.**
   - The manuscript does not claim live deployment validation, and that is appropriate.
   - But the security and performance conclusions are still limited to synthetic alerts and a simulated replay harness, so broad operational generalization would be premature.

2. **The baseline is broader than plain RBAC.**
   - The paper now labels it `RBAC+Rules Baseline`, which is better and more honest.
   - Still, the baseline includes authentication, time/network constraints, and signature filtering, so readers should not interpret it as a minimal RBAC-only control.

## Major Issues
- **The reported gains are benchmark-specific.**
  - The red-team and performance results are useful, but they are generated under author-defined scenarios.
  - The manuscript correctly warns about this, but the discussion should continue to avoid implying general security guarantees beyond the benchmark.

- **The stress-test numbers are simulation-derived.**
  - The manuscript now says this clearly, which is good.
  - Nevertheless, the exact latency and throughput values should be read as synthetic replay outputs, not as independently observed production measurements.

- **The related-work comparison table is informative but still heterogeneous.**
  - The table compares systems that solve different subproblems (policy translation, auto-configuration, and runtime access control).
  - The manuscript acknowledges that the metrics are not directly comparable, which is the right caveat.

## Minor Issues
- The results section could briefly explain why the 102 scenarios become 204 runs, even though the repetition is already inferable from the analysis script.
- The confidence wording around the LLM layer is carefully hedged, but it would still benefit from a short calibration note if the verbalized confidence is ever used in future work.
- The manuscript still reads slightly optimistic in the discussion sections relative to the synthetic scope, though this is much improved from the earlier version.

## Reproducibility and Verification
**Verification status: PARTIAL but strong**

What I verified:
- `results/results_comparison.json` matches the manuscript’s accuracy numbers.
- `results/safety_metrics.json` matches the manuscript’s precision/recall/false-permit table.
- `results/statistical_analysis_report.json` matches the manuscript’s McNemar statistic and confidence intervals.
- `results/red_team_results.json` matches the adversarial aggregate claim.
- `results/stress_test_results.json` supports the synthetic replay figures.
- `scripts/02_evaluate_system.py` now uses `evaluation/benchmark_manifest_204.txt`, making the benchmark selection explicit.
- `evaluation/benchmark_manifest_204.txt` contains 102 scenario files only.

What I did not independently run:
- I did not rerun the full benchmark end-to-end.
- I did not rebuild the LaTeX PDF.
- I did not audit any external GitHub repository referenced in the paper.

Bottom line: the repository now supports the manuscript’s main claims much better than before, and the reproducibility path is reasonably clear for a synthetic benchmark paper.

## Inline Annotations
- **Abstract / Introduction**: Strong framing, and now appropriately cautious about synthetic evaluation.
- **Evaluation Methodology**: The 102-scenario / 204-run structure is plausible and now reproducible via the manifest.
- **Results, Table 1**: The accuracy numbers are consistent with `results/results_comparison.json`.
- **Results, Table 2 / Safety Metrics**: The safety metrics are consistent with `results/safety_metrics.json`.
- **Results, McNemar discussion**: The significance statement is supported by `results/statistical_analysis_report.json`.
- **Safety-Critical Metrics Analysis**: The stress replay is correctly labeled as simulated, not live.
- **Reproducibility and Open-Source Artifacts**: The manifest pinning is the right direction and materially strengthens the paper.

## Recommendation
**Accept with minor revisions**

Reason: the manuscript is now internally consistent with the checked-in artifacts, and the reproducibility story is substantially improved. The remaining concerns are mostly about scope and generalization beyond the synthetic benchmark, not about internal validity.

## Sources
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/manuscript/main_ceur.tex`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/README.md`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/scripts/02_evaluate_system.py`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/scripts/03_analyze_results.py`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/evaluation/benchmark_manifest_204.txt`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/results_comparison.json`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/safety_metrics.json`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/red_team_results.json`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/statistical_analysis_report.json`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/results/stress_test_results.json`
