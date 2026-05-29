# Review Plan: main-ceur

## Artifact
- **Identifier:** `manuscript/main_ceur.tex`
- **Source type:** Local LaTeX manuscript
- **Related local artifacts inspected:** `manuscript/main_ceur.pdf`, `manuscript/architecture.pdf`, `manuscript/references.bib`, `README.md`, `results/*.json`, core code under `decision_engine/`, `common/`, `enforcer/`, and `evaluation/`

## Review Criteria
1. **Novelty** — whether the paper’s contribution is meaningfully distinct from prior LLM-assisted access control and whether the framing overclaims originality.
2. **Empirical rigor** — whether the benchmark design, measurement setup, and reported statistics are sufficiently described and credible.
3. **Baselines** — whether the comparison set is fair, relevant, and close enough to prior art.
4. **Reproducibility** — whether the paper exposes enough artifact detail to rerun or audit the results.
5. **Claims validity** — whether the narrative claims match the code/results artifacts and whether any numbers are unsupported or inconsistent.
6. **Figures/tables** — whether figures and tables are internally consistent with the text and data artifacts.
7. **Metrics** — whether the reported accuracy, statistical tests, latency, and safety metrics are explained and traceable.
8. **Related work** — whether the paper positions itself correctly against the most relevant literature and prior systems.
9. **Writing quality** — whether the manuscript is clear, precise, and free of misleading phrasing.

## Verification Checks
- Trace all headline quantitative claims in the manuscript against local result artifacts or code:
  - accuracy values, confusion-matrix metrics, McNemar test, confidence intervals, adversarial detection rates, cost savings, latency, throughput, and timeout counts
- Inspect whether the benchmark counts are internally consistent:
  - 102 functional scenarios, 105 red-team scenarios, 204 total runs, 94.1% / 82.4% accuracy, 70/105 layer-0 detections, 35/105 semantic detections
- Check whether the baseline is fairly defined and whether it is truly an RBAC baseline or a richer rule-based system.
- Check whether the paper’s claims about reproducibility are backed by accessible code, scenarios, result files, and explicit configuration details.
- Check whether figures/tables correspond to code/data and whether any chart/table values are likely hand-authored rather than derived.
- Inspect linked or cited artifacts that materially affect review quality when reachable (code, results JSON, evaluation scripts, README, bibliography).
- Record any unverified or blocked items explicitly rather than inferring them.

## Method
1. Read the manuscript directly and identify major claims, tables, figures, and limitations.
2. Inspect the repository files that substantiate the evaluation and system architecture.
3. Compare manuscript claims with `results/*.json`, key implementation files, and evaluation scripts.
4. Draft evidence notes before the final review.
5. Write the final review with clear strengths, weaknesses, reproducibility notes, and a recommendation.
