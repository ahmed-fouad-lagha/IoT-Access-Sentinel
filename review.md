## Summary
The manuscript presents IoT-Access-Sentinel, a two-stage IoT access-control pipeline that combines deterministic Layer 0 checks (authentication, normalization, allowlists, network/time rules) with Layer 1 multi-agent LLM reasoning for semantically ambiguous requests. The evaluation is based on a synthetic Wazuh-driven benchmark, including a red-team suite, and reports improved accuracy and prompt-injection resilience relative to a rule-based baseline.

The revised draft is noticeably better scoped than a generic “LLM is secure” paper: it now states that the evaluation is synthetic, benchmark-specific, and not a general security guarantee. The remaining concerns are mostly about how strongly the results are phrased, whether the baseline is being described fairly, and whether the manifest-based benchmark protocol is being presented with enough clarity about what is actually counted.

## Strengths
- [S1] The paper now repeatedly qualifies its security claims as benchmark-specific. For example, the threat-model and adversarial-evaluation sections explicitly say the results “do not constitute a generalized security guarantee,” which is the right direction for a security paper with synthetic tests.
- [S2] The reproducibility story is unusually concrete: the paper names the manifest file, the evaluation scripts, a commit hash, a seed, and the saved stress-test outputs. That is better evidence than a generic “code will be released” statement.
- [S3] The baseline is not a strawman pure-RBAC comparator. The manuscript explicitly says the baseline includes authentication, time/network rules, and signature filtering, which is more defensible than comparing against role checks alone.

## Weaknesses
- [W1] **MAJOR:** The manuscript still occasionally overstates robustness in ways that outrun the evidence. Phrases like “100% defense rate” and “handled all evaluated evasion attempts” are too easy to read as broad security claims, even though the evidence is only for a synthetic, author-defined red-team suite. The draft does include caveats elsewhere, but the strongest summary statements should repeat those caveats so they are not misread as general guarantees.
- [W2] **MAJOR:** The baseline is fair only if it is framed as a rule-hardened comparator, not as “production-representative” parity with the hybrid system. The code for `baseline_rbac.py` uses heuristic token checks and a lenient time parser, so the manuscript’s wording can overstate how close this baseline is to a real security gateway. The baseline label itself is acceptable; the stronger claim about production representativeness is the problem.
- [W3] **MAJOR:** The manifest-backed benchmark protocol has hidden scope and independence issues. The manifest includes a non-scenario `summary.json` artifact, and the evaluation script duplicates each file twice, so the raw 204-run count is not the effective sample size. If the paper is using those repeated runs in significance testing and accuracy reporting, it should say so explicitly and report the filtered scenario count after skipping non-scenario entries.
- [W4] **MINOR:** The reproducibility claim is slightly overconfident if it implies that commit hash + seed fully pin the hybrid results. The hybrid pipeline depends on an external LLM API, so a seed does not freeze model revisions, backend routing, or sampling behavior. The reproducibility section should scope this more carefully to stored result files or a frozen API snapshot.

## Questions for Authors
- [Q1] After filtering the manifest, how many entries are actual scored scenarios versus auxiliary artifacts like `summary.json`?
- [Q2] Were the duplicated cached/uncached passes used only for cache verification, or did they also enter the headline accuracy and McNemar analysis? If they did, how do you justify the implied dependence structure?
- [Q3] Can you clarify which specific baseline behaviors are heuristic shortcuts rather than cryptographic or formally validated checks?
- [Q4] Which exact external LLM/version produced the reported results, and are the released result files sufficient to reproduce the same numbers if the API behavior changes later?

## Verdict
Borderline accept for a workshop-style venue such as ITAT/CEUR, provided W1–W3 are tightened. As written, it is not yet strong enough for a top-tier security venue because the strongest robustness and reproducibility claims remain a little too loose. Confidence: 0.81.

## Revision Plan
1. Rewrite the highest-level robustness statements so they always include the benchmark scope.
2. Recast the baseline as “RBAC+rules” and explicitly distinguish heuristic checks from deterministic/authenticated checks.
3. Explain the manifest filtering and the duplicated-pass protocol, and report the effective number of scored scenarios after filtering.
4. Add a reproducibility note that external LLM variability is not fixed by the repository seed alone.

## Inline Annotations

> “Evaluating the system on a synthetic benchmark, we show that while the LLM reasoning layer alone is vulnerable to prompt injection, pairing a deterministic validation pre-filter with strict semantic delimiters improves robustness under the benchmark threat model.”
**[W1] MAJOR:** Good caveat, but the rest of the paper still uses stronger language like “100% defense rate” and “handled all evaluated evasion attempts.” Please keep the benchmark limitation attached whenever robustness is summarized.

> “This baseline represents a modern, security-hardened API gateway capability, rather than a plain RBAC model that only evaluates user roles.”
**[W2] MAJOR:** The baseline is indeed more than plain RBAC, but the code is still heuristic in places (for example, token checks are not cryptographic JWT verification, and malformed timestamps can be treated leniently). “Security-hardened” is stronger than the implementation supports.

> “The 204-run benchmark comparison is pinned by the explicit manifest file `evaluation/benchmark_manifest_204.txt`.”
**[W3] MAJOR:** The manifest is not a pure list of scored scenarios: it includes `summary.json`, and the runner skips files without `expected_decision`. Also, each scenario is duplicated for cached/uncached replay, so the raw run count should not be treated as an independent sample size.

> “The reported metrics correspond to repository commit hash `8d2f7a9e` (using random seed `42` for data generation).”
**[W4] MINOR:** The seed helps with scenario generation, but it does not pin external LLM behavior or API revisions. If reproducibility matters, specify the exact model/API snapshot or point to the stored result files as the canonical artifact.

## Sources
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/manuscript/main_ceur.tex`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/README.md`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/decision_engine/baseline_rbac.py`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/decision_engine/validators/user_auth_validator.py`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/decision_engine/decision_pipeline.py`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/common/validation.py`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/evaluation/benchmark_manifest_204.txt`
- `file:///home/lagha/PhD/projects/IoT-Access-Sentinel/scripts/02_evaluate_system.py`
