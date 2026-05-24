"""
Rebuild results_comparison.json from the correct baseline_comparison_report.json
This replaces the stale data from before the LLM pipeline was fixed.
"""
import json
from pathlib import Path
from collections import Counter


def rebuild():
    report_path = Path("results/baseline_comparison_report.json")
    if not report_path.exists():
        print("results/baseline_comparison_report.json not found!")
        return

    with open(report_path) as f:
        report = json.load(f)

    rbac_decisions = []
    hybrid_decisions = []

    for item in report["test_results"]:
        expected = item["expected"]

        rbac_actual = item["baseline"]["action"]
        rbac_decisions.append({"expected": expected, "actual": rbac_actual})

        llm_actual = item["llm"]["action"]
        hybrid_decisions.append({"expected": expected, "actual": llm_actual})

    rbac_correct = sum(1 for d in rbac_decisions if d["expected"] == d["actual"])
    hybrid_correct = sum(1 for d in hybrid_decisions if d["expected"] == d["actual"])
    total = len(rbac_decisions)

    print(f"RBAC:   {rbac_correct}/{total} = {rbac_correct/total*100:.2f}%")
    print(f"Hybrid: {hybrid_correct}/{total} = {hybrid_correct/total*100:.2f}%")

    hybrid_expected = Counter(d["expected"] for d in hybrid_decisions)
    hybrid_actual = Counter(d["actual"] for d in hybrid_decisions)
    print(f"\nHybrid expected distribution: {dict(hybrid_expected)}")
    print(f"Hybrid actual distribution:   {dict(hybrid_actual)}")

    # Build category breakdown (all go to 'synthetic' for now)
    results = {
        "rbac": {
            "correct": rbac_correct,
            "total": total,
            "decisions": rbac_decisions,
        },
        "hybrid": {
            "correct": hybrid_correct,
            "total": total,
            "decisions": hybrid_decisions,
        },
        "categories": {
            "synthetic": {"rbac": rbac_correct, "hybrid": hybrid_correct, "total": total}
        },
    }

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / "results_comparison.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ results/results_comparison.json rebuilt successfully.")


if __name__ == "__main__":
    rebuild()
