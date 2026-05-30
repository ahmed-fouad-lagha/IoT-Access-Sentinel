#!/usr/bin/env python3
"""
Confidence Calibration Analysis for IoT-Access-Sentinel
========================================================
Computes Expected Calibration Error (ECE) from the hybrid system's
verbalized semantic confidence scores recorded in results_comparison.json.

Generates:
  - results/calibration_analysis.json  (ECE, per-bin stats)

Usage:
    python3 scripts/08_calibration_analysis.py
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))


def load_hybrid_decisions(results_file: Path) -> list:
    """Extract hybrid decisions with confidence and correctness."""
    with open(results_file, "r") as f:
        data = json.load(f)
    
    decisions = data.get("hybrid", {}).get("decisions", [])
    records = []
    for d in decisions:
        conf = d.get("confidence")
        correct = d.get("correct")
        if conf is not None and correct is not None:
            records.append({
                "confidence": float(conf),
                "correct": bool(correct),
                "action": d.get("actual", "UNKNOWN"),
                "expected": d.get("expected", "UNKNOWN"),
            })
    return records


def compute_ece(records: list, n_bins: int = 10) -> dict:
    """
    Compute Expected Calibration Error (ECE) with equal-width bins.
    
    ECE = sum_{b=1}^{B} (n_b / N) * |acc_b - conf_b|
    
    Where:
      - B = number of bins
      - n_b = number of samples in bin b
      - N = total number of samples
      - acc_b = accuracy of bin b
      - conf_b = average confidence of bin b
    """
    N = len(records)
    if N == 0:
        return {"ece": 0.0, "bins": [], "n_samples": 0}
    
    bin_width = 1.0 / n_bins
    bins = defaultdict(lambda: {"confidences": [], "correct": [], "count": 0})
    
    for r in records:
        bin_idx = min(int(r["confidence"] / bin_width), n_bins - 1)
        bins[bin_idx]["confidences"].append(r["confidence"])
        bins[bin_idx]["correct"].append(1.0 if r["correct"] else 0.0)
        bins[bin_idx]["count"] += 1
    
    ece = 0.0
    bin_details = []
    
    for b in range(n_bins):
        bin_data = bins[b]
        n_b = bin_data["count"]
        
        if n_b == 0:
            bin_details.append({
                "bin_index": b,
                "bin_range": f"[{b * bin_width:.1f}, {(b + 1) * bin_width:.1f})",
                "count": 0,
                "avg_confidence": None,
                "accuracy": None,
                "calibration_gap": None
            })
            continue
        
        avg_conf = sum(bin_data["confidences"]) / n_b
        acc = sum(bin_data["correct"]) / n_b
        gap = abs(acc - avg_conf)
        ece += (n_b / N) * gap
        
        bin_details.append({
            "bin_index": b,
            "bin_range": f"[{b * bin_width:.1f}, {(b + 1) * bin_width:.1f})",
            "count": n_b,
            "avg_confidence": round(avg_conf, 4),
            "accuracy": round(acc, 4),
            "calibration_gap": round(gap, 4)
        })
    
    return {
        "ece": round(ece, 4),
        "n_bins": n_bins,
        "n_samples": N,
        "bins": bin_details
    }


def compute_confidence_distribution(records: list) -> dict:
    """Compute distribution statistics of confidence scores."""
    confs = [r["confidence"] for r in records]
    correct_confs = [r["confidence"] for r in records if r["correct"]]
    incorrect_confs = [r["confidence"] for r in records if not r["correct"]]
    
    def stats(values):
        if not values:
            return {"count": 0, "mean": None, "min": None, "max": None}
        return {
            "count": len(values),
            "mean": round(sum(values) / len(values), 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4),
        }
    
    return {
        "all": stats(confs),
        "correct_decisions": stats(correct_confs),
        "incorrect_decisions": stats(incorrect_confs),
    }


def main():
    results_file = Path("results/results_comparison.json")
    if not results_file.exists():
        print(f"ERROR: {results_file} not found. Run the evaluation first.")
        sys.exit(1)
    
    print("=" * 60)
    print("IoT-Access-Sentinel Confidence Calibration Analysis")
    print("=" * 60)
    
    records = load_hybrid_decisions(results_file)
    print(f"Loaded {len(records)} hybrid decisions with confidence scores.\n")
    
    if not records:
        print("ERROR: No decisions with confidence scores found.")
        sys.exit(1)
    
    # Compute ECE
    ece_result = compute_ece(records, n_bins=10)
    print(f"Expected Calibration Error (ECE): {ece_result['ece']:.4f}")
    print(f"Number of bins: {ece_result['n_bins']}")
    print(f"Number of samples: {ece_result['n_samples']}")
    
    print(f"\n{'Bin Range':<15} {'Count':>6} {'Avg Conf':>10} {'Accuracy':>10} {'Gap':>8}")
    print("-" * 55)
    for b in ece_result["bins"]:
        if b["count"] > 0:
            print(f"{b['bin_range']:<15} {b['count']:>6} {b['avg_confidence']:>10.4f} {b['accuracy']:>10.4f} {b['calibration_gap']:>8.4f}")
        else:
            print(f"{b['bin_range']:<15} {b['count']:>6} {'---':>10} {'---':>10} {'---':>8}")
    
    # Confidence distribution
    conf_dist = compute_confidence_distribution(records)
    print(f"\nConfidence Distribution:")
    print(f"  All decisions:       mean={conf_dist['all']['mean']}, range=[{conf_dist['all']['min']}, {conf_dist['all']['max']}]")
    if conf_dist['correct_decisions']['count'] > 0:
        print(f"  Correct decisions:   mean={conf_dist['correct_decisions']['mean']}, n={conf_dist['correct_decisions']['count']}")
    if conf_dist['incorrect_decisions']['count'] > 0:
        print(f"  Incorrect decisions: mean={conf_dist['incorrect_decisions']['mean']}, n={conf_dist['incorrect_decisions']['count']}")
    
    # Interpretation
    ece_val = ece_result["ece"]
    if ece_val < 0.05:
        calibration_quality = "well-calibrated"
    elif ece_val < 0.15:
        calibration_quality = "moderately calibrated"
    elif ece_val < 0.30:
        calibration_quality = "poorly calibrated"
    else:
        calibration_quality = "severely miscalibrated"
    
    print(f"\nInterpretation: ECE = {ece_val:.4f} → Confidence scores are {calibration_quality}.")
    
    # Overconfidence analysis
    overconfident_bins = [b for b in ece_result["bins"] if b["count"] > 0 and b["avg_confidence"] is not None and b["accuracy"] is not None and b["avg_confidence"] > b["accuracy"]]
    underconfident_bins = [b for b in ece_result["bins"] if b["count"] > 0 and b["avg_confidence"] is not None and b["accuracy"] is not None and b["avg_confidence"] < b["accuracy"]]
    
    if overconfident_bins:
        print(f"  Overconfident bins: {len(overconfident_bins)} (confidence > accuracy)")
    if underconfident_bins:
        print(f"  Underconfident bins: {len(underconfident_bins)} (confidence < accuracy)")
    
    # Save results
    output = {
        "calibration": ece_result,
        "confidence_distribution": conf_dist,
        "interpretation": {
            "ece": ece_val,
            "quality": calibration_quality,
            "overconfident_bins": len(overconfident_bins),
            "underconfident_bins": len(underconfident_bins),
        }
    }
    
    out_dir = Path("results")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "calibration_analysis.json"
    with open(out_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {out_file}")


if __name__ == "__main__":
    main()
