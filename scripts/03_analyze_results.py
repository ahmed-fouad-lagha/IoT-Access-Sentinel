#!/usr/bin/env python3
"""
Results Analyzer
================
- Safety Metrics (Precision, Recall, False Permit Rate)
- Ablation Study (Component Contribution)
- Statistical Analysis (McNemar's / Chi-square, Confidence Intervals)
"""

import sys
import json
import argparse
import statistics
from pathlib import Path
from typing import Dict

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def run_safety(results_file="results/results_comparison.json"):
    """Calculate safety metrics for both systems"""
    print("\n" + "="*80)
    print("SAFETY METRICS ANALYSIS")
    print("="*80)
    
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    systems = ['rbac', 'hybrid']
    metrics = {}
    
    for system in systems:
        if system not in data:
            continue
        decisions = data[system]['decisions']
        tp = tn = fp = fn = 0
        
        for decision in decisions:
            expected = decision['expected']
            actual = decision['actual']
            if expected == 'ALLOW' and actual == 'ALLOW': tp += 1
            elif expected == 'DENY' and actual == 'DENY': tn += 1
            elif expected == 'DENY' and actual == 'ALLOW': fp += 1
            elif expected == 'ALLOW' and actual == 'DENY': fn += 1
        
        total = tp + tn + fp + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (tn + fp) if (tn + fp) > 0 else 0
        fdr = fn / (tp + fn) if (tp + fn) > 0 else 0
        acc = (tp + tn) / total if total > 0 else 0
        
        metrics[system] = {
            'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn, 'total': total,
            'accuracy': acc * 100, 'precision': precision * 100, 'recall': recall * 100,
            'f1_score': f1 * 100, 'false_permit_rate': fpr * 100, 'false_deny_rate': fdr * 100
        }
    
    print(f"\n{'Metric':<30} {'Baseline':<20} {'Hybrid LLM':<20}")
    print("-" * 70)
    
    rbac = metrics['rbac']
    hybrid = metrics['hybrid']
    
    print(f"\n{'CONFUSION MATRIX:':<30}")
    print(f"{'  True Positives (TP)':<30} {rbac['tp']:<20} {hybrid['tp']:<20}")
    print(f"{'  True Negatives (TN)':<30} {rbac['tn']:<20} {hybrid['tn']:<20}")
    print(f"{'  False Positives (FP)':<30} {rbac['fp']:<20} {hybrid['fp']:<20}")
    print(f"{'  False Negatives (FN)':<30} {rbac['fn']:<20} {hybrid['fn']:<20}")
    
    print(f"\n{'SAFETY METRICS (Critical!):':<30}")
    print(f"{'  False Permit Rate':<30} {rbac['false_permit_rate']:.1f}%{'':<15} {hybrid['false_permit_rate']:.1f}%")
    print(f"{'  False Deny Rate':<30} {rbac['false_deny_rate']:.1f}%{'':<15} {hybrid['false_deny_rate']:.1f}%")
    print("\n" + "="*80)
    
    input_path = Path(results_file)
    if input_path.name == "results_comparison.json":
        out_path = Path('results') / 'safety_metrics.json'
    else:
        suffix = input_path.stem[len("results_comparison"):] if input_path.stem.startswith("results_comparison") else f"_{input_path.stem}"
        out_path = Path('results') / f'safety_metrics{suffix}.json'

    with open(out_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"\nMetrics saved to: {out_path}")


def run_ablation(results_file="results/results_comparison.json"):
    """Analyze ablation study from existing comparison results"""
    print("\n" + "="*80)
    print("ABLATION STUDY ANALYSIS")
    print("="*80)
    
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    rbac_accuracy = (data['rbac']['correct'] / data['rbac']['total']) * 100
    hybrid_correct_non_api = len([d for d in data['hybrid']['decisions'] if d['correct'] and '429' not in d.get('reason', '')])
    hybrid_total_non_api = len([d for d in data['hybrid']['decisions'] if '429' not in d.get('reason', '')])
    hybrid_accuracy = (hybrid_correct_non_api / hybrid_total_non_api) * 100 if hybrid_total_non_api > 0 else 0
    synergy = hybrid_accuracy - rbac_accuracy
    
    deterministic_denies = 0
    llm_adds_value = 0
    rbac_decisions = data['rbac']['decisions']
    hybrid_decisions = data['hybrid']['decisions']
    
    for rbac_dec, hybrid_dec in zip(rbac_decisions[:len(hybrid_decisions)], hybrid_decisions):
        if rbac_dec['actual'] == 'DENY' and rbac_dec['correct']:
            deterministic_denies += 1
        elif not rbac_dec['correct'] and hybrid_dec['correct'] and '429' not in hybrid_dec.get('reason', ''):
            llm_adds_value += 1
            
    print(f"\nComponent Contribution:")
    print(f"  Deterministic pre-check: {deterministic_denies} scenarios (security-critical)")
    print(f"  LLM semantic layer: {llm_adds_value} scenarios (Baseline failed, LLM succeeded)")
    
    print("\nCategory-Wise Contribution:")
    for category, stats in sorted(data['categories'].items()):
        if stats['total'] > 0:
            rbac_cat = (stats['rbac'] / stats['total']) * 100
            hybrid_cat = (stats['hybrid'] / stats['total']) * 100
            print(f"  {category.replace('_', ' ').title():<20}: Baseline {rbac_cat:>5.1f}% | Hybrid {hybrid_cat:>5.1f}% | Δ {hybrid_cat-rbac_cat:>+6.1f}%")

    cost_savings = (deterministic_denies / len(rbac_decisions) * 100) if rbac_decisions else 0
    print(f"\nCost Efficiency:\n   - Deterministic pre-check handles {cost_savings:.0f}% of requests without LLM invocation")
    
    ablation_results = {
        "configurations": {
            "deterministic_only": {"accuracy": rbac_accuracy, "correct": data['rbac']['correct'], "total": data['rbac']['total']},
            "hybrid": {"accuracy": hybrid_accuracy, "correct": hybrid_correct_non_api, "total": hybrid_total_non_api}
        },
        "synergy": synergy, "deterministic_contribution": deterministic_denies, "llm_contribution": llm_adds_value, "cost_savings": cost_savings
    }
    
    input_path = Path(results_file)
    if input_path.name == "results_comparison.json":
        out_path = Path("results/ablation_results.json")
    else:
        suffix = input_path.stem[len("results_comparison"):] if input_path.stem.startswith("results_comparison") else f"_{input_path.stem}"
        out_path = Path('results') / f'ablation_results{suffix}.json'

    with open(out_path, 'w') as f:
        json.dump(ablation_results, f, indent=2)
    print(f"\nAblation results saved to: {out_path}")


def calculate_confidence_interval(successes: int, total: int, confidence: float = 0.95) -> Dict:
    if total == 0: return {"lower": 0, "upper": 0}
    p = successes / total
    z = 1.96 if confidence == 0.95 else 2.576
    denominator = 1 + (z ** 2) / total
    center = (p + (z ** 2) / (2 * total)) / denominator
    margin = (z * ((p * (1 - p) / total + (z ** 2) / (4 * total ** 2)) ** 0.5)) / denominator
    return {"lower": max(0, center - margin) * 100, "upper": min(1, center + margin) * 100, "center": center * 100}

def mcnemar_test(rbac_decisions: list, hybrid_decisions: list) -> Dict:
    a = b = c = d = 0
    for r, h in zip(rbac_decisions, hybrid_decisions):
        r_corr = r["correct"]
        h_corr = h["correct"]
        if r_corr and h_corr: a += 1
        elif r_corr and not h_corr: b += 1
        elif not r_corr and h_corr: c += 1
        else: d += 1
    
    # McNemar's test statistic with continuity correction
    if (b + c) > 0:
        chi_square = (abs(b - c) - 1)**2 / (b + c)
    else:
        chi_square = 0.0
        
    if chi_square > 10.828: return {"chi_square": chi_square, "p_value": "< 0.001", "significant": True, "contingency_table": {"a": a, "b": b, "c": c, "d": d}}
    elif chi_square > 6.635: return {"chi_square": chi_square, "p_value": "< 0.01", "significant": True, "contingency_table": {"a": a, "b": b, "c": c, "d": d}}
    elif chi_square > 3.841: return {"chi_square": chi_square, "p_value": "< 0.05", "significant": True, "contingency_table": {"a": a, "b": b, "c": c, "d": d}}
    return {"chi_square": chi_square, "p_value": "> 0.05", "significant": False, "contingency_table": {"a": a, "b": b, "c": c, "d": d}}

def run_stats(results_file="results/results_comparison.json"):
    print("\n" + "=" * 80)
    print("STATISTICAL ANALYSIS")
    print("=" * 80)
    
    with open(results_file) as f:
        data = json.load(f)
        
    total_tests = data['rbac']['total']
    baseline_correct = data['rbac']['correct']
    llm_correct = data['hybrid']['correct']
    
    baseline_accuracy = (baseline_correct / total_tests) * 100
    llm_accuracy = (llm_correct / total_tests) * 100
    improvement = llm_accuracy - baseline_accuracy
    
    mcnemar_result = mcnemar_test(data['rbac']['decisions'], data['hybrid']['decisions'])
    baseline_ci = calculate_confidence_interval(baseline_correct, total_tests)
    llm_ci = calculate_confidence_interval(llm_correct, total_tests)
    
    print(f"\nMcNemar's Test (with continuity correction):")
    print(f"  - Contingency Table: a={mcnemar_result['contingency_table']['a']}, b={mcnemar_result['contingency_table']['b']}, c={mcnemar_result['contingency_table']['c']}, d={mcnemar_result['contingency_table']['d']}")
    print(f"  - Statistic: {mcnemar_result['chi_square']:.4f} | p-value: {mcnemar_result['p_value']}")
    print(f"  - Significant Difference: {'YES ✓' if mcnemar_result['significant'] else 'NO ✗'}")
    
    print(f"\nConfidence Intervals (95%):")
    print(f"  Baseline: {baseline_accuracy:.1f}% [{baseline_ci['lower']:.1f}%, {baseline_ci['upper']:.1f}%]")
    print(f"  Hybrid:   {llm_accuracy:.1f}% [{llm_ci['lower']:.1f}%, {llm_ci['upper']:.1f}%]")
    
    summary = {
        "overall": {
            "total_tests": total_tests, "baseline_accuracy": baseline_accuracy, "llm_accuracy": llm_accuracy,
            "improvement": improvement, "chi_square": mcnemar_result['chi_square'], "p_value": mcnemar_result['p_value'],
            "statistically_significant": mcnemar_result['significant']
        },
        "contingency_table": mcnemar_result['contingency_table'],
        "confidence_intervals_95": {"baseline": baseline_ci, "llm": llm_ci}
    }
    
    input_path = Path(results_file)
    if input_path.name == "results_comparison.json":
        out_path = Path("results/statistical_analysis_report.json")
    else:
        suffix = input_path.stem[len("results_comparison"):] if input_path.stem.startswith("results_comparison") else f"_{input_path.stem}"
        out_path = Path('results') / f'statistical_analysis_report{suffix}.json'

    with open(out_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nStatistical report saved to: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="IoT Access Sentinel Analysis Suite")
    parser.add_argument("--mode", type=str, required=True, 
                        choices=['safety', 'ablation', 'stats', 'all'],
                        help="Analysis mode to run")
    parser.add_argument("--file", type=str, default="results/results_comparison.json",
                        help="Input comparison results file")
    args = parser.parse_args()
    
    if not Path(args.file).exists():
        print(f"Error: {args.file} not found. Run scripts/02_evaluate_system.py first.")
        sys.exit(1)
        
    if args.mode in ['safety', 'all']: run_safety(args.file)
    if args.mode in ['ablation', 'all']: run_ablation(args.file)
    if args.mode in ['stats', 'all']: run_stats(args.file)

if __name__ == "__main__":
    main()
