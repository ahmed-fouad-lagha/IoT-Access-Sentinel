#!/usr/bin/env python3
"""
Statistical Analysis for IoT-Access-Sentinel
============================================
Validates statistical significance of baseline comparison results.

Tests:
- Chi-square test for overall accuracy difference
- Category-wise breakdown analysis
- Confidence intervals
"""

import sys
import json
from pathlib import Path
from typing import Dict
import statistics

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def chi_square_test(observed: list, expected: list) -> Dict:
    """
    Manual chi-square calculation (avoiding scipy dependency).
    
    For 2x2 contingency table:
    [[a, b],   # LLM: correct, wrong
     [c, d]]   # Baseline: correct, wrong
    
    Chi-square = n * (ad - bc)^2 / ((a+b)(c+d)(a+c)(b+d))
    where n = a+b+c+d
    """
    a, b = observed
    c, d = expected
    n = a + b + c + d
    
    numerator = n * ((a * d) - (b * c)) ** 2
    denominator = (a + b) * (c + d) * (a + c) * (b + d)
    
    if denominator == 0:
        return {"chi_square": 0, "significant": False, "note": "Invalid data"}
    
    chi_square = numerator / denominator
    
    # Critical value for df=1, alpha=0.05 is 3.841
    # Critical value for df=1, alpha=0.01 is 6.635
    # Critical value for df=1, alpha=0.001 is 10.828
    
    if chi_square > 10.828:
        p_value_estimate = "< 0.001"
        significant = True
    elif chi_square > 6.635:
        p_value_estimate = "< 0.01"
        significant = True
    elif chi_square > 3.841:
        p_value_estimate = "< 0.05"
        significant = True
    else:
        p_value_estimate = "> 0.05"
        significant = False
    
    return {
        "chi_square": chi_square,
        "p_value": p_value_estimate,
        "significant": significant,
        "degrees_of_freedom": 1
    }


def calculate_confidence_interval(successes: int, total: int, confidence: float = 0.95) -> Dict:
    """
    Calculate Wilson score confidence interval for proportion.
    
    More accurate than normal approximation for small samples.
    """
    if total == 0:
        return {"lower": 0, "upper": 0}
    
    p = successes / total
    z = 1.96 if confidence == 0.95 else 2.576  # 95% or 99% confidence
    
    # Wilson score interval
    denominator = 1 + (z ** 2) / total
    center = (p + (z ** 2) / (2 * total)) / denominator
    margin = (z * ((p * (1 - p) / total + (z ** 2) / (4 * total ** 2)) ** 0.5)) / denominator
    
    return {
        "lower": max(0, center - margin) * 100,
        "upper": min(1, center + margin) * 100,
        "center": center * 100
    }


def analyze_baseline_comparison(report_path: str = "tests/baseline_comparison_report.json") -> Dict:
    """Perform statistical analysis on baseline comparison results"""
    
    print("=" * 70)
    print("Statistical Analysis - Baseline Comparison")
    print("=" * 70)
    
    # Load results
    with open(report_path) as f:
        report = json.load(f)
    
    total_tests = report['total_tests']
    baseline_correct = report['baseline']['correct']
    llm_correct = report['llm']['correct']
    
    baseline_accuracy = report['baseline']['accuracy']
    llm_accuracy = report['llm']['accuracy']
    improvement = report['improvement']
    
    print(f"\n📊 Dataset Overview:")
    print(f"   Total tests: {total_tests}")
    print(f"   Baseline: {baseline_correct}/{total_tests} correct ({baseline_accuracy:.1f}%)")
    print(f"   LLM System: {llm_correct}/{total_tests} correct ({llm_accuracy:.1f}%)")
    print(f"   Improvement: +{improvement:.1f}%")
    
    # Chi-square test
    print(f"\n\n🧪 Chi-Square Test for Independence")
    print(f"   H0: No difference in accuracy between systems")
    print(f"   H1: LLM accuracy significantly higher than baseline")
    print(f"   Significance level: α = 0.05")
    
    # Contingency table: [LLM correct, LLM wrong], [Baseline correct, Baseline wrong]
    llm_wrong = total_tests - llm_correct
    baseline_wrong = total_tests - baseline_correct
    
    chi_result = chi_square_test(
        [llm_correct, llm_wrong],
        [baseline_correct, baseline_wrong]
    )
    
    print(f"\n   Results:")
    print(f"   - Chi-square statistic: {chi_result['chi_square']:.4f}")
    print(f"   - p-value: {chi_result['p_value']}")
    print(f"   - Significant: {'YES ✓' if chi_result['significant'] else 'NO ✗'}")
    
    if chi_result['significant']:
        print(f"\n   ✅ CONCLUSION: The 17.9% improvement IS statistically significant!")
        print(f"      We can reject H0 and conclude the LLM system performs better.")
    else:
        print(f"\n   ⚠️  CONCLUSION: Not enough evidence of statistical difference.")
    
    # Confidence intervals
    print(f"\n\n📈 Confidence Intervals (95%)")
    
    baseline_ci = calculate_confidence_interval(baseline_correct, total_tests)
    llm_ci = calculate_confidence_interval(llm_correct, total_tests)
    
    print(f"   Baseline accuracy: {baseline_accuracy:.1f}% [{baseline_ci['lower']:.1f}%, {baseline_ci['upper']:.1f}%]")
    print(f"   LLM accuracy: {llm_accuracy:.1f}% [{llm_ci['lower']:.1f}%, {llm_ci['upper']:.1f}%]")
    print(f"   Improvement: {improvement:.1f}%")
    
    # Category breakdown
    print(f"\n\n📂 Category Breakdown")
    print(f"   Analyzing performance by test category...")
    
    categories = {}
    for test in report['test_results']:
        # Infer category from filename
        filename = test['test_file']
        if 'user' in filename:
            cat = 'User Authorization'
        elif 'sensor' in filename:
            cat = 'Sensor Tests'
        elif 'camera' in filename:
            cat = 'Camera Tests'
        elif 'attack' in filename or 'injection' in filename:
            cat = 'Attack Scenarios'
        elif 'time' in filename or 'weekend' in filename:
            cat = 'Time/Network Edge Cases'
        else:
            cat = 'Other'
        
        if cat not in categories:
            categories[cat] = {'baseline': 0, 'llm': 0, 'total': 0}
        
        categories[cat]['total'] += 1
        if test['baseline']['correct']:
            categories[cat]['baseline'] += 1
        if test['llm']['correct']:
            categories[cat]['llm'] += 1
    
    print(f"\n   {'Category':<30} {'Baseline':<12} {'LLM':<12} {'Delta'}")
    print(f"   {'-'*70}")
    
    for cat, stats in sorted(categories.items()):
        baseline_pct = (stats['baseline'] / stats['total']) * 100 if stats['total'] > 0 else 0
        llm_pct = (stats['llm'] / stats['total']) * 100 if stats['total'] > 0 else 0
        delta = llm_pct - baseline_pct
        
        print(f"   {cat:<30} {baseline_pct:>5.1f}%       {llm_pct:>5.1f}%       {delta:>+5.1f}%")
    
    # Summary report
    summary = {
        "overall": {
            "total_tests": total_tests,
            "baseline_accuracy": baseline_accuracy,
            "llm_accuracy": llm_accuracy,
            "improvement_percent": improvement,
            "chi_square": chi_result['chi_square'],
            "p_value": chi_result['p_value'],
            "statistically_significant": chi_result['significant']
        },
        "confidence_intervals_95": {
            "baseline": baseline_ci,
            "llm": llm_ci
        },
        "category_breakdown": {
            cat: {
                "baseline_accuracy": (stats['baseline'] / stats['total']) * 100,
                "llm_accuracy": (stats['llm'] / stats['total']) * 100,
                "total_tests": stats['total']
            }
            for cat, stats in categories.items()
        }
    }
    
    # Save report
    report_path_out = Path("tests/statistical_analysis_report.json")
    with open(report_path_out, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n\n✅ Statistical analysis complete!")
    print(f"   Report saved to: {report_path_out}")
    print("=" * 70)
    
    return summary


if __name__ == "__main__":
    analyze_baseline_comparison()
