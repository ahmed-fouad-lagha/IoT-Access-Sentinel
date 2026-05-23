"""
Calculate Safety Metrics (Precision, Recall, FP/FN Rates)
Critical for security systems: False permits are security breaches!

Metrics:
- Precision: Of all ALLOWs, how many were correct?
- Recall: Of all should-ALLOW, how many did we ALLOW?
- False Permit Rate: Incorrectly ALLOW when should DENY (CRITICAL!)
- False Deny Rate: Incorrectly DENY when should ALLOW (usability issue)
"""

import json
from pathlib import Path


def calculate_safety_metrics(results_file="results/results_comparison.json"):
    """Calculate safety metrics for both systems"""
    
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    systems = ['rbac', 'hybrid']
    all_metrics = {}
    
    for system in systems:
        decisions = data[system]['decisions']
        
        # Initialize counters
        tp = 0  # True Positive: Correctly ALLOW
        tn = 0  # True Negative: Correctly DENY
        fp = 0  # False Positive (False Permit): Incorrectly ALLOW
        fn = 0  # False Negative (False Deny): Incorrectly DENY
        
        for decision in decisions:
            expected = decision['expected']
            actual = decision['actual']
            
            if expected == 'ALLOW' and actual == 'ALLOW':
                tp += 1
            elif expected == 'DENY' and actual == 'DENY':
                tn += 1
            elif expected == 'DENY' and actual == 'ALLOW':
                fp += 1  # FALSE PERMIT - SECURITY BREACH!
            elif expected == 'ALLOW' and actual == 'DENY':
                fn += 1  # FALSE DENY - Usability issue
        
        total = tp + tn + fp + fn
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Safety-critical metrics
        false_permit_rate = fp / (tn + fp) if (tn + fp) > 0 else 0  # Of all should-DENY, how many we wrongly ALLOWed
        false_deny_rate = fn / (tp + fn) if (tp + fn) > 0 else 0    # Of all should-ALLOW, how many we wrongly DENYed
        
        accuracy = (tp + tn) / total if total > 0 else 0
        
        all_metrics[system] = {
            'tp': tp,
            'tn': tn,
            'fp': fp,
            'fn': fn,
            'total': total,
            'accuracy': accuracy * 100,
            'precision': precision * 100,
            'recall': recall * 100,
            'f1_score': f1 * 100,
            'false_permit_rate': false_permit_rate * 100,
            'false_deny_rate': false_deny_rate * 100
        }
    
    return all_metrics


def print_metrics_table(metrics):
    """Print formatted metrics table"""
    
    print("\n" + "="*80)
    print("SAFETY METRICS ANALYSIS")
    print("="*80 + "\n")
    
    print(f"{'Metric':<30} {'RBAC Baseline':<20} {'Hybrid LLM':<20}")
    print("-" * 70)
    
    rbac = metrics['rbac']
    hybrid = metrics['hybrid']
    
    # Confusion matrix
    print(f"\n{'CONFUSION MATRIX:':<30}")
    print(f"{'  True Positives (TP)':<30} {rbac['tp']:<20} {hybrid['tp']:<20}")
    print(f"{'  True Negatives (TN)':<30} {rbac['tn']:<20} {hybrid['tn']:<20}")
    print(f"{'  False Positives (FP)':<30} {rbac['fp']:<20} {hybrid['fp']:<20}")
    print(f"{'  False Negatives (FN)':<30} {rbac['fn']:<20} {hybrid['fn']:<20}")
    
    # Performance metrics
    print(f"\n{'PERFORMANCE METRICS:':<30}")
    print(f"{'  Accuracy':<30} {rbac['accuracy']:.1f}%{'':<15} {hybrid['accuracy']:.1f}%")
    print(f"{'  Precision':<30} {rbac['precision']:.1f}%{'':<15} {hybrid['precision']:.1f}%")
    print(f"{'  Recall':<30} {rbac['recall']:.1f}%{'':<15} {hybrid['recall']:.1f}%")
    print(f"{'  F1 Score':<30} {rbac['f1_score']:.1f}%{'':<15} {hybrid['f1_score']:.1f}%")
    
    # SAFETY-CRITICAL METRICS
    print(f"\n{'SAFETY METRICS (Critical!):':<30}")
    print(f"{'  False Permit Rate':<30} {rbac['false_permit_rate']:.1f}%{'':<15} {hybrid['false_permit_rate']:.1f}%")
    print(f"{'  False Deny Rate':<30} {rbac['false_deny_rate']:.1f}%{'':<15} {hybrid['false_deny_rate']:.1f}%")
    
    print("\n" + "="*80)
    
    # Key insights
    print("\n🔐 SECURITY ANALYSIS:\n")
    
    if hybrid['false_permit_rate'] < rbac['false_permit_rate']:
        print(f"✅ Hybrid has LOWER false permit rate ({hybrid['false_permit_rate']:.1f}% vs {rbac['false_permit_rate']:.1f}%)")
        print("   → More secure against unauthorized access")
    else:
        print(f"⚠️  Hybrid has HIGHER false permit rate ({hybrid['false_permit_rate']:.1f}% vs {rbac['false_permit_rate']:.1f}%)")
        print("   → Needs improvement in blocking unauthorized access")
    
    print()
    
    if hybrid['false_deny_rate'] < rbac['false_deny_rate']:
        print(f"✅ Hybrid has LOWER false deny rate ({hybrid['false_deny_rate']:.1f}% vs {rbac['false_deny_rate']:.1f}%)")
        print("   → Better usability (fewer legitimate users blocked)")
    else:
        print(f"⚠️  Hybrid has HIGHER false deny rate ({hybrid['false_deny_rate']:.1f}% vs {rbac['false_deny_rate']:.1f}%)")
        print("   → May frustrate legitimate users")


def generate_latex_table(metrics):
    """Generate LaTeX table for paper"""
    
    rbac = metrics['rbac']
    hybrid = metrics['hybrid']
    
    latex = r"""\begin{table}[h]
    \centering
    \caption{Safety Metrics: Precision, Recall, and Error Rates}
    \label{tab:safety_metrics}
    \begin{tabular}{lcc}
        \toprule
        \textbf{Metric} & \textbf{RBAC Baseline} & \textbf{Hybrid LLM} \\
        \midrule
        \multicolumn{3}{l}{\textit{Performance Metrics}} \\
        Accuracy        & """ + f"{rbac['accuracy']:.1f}\\%" + r""" & \textbf{""" + f"{hybrid['accuracy']:.1f}\\%" + r"""} \\
        Precision       & """ + f"{rbac['precision']:.1f}\\%" + r""" & \textbf{""" + f"{hybrid['precision']:.1f}\\%" + r"""} \\
        Recall          & """ + f"{rbac['recall']:.1f}\\%" + r""" & \textbf{""" + f"{hybrid['recall']:.1f}\\%" + r"""} \\
        F1 Score        & """ + f"{rbac['f1_score']:.1f}\\%" + r""" & \textbf{""" + f"{hybrid['f1_score']:.1f}\\%" + r"""} \\
        \midrule
        \multicolumn{3}{l}{\textit{Safety-Critical Metrics}} \\
        False Permit Rate (FP)  & """ + f"{rbac['false_permit_rate']:.1f}\\%" + r""" & """ + f"{hybrid['false_permit_rate']:.1f}\\%" + r""" \\
        False Deny Rate (FN)    & """ + f"{rbac['false_deny_rate']:.1f}\\%" + r""" & """ + f"{hybrid['false_deny_rate']:.1f}\\%" + r""" \\
        \bottomrule
    \end{tabular}
\end{table}

\textit{Note}: False Permit (FP) represents security breaches (incorrectly allowing unauthorized access). False Deny (FN) affects usability (incorrectly blocking legitimate users). Lower FP rate is critical for security.
"""
    
    results_dir = Path('results')
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / 'safety_metrics_table.tex'
    with open(out_path, 'w') as f:
        f.write(latex)
    
    print(f"\n✅ LaTeX table saved to: {out_path}\n")
    print("="*80)
    print("LaTeX Code Preview:")
    print("="*80)
    print(latex)


if __name__ == "__main__":
    if not Path("results/results_comparison.json").exists():
        print("❌ Error: results/results_comparison.json not found!")
        print("Run tools/run_baseline_comparison.py first")
        exit(1)
    
    metrics = calculate_safety_metrics()
    print_metrics_table(metrics)
    generate_latex_table(metrics)
    
    # Save metrics to JSON for later use
    with open(Path('results') / 'safety_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    
    print("\n💾 Metrics saved to: results/safety_metrics.json")
