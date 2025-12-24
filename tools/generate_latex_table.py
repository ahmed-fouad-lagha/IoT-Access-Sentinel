"""
Generate LaTeX Table from Comparison Results
Reads results_comparison.json and generates a publication-ready LaTeX table
"""

import json
from pathlib import Path


def generate_latex_table(results_file="results_comparison.json"):
    """Generate LaTeX table from comparison results"""
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    rbac_acc = (results['rbac']['correct'] / results['rbac']['total']) * 100
    hybrid_acc = (results['hybrid']['correct'] / results['hybrid']['total']) * 100
    
    latex = r"""\begin{table}[t]
    \centering
    \caption{Comparison: Fair RBAC Baseline vs Hybrid LLM System}
    \label{tab:fair_comparison}
    \begin{tabular}{lcc}
        \toprule
        \textbf{Category} & \textbf{RBAC Baseline} & \textbf{Hybrid LLM} \\
        \midrule
"""
    
    # Add category rows
    for category, stats in sorted(results['categories'].items()):
        if stats['total'] > 0:
            rbac_cat = (stats['rbac'] / stats['total']) * 100
            hybrid_cat = (stats['hybrid'] / stats['total']) * 100
            
            category_name = category.replace('_', ' ').title()
            latex += f"        {category_name:<20} & {rbac_cat:>5.1f}\\% & {hybrid_cat:>5.1f}\\% \\\\\n"
    
    latex += r"""        \midrule
        \textbf{Overall} & \textbf{""" + f"{rbac_acc:.1f}\\%" + r"""} & \textbf{""" + f"{hybrid_acc:.1f}\\%" + r"""} \\
        \bottomrule
    \end{tabular}
\end{table}
"""
    
    print(latex)
    
    # Save to file
    with open("comparison_table.tex", 'w') as f:
        f.write(latex)
    
    print("\n✅ LaTeX table saved to: comparison_table.tex")
    print(f"\n📊 Summary:")
    print(f"   RBAC Baseline: {rbac_acc:.1f}%")
    print(f"   Hybrid LLM:    {hybrid_acc:.1f}%")
    print(f"   Improvement:   +{hybrid_acc - rbac_acc:.1f}%")


if __name__ == "__main__":
    if Path("results_comparison.json").exists():
        generate_latex_table()
    else:
        print("❌ Run tools/run_baseline_comparison.py first!")
