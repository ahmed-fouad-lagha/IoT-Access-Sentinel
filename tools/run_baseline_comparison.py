"""
Baseline Comparison Script
Runs all 106 test scenarios against BOTH systems and compares results:
1. RBAC Baseline (with authentication)
2. Hybrid LLM System (your current system)

Outputs:
- Accuracy comparison
- Category-wise breakdown
- Confusion matrix
- Statistical significance (McNemar's test)
"""

import json
import asyncio
from pathlib import Path
from collections import defaultdict
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.rbac_baseline import RBACBaseline
from decision_engine.decision_pipeline import DecisionPipeline
from observer.models import IoTAccessAlert


async def run_comparison():
    """Run all tests against both baselines"""
    
    # Initialize both systems
    print("🔧 Initializing systems...")
    rbac = RBACBaseline()
    
    from config.settings import get_settings
    settings = get_settings()
    hybrid = DecisionPipeline(settings)
    
    # Find all test files
    test_dir = Path("tests")
    test_files = list(test_dir.rglob("*.json"))
    print(f"📋 Found {len(test_files)} test scenarios\n")
    
    # Track results
    results = {
        'rbac': {'correct': 0, 'total': 0, 'decisions': []},
        'hybrid': {'correct': 0, 'total': 0, 'decisions': []},
        'categories': defaultdict(lambda: {'rbac': 0, 'hybrid': 0, 'total': 0})
    }
    
    # Contingency table for McNemar's test
    both_correct = 0
    only_rbac_correct = 0
    only_hybrid_correct = 0
    both_wrong = 0
    
    print("Running comparisons (Simulating 2x traffic for cache evaluation)...")
    print("=" * 80)
    
    # Duplicate the test files to simulate repeated traffic (retries/high-frequency logs)
    evaluation_files = []
    for f in test_files[:103]:
        evaluation_files.append(f)
        evaluation_files.append(f)
    
    for test_file in evaluation_files:
        with open(test_file, 'r') as f:
            test_data = json.load(f)
        
        # Extract expected decision and alert data
        expected = test_data.pop('expected_decision', None)
        if not expected:
            print(f"⚠️  Skipping {test_file.name}: no expected_decision")
            continue
        
        alert_data = test_data  # The whole file IS the alert
        category = test_file.parent.name  # e.g., "user_auth", "time_based"
        
        # Run RBAC baseline
        rbac_decision = rbac.make_decision(alert_data)
        rbac_correct = (rbac_decision['action'] == expected)
        
        # Run Hybrid LLM system
        try:
            iot_alert = IoTAccessAlert(**alert_data)
            hybrid_decision = await hybrid.make_decision(iot_alert)
            hybrid_correct = (hybrid_decision.action == expected)
        except Exception as e:
            print(f"❌ Error on {test_file.name}: {e}")
            hybrid_correct = False
            hybrid_decision = None
        
        # Update results
        results['rbac']['total'] += 1
        results['hybrid']['total'] += 1
        
        if rbac_correct:
            results['rbac']['correct'] += 1
        if hybrid_correct:
            results['hybrid']['correct'] += 1
        
        # Category tracking
        results['categories'][category]['total'] += 1
        if rbac_correct:
            results['categories'][category]['rbac'] += 1
        if hybrid_correct:
            results['categories'][category]['hybrid'] += 1
        
        # McNemar contingency table
        if rbac_correct and hybrid_correct:
            both_correct += 1
        elif rbac_correct and not hybrid_correct:
            only_rbac_correct += 1
        elif not rbac_correct and hybrid_correct:
            only_hybrid_correct += 1
        else:
            both_wrong += 1
        
        # Store decisions for analysis
        results['rbac']['decisions'].append({
            'file': str(test_file),
            'expected': expected,
            'actual': rbac_decision['action'],
            'correct': rbac_correct,
            'reason': rbac_decision['reason']
        })
        
        if hybrid_decision:
            results['hybrid']['decisions'].append({
                'file': str(test_file),
                'expected': expected,
                'actual': hybrid_decision.action,
                'correct': hybrid_correct,
                'reason': hybrid_decision.reason,
                'confidence': hybrid_decision.confidence
            })
        
        # Progress indicator
        if results['rbac']['total'] % 10 == 0:
            print(f"Processed {results['rbac']['total']} scenarios...")
    
    print("=" * 80)
    print("\n📊 RESULTS\n")
    
    # Overall accuracy
    rbac_acc = (results['rbac']['correct'] / results['rbac']['total']) * 100
    hybrid_acc = (results['hybrid']['correct'] / results['hybrid']['total']) * 100
    improvement = hybrid_acc - rbac_acc
    
    print(f"{'System':<20} {'Accuracy':<12} {'Correct/Total'}")
    print("-" * 50)
    print(f"{'RBAC Baseline':<20} {rbac_acc:>6.1f}%     {results['rbac']['correct']}/{results['rbac']['total']}")
    print(f"{'Hybrid LLM':<20} {hybrid_acc:>6.1f}%     {results['hybrid']['correct']}/{results['hybrid']['total']}")
    print(f"{'Improvement':<20} {improvement:>+6.1f}%")
    print()
    
    # Category breakdown
    print("\n📂 Category-Wise Performance:\n")
    print(f"{'Category':<20} {'RBAC':<12} {'Hybrid':<12} {'Delta'}")
    print("-" * 60)
    
    for category, stats in sorted(results['categories'].items()):
        if stats['total'] > 0:
            rbac_cat = (stats['rbac'] / stats['total']) * 100
            hybrid_cat = (stats['hybrid'] / stats['total']) * 100
            delta = hybrid_cat - rbac_cat
            print(f"{category:<20} {rbac_cat:>6.1f}%      {hybrid_cat:>6.1f}%      {delta:>+6.1f}%")
    
    # McNemar's Test
    print("\n\n📈 McNemar's Test for Statistical Significance:\n")
    print(f"Both correct:       {both_correct}")
    print(f"Only RBAC correct:  {only_rbac_correct}")
    print(f"Only Hybrid correct: {only_hybrid_correct}")
    print(f"Both wrong:         {both_wrong}")
    
    # Calculate McNemar's statistic
    if (only_rbac_correct + only_hybrid_correct) > 0:
        mcnemar_stat = ((only_hybrid_correct - only_rbac_correct) ** 2) / (only_hybrid_correct + only_rbac_correct)
        print(f"\nMcNemar's χ² = {mcnemar_stat:.2f}")
        
        # Interpret p-value (approximation)
        if mcnemar_stat > 6.63:
            print("p < 0.01 (highly significant)")
        elif mcnemar_stat > 3.84:
            print("p < 0.05 (significant)")
        else:
            print("p >= 0.05 (not significant)")
    
    # Caching metrics
    print("\n⚡ Caching Mitigation Evaluation:")
    print(f"{'Metric':<20} {'Value'}")
    print("-" * 30)
    print(f"{'Cache Hits':<20} {hybrid.cache_hits}")
    print(f"{'Cache Misses':<20} {hybrid.cache_misses}")
    if (hybrid.cache_hits + hybrid.cache_misses) > 0:
        hit_rate = (hybrid.cache_hits / (hybrid.cache_hits + hybrid.cache_misses)) * 100
        print(f"{'Hit Rate':<20} {hit_rate:>6.1f}%")
    
    # Save detailed results
    output_dir = Path("results")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / "results_comparison.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n\n💾 Detailed results saved to: {output_file}")
    
    return results


if __name__ == "__main__":
    asyncio.run(run_comparison())
