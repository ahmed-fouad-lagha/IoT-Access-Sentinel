#!/usr/bin/env python3
"""
Baseline Comparison Test Runner
================================
Runs both the hybrid LLM system and static firewall baseline on the same
test scenarios to quantitatively compare performance.

Output: Comparison report with metrics and analysis
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import json
import asyncio
from typing import Dict, List, Tuple
from datetime import datetime

from observer.models import IoTAccessAlert
from decision_engine.baseline import get_static_firewall
from decision_engine.decision_pipeline import DecisionPipeline
from config.settings import Settings


from collections import defaultdict

class BaselineComparison:
    """Compares LLM system vs static firewall baseline"""
    
    def __init__(self):
        self.settings = Settings()
        self.static_firewall = get_static_firewall()
        self.llm_pipeline = DecisionPipeline(self.settings)
        
        self.results = {
            'hybrid': {'correct': 0, 'total': 0, 'decisions': []},
            'rbac': {'correct': 0, 'total': 0, 'decisions': []},
            'categories': defaultdict(lambda: {'rbac': 0, 'hybrid': 0, 'total': 0})
        }
    
    def load_test_scenario(self, test_path: Path) -> Tuple[IoTAccessAlert, str]:
        """Load test scenario and expected decision"""
        with open(test_path, 'r') as f:
            data = json.load(f)
        
        # Extract expected decision
        expected = data.get('expected_decision', data.get('expected_action', 'UNKNOWN'))
        
        # Remove test metadata
        alert_data = {k: v for k, v in data.items() 
                     if k not in ['expected_decision', 'expected_action', 'test_category', 'description']}
        
        alert = IoTAccessAlert(**alert_data)
        return alert, expected
    
    async def test_scenario(self, test_path: Path) -> Dict:
        """Test both systems on a single scenario"""
        print(f"\n{'='*60}")
        print(f"Testing: {test_path.name}")
        print(f"{'='*60}")
        
        alert, expected = self.load_test_scenario(test_path)
        
        # Test 1: Static Firewall
        baseline_decision = self.static_firewall.evaluate(alert)
        baseline_correct = (baseline_decision.action == expected)
        
        # Test 2: LLM System
        try:
            llm_decision = await self.llm_pipeline.make_decision(alert)
            llm_correct = (llm_decision.action == expected)
        except Exception as e:
            print(f"⚠️  LLM Error: {e}")
            llm_decision = None
            llm_correct = False
        
        # Record results
        result = {
            'test_file': test_path.name,
            'expected': expected,
            'baseline': {
                'action': baseline_decision.action,
                'correct': baseline_correct,
                'reason': baseline_decision.reason
            },
            'llm': {
                'action': llm_decision.action if llm_decision else 'ERROR',
                'correct': llm_correct,
                'reason': llm_decision.reason if llm_decision else 'LLM failed'
            }
        }
        
        # Print comparison
        print(f"Expected:  {expected}")
        print(f"Baseline:  {baseline_decision.action} {'✅' if baseline_correct else '❌'}")
        print(f"           {baseline_decision.reason[:80]}...")
        print(f"LLM:       {llm_decision.action if llm_decision else 'ERROR'} {'✅' if llm_correct else '❌'}")
        if llm_decision:
            print(f"           {llm_decision.reason[:80]}...")
        
        # Update stats
        self.results['rbac']['total'] += 1
        self.results['rbac']['correct'] += (1 if baseline_correct else 0)
        self.results['rbac']['decisions'].append({
            'expected': expected,
            'actual': baseline_decision.action,
            'correct': baseline_correct,
            'reason': baseline_decision.reason
        })
        
        self.results['hybrid']['total'] += 1
        self.results['hybrid']['correct'] += (1 if llm_correct else 0)
        self.results['hybrid']['decisions'].append({
            'expected': expected,
            'actual': llm_decision.action if llm_decision else 'ERROR',
            'correct': llm_correct,
            'reason': llm_decision.reason if llm_decision else 'LLM failed'
        })
        
        category = test_path.parent.name
        self.results['categories'][category]['total'] += 1
        self.results['categories'][category]['rbac'] += (1 if baseline_correct else 0)
        self.results['categories'][category]['hybrid'] += (1 if llm_correct else 0)
        
        return result
    
    async def run_comparison(self, test_dirs: List[str]) -> Dict:
        """Run comparison across all test scenarios"""
        all_results = []
        
        for test_dir in test_dirs:
            test_path = Path(test_dir)
            if not test_path.exists():
                print(f"⚠️  Directory not found: {test_dir}")
                continue
            
            print(f"\n{'#'*60}")
            print(f"# Testing: {test_path.name}")
            print(f"{'#'*60}")
            
            for test_file in sorted(test_path.glob('*.json')):
                result = await self.test_scenario(test_file)
                all_results.append(result)
        
        # Calculate metrics
        baseline_accuracy = (self.results['rbac']['correct'] / self.results['rbac']['total']) * 100
        llm_accuracy = (self.results['hybrid']['correct'] / self.results['hybrid']['total']) * 100
        improvement = llm_accuracy - baseline_accuracy
        
        return self.results
    
    def print_summary(self, report: Dict):
        """Print comparison summary"""
        baseline_accuracy = (report['rbac']['correct'] / report['rbac']['total']) * 100
        llm_accuracy = (report['hybrid']['correct'] / report['hybrid']['total']) * 100
        improvement = llm_accuracy - baseline_accuracy
        
        print(f"\n{'='*60}")
        print(f"COMPARISON SUMMARY")
        print(f"{'='*60}")
        print(f"Total Tests: {report['rbac']['total']}")
        print(f"\nStatic Firewall Baseline:")
        print(f"  Correct: {report['rbac']['correct']}/{report['rbac']['total']}")
        print(f"  Accuracy: {baseline_accuracy:.1f}%")
        print(f"\nHybrid LLM System:")
        print(f"  Correct: {report['hybrid']['correct']}/{report['hybrid']['total']}")
        print(f"  Accuracy: {llm_accuracy:.1f}%")
        print(f"\n{'IMPROVEMENT: ' if improvement > 0 else 'REGRESSION: '}{improvement:+.1f}%")
        print(f"{'='*60}")


async def main():
    """Run baseline comparison on all test scenarios"""
    comparison = BaselineComparison()
    
    # Test directories
    test_dirs = [
        'evaluation/user_auth',       # User authorization tests (6 tests)
        'evaluation/scenarios',       # Manual test scenarios (8 tests)
        'evaluation/red_team',        # Red team tests (7 tests)
        'evaluation/synthetic',       # Enhanced synthetic scenarios (85 tests)
    ]
    
    print("Starting Baseline Comparison Test Suite")
    print("Testing directories:")
    for d in test_dirs:
        print(f"  - {d}")
    
    # Run comparison
    report = await comparison.run_comparison(test_dirs)
    
    # Print summary
    comparison.print_summary(report)
    
    # Save report
    report_path = Path('results/results_comparison.json')
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\nDetailed report saved to: {report_path}")
    
    return report


if __name__ == "__main__":
    asyncio.run(main())
