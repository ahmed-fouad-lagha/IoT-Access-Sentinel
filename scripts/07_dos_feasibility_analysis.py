#!/usr/bin/env python3
"""
DoS Feasibility Analysis for IoT-Access-Sentinel
=================================================
Simulates a denial-of-service attack where an adversary generates
syntactically valid requests that bypass Layer 0 and force LLM invocation
(Layer 1), exhausting the API budget and causing timeout-driven denials
for legitimate users.

Computes:
  - DoS amplification ratio (attacker requests needed per legitimate user blocked)
  - Timeout escalation curve at increasing attack request rates
  - Effectiveness of per-IP rate limiting as a defense

Usage:
    python3 scripts/07_dos_feasibility_analysis.py
"""

import json
import math
import random
import sys
import time
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))


class DoSSimulator:
    """Simulates DoS scenarios where attackers force LLM invocations."""
    
    def __init__(self):
        self.timeout_budget_ms = 150
        # Log-normal latency model (same as updated stress test)
        self.mu_ln = math.log(115.0)
        self.sigma_ln = 0.45
        
        # Rate limiter settings
        self.rate_limit_window_s = 60      # 1-minute window
        self.rate_limit_max_requests = 10  # max LLM invocations per IP per window
    
    def sample_latency(self):
        """Sample latency from log-normal distribution."""
        return max(1.0, random.lognormvariate(self.mu_ln, self.sigma_ln))
    
    def simulate_scenario(self, total_capacity, attacker_requests, legitimate_requests, use_rate_limiter=False):
        """
        Simulate a scenario with mixed attacker and legitimate traffic.
        
        Args:
            total_capacity: max concurrent LLM requests the API can handle
            attacker_requests: number of attacker requests that bypass Layer 0
            legitimate_requests: number of legitimate requests needing LLM
            use_rate_limiter: whether per-IP rate limiting is enabled
            
        Returns:
            dict with outcome metrics
        """
        # All requests enter the LLM path (they passed Layer 0)
        all_requests = []
        for i in range(attacker_requests):
            all_requests.append({"type": "attacker", "ip": f"10.0.{i % 256}.{i % 256}", "id": i})
        for i in range(legitimate_requests):
            all_requests.append({"type": "legitimate", "ip": f"192.168.1.{(i % 254) + 1}", "id": i})
        
        # Shuffle to simulate interleaved arrival
        random.shuffle(all_requests)
        
        # Track rate limiting
        ip_request_counts = defaultdict(int)
        
        results = {"attacker": {"total": 0, "timeout": 0, "rate_limited": 0, "served": 0},
                    "legitimate": {"total": 0, "timeout": 0, "rate_limited": 0, "served": 0}}
        
        active_slots = 0
        
        for req in all_requests:
            rtype = req["type"]
            results[rtype]["total"] += 1
            
            # Rate limiting check
            if use_rate_limiter:
                ip_request_counts[req["ip"]] += 1
                if ip_request_counts[req["ip"]] > self.rate_limit_max_requests:
                    results[rtype]["rate_limited"] += 1
                    continue  # Blocked by rate limiter, DENY without LLM
            
            # Simulate LLM invocation
            latency = self.sample_latency()
            if latency > self.timeout_budget_ms or active_slots >= total_capacity:
                results[rtype]["timeout"] += 1
            else:
                results[rtype]["served"] += 1
        
        # Compute metrics
        legit_total = results["legitimate"]["total"]
        legit_denied = results["legitimate"]["timeout"] + results["legitimate"]["rate_limited"]
        legit_served = results["legitimate"]["served"]
        
        attacker_total = results["attacker"]["total"]
        
        denial_rate = (legit_denied / legit_total * 100) if legit_total > 0 else 0.0
        amplification = (legit_denied / attacker_total) if attacker_total > 0 else 0.0
        
        return {
            "attacker_requests": attacker_total,
            "legitimate_requests": legit_total,
            "legitimate_served": legit_served,
            "legitimate_denied": legit_denied,
            "legitimate_denial_rate_percent": round(denial_rate, 2),
            "dos_amplification_ratio": round(amplification, 4),
            "results_breakdown": results,
            "rate_limiter_enabled": use_rate_limiter,
        }
    
    def run_escalation_analysis(self):
        """Run DoS at increasing attack intensities."""
        legitimate_requests = 50  # Fixed legitimate traffic
        total_capacity = 20       # Concurrent LLM capacity
        
        attack_levels = [0, 10, 25, 50, 100, 200, 500, 1000]
        
        results_no_rl = []
        results_with_rl = []
        
        for attack_count in attack_levels:
            # Without rate limiter
            outcome = self.simulate_scenario(
                total_capacity=total_capacity,
                attacker_requests=attack_count,
                legitimate_requests=legitimate_requests,
                use_rate_limiter=False
            )
            results_no_rl.append(outcome)
            
            # With rate limiter
            outcome_rl = self.simulate_scenario(
                total_capacity=total_capacity,
                attacker_requests=attack_count,
                legitimate_requests=legitimate_requests,
                use_rate_limiter=True
            )
            results_with_rl.append(outcome_rl)
        
        return {
            "parameters": {
                "legitimate_requests": legitimate_requests,
                "total_llm_capacity": total_capacity,
                "timeout_budget_ms": self.timeout_budget_ms,
                "rate_limit_window_s": self.rate_limit_window_s,
                "rate_limit_max_per_ip": self.rate_limit_max_requests,
                "latency_distribution": "lognormal",
                "latency_mu_ln": round(self.mu_ln, 4),
                "latency_sigma_ln": self.sigma_ln,
            },
            "without_rate_limiter": results_no_rl,
            "with_rate_limiter": results_with_rl,
        }


def main():
    print("=" * 60)
    print("IoT-Access-Sentinel DoS Feasibility Analysis")
    print("=" * 60)
    
    simulator = DoSSimulator()
    
    # Run escalation analysis
    print("\nRunning DoS escalation analysis...")
    analysis = simulator.run_escalation_analysis()
    
    # Print results
    print(f"\n{'Attack Reqs':>12} {'Legit Denial %':>16} {'Amplification':>14} | {'w/ Rate Limit':>14} {'RL Denial %':>12}")
    print("-" * 80)
    
    for no_rl, with_rl in zip(analysis["without_rate_limiter"], analysis["with_rate_limiter"]):
        print(f"{no_rl['attacker_requests']:>12} "
              f"{no_rl['legitimate_denial_rate_percent']:>15.1f}% "
              f"{no_rl['dos_amplification_ratio']:>14.4f} | "
              f"{'Yes':>14} "
              f"{with_rl['legitimate_denial_rate_percent']:>11.1f}%")
    
    # Summary
    baseline = analysis["without_rate_limiter"][0]  # 0 attacker requests
    worst_no_rl = analysis["without_rate_limiter"][-1]
    worst_with_rl = analysis["with_rate_limiter"][-1]
    
    print(f"\n--- Summary ---")
    print(f"Baseline legitimate denial rate (no attack): {baseline['legitimate_denial_rate_percent']:.1f}%")
    print(f"Worst-case denial rate (1000 attack reqs, no rate limit): {worst_no_rl['legitimate_denial_rate_percent']:.1f}%")
    print(f"Worst-case denial rate (1000 attack reqs, with rate limit): {worst_with_rl['legitimate_denial_rate_percent']:.1f}%")
    print(f"Rate limiter reduction: {worst_no_rl['legitimate_denial_rate_percent'] - worst_with_rl['legitimate_denial_rate_percent']:.1f} percentage points")
    
    # Save
    out_dir = Path("results")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "dos_feasibility_analysis.json"
    with open(out_file, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"\nResults saved to: {out_file}")


if __name__ == "__main__":
    main()
