#!/usr/bin/env python3
"""
Performance Benchmark Suite for IoT-Access-Sentinel
===================================================
Measures latency, throughput, and resource usage.

Metrics:
- End-to-end latency (alert → decision)
- Component breakdown (user auth, LLM calls, enforcement)
- Throughput (requests per second)
- Resource usage (memory, CPU)
"""

import sys
import time
import asyncio
import statistics
import json
import psutil
import random
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from observer.models import IoTAccessAlert
from decision_engine.decision_pipeline import DecisionPipeline
from config.settings import Settings


class PerformanceBenchmark:
    """Performance benchmarking for IoT-Access-Sentinel"""
    
    def __init__(self):
        self.settings = Settings()
        self.pipeline = DecisionPipeline(self.settings)
        self.results = {}
    
    async def measure_single_request_latency(self, alert: IoTAccessAlert, num_runs: int = 20) -> Dict:
        """
        Measure latency for a single scenario with multiple runs.
        
        Args:
            alert: Test alert
            num_runs: Number of times to run
        
        Returns:
            Latency statistics
        """
        latencies = []
        
        print(f"\n📊 Running {num_runs} iterations for latency measurement...")
        
        for i in range(num_runs):
            start = time.time()
            try:
                decision = await self.pipeline.make_decision(alert)
                end = time.time()
                latency_ms = (end - start) * 1000
                latencies.append(latency_ms)
                print(f"  Run {i+1}/{num_runs}: {latency_ms:.0f}ms", end='\r')
            except Exception as e:
                print(f"\n  ⚠️  Run {i+1} failed: {e}")
        
        print()  # New line after progress
        
        if not latencies:
            return {"error": "All runs failed"}
        
        latencies.sort()
        
        return {
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "avg_ms": statistics.mean(latencies),
            "median_ms": statistics.median(latencies),
            "p95_ms": latencies[int(len(latencies) * 0.95)] if len(latencies) > 1 else latencies[0],
            "p99_ms": latencies[int(len(latencies) * 0.99)] if len(latencies) > 1 else latencies[0],
            "std_dev_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "num_samples": len(latencies)
        }
    
    async def measure_component_breakdown(self, alert: IoTAccessAlert) -> Dict:
        """
        Measure time spent in each component.
        
        NOTE: This is an approximation since components run sequentially.
        """
        print("\n⚙️  Measuring component breakdown...")
        
        # Measure user auth (if applicable)
        start_auth = time.time()
        # User auth happens in pipeline, we'll estimate from total time
        
        # Make decision (includes all components)
        start_total = time.time()
        decision = await self.pipeline.make_decision(alert)
        end_total = time.time()
        
        total_ms = (end_total - start_total) * 1000
        
        # Rough estimates based on typical API latency
        estimated_llm_ms = 500  # Typical Groq API call
        estimated_auth_ms = 5    # Deterministic validation
        estimated_enforcement_ms = 10  # Dry-run enforcement
        
        return {
            "total_ms": total_ms,
            "estimated_user_auth_ms": estimated_auth_ms,
            "estimated_llm_calls_ms": estimated_llm_ms * 2,  # 2 LLM calls
            "estimated_enforcement_ms": estimated_enforcement_ms,
            "note": "Component breakdown is estimated; actual may vary"
        }
    
    async def measure_throughput(self, alert: IoTAccessAlert, concurrent: int = 10, duration_sec: int = 10) -> Dict:
        """
        Measure throughput under concurrent load.
        
        Args:
            alert: Test alert
            concurrent: Number of concurrent requests
            duration_sec: Test duration in seconds
        
        Returns:
            Throughput statistics
        """
        print(f"\n🚀 Measuring throughput ({concurrent} concurrent requests for {duration_sec}s)...")
        
        requests_completed = 0
        errors = 0
        start_time = time.time()
        
        async def make_request():
            nonlocal requests_completed, errors
            try:
                await self.pipeline.make_decision(alert)
                requests_completed += 1
            except Exception:
                errors += 1
        
        # Run concurrent requests for specified duration
        tasks = []
        while time.time() - start_time < duration_sec:
            # Launch batch of concurrent requests
            batch = [make_request() for _ in range(concurrent)]
            await asyncio.gather(*batch)
            
            # Brief sleep to prevent overwhelming
            await asyncio.sleep(0.1)
        
        elapsed = time.time() - start_time
        rps = requests_completed / elapsed
        
        print(f"  Completed {requests_completed} requests in {elapsed:.1f}s")
        print(f"  Throughput: {rps:.1f} RPS")
        
        return {
            "duration_sec": elapsed,
            "total_requests": requests_completed,
            "errors": errors,
       "success_rate_percent": (requests_completed / (requests_completed + errors) * 100) if (requests_completed + errors) > 0 else 0,
            "requests_per_second": rps,
            "concurrent_level": concurrent
        }
    
    def measure_resource_usage(self) -> Dict:
        """Measure current resource usage"""
        process = psutil.Process()
        
        return {
            "memory_mb": process.memory_info().rss / 1024 / 1024,
            "cpu_percent": process.cpu_percent(interval=1),
            "threads": process.num_threads()
        }
    
    async def run_full_benchmark(self) -> Dict:
        """Run complete benchmark suite"""
        print("=" * 70)
        print("IoT-Access-Sentinel Performance Benchmark Suite")
        print("=" * 70)
        
        # Create test scenarios
        test_scenarios = [
            {
                "name": "User Auth + LLM (Camera)",
                "alert": IoTAccessAlert(
                    id="bench-camera-001",
                    timestamp="2025-12-23T10:00:00Z",
                    rule={"level": 5, "description": "Camera access", "id": "100010"},
                    device_id="camera-office-01",
                    device_type="camera",
                    source_ip="192.168.1.100",
                    destination_ip="10.0.0.1",
                    destination_port=443,
                    protocol="HTTPS",
                    user_id="alice@company.com",
                    auth_token="valid-token-123",
                    user_role="security_admin"
                )
            },
            {
                "name": "Sensor (No User Auth)",
                "alert": IoTAccessAlert(
                    id="bench-sensor-001",
                    timestamp="2025-12-23T10:00:00Z",
                    rule={"level": 5, "description": "Sensor data", "id": "100020"},
                    device_id="sensor-temp-01",
                    device_type="sensor",
                    source_ip="192.168.2.50",
                    destination_ip="10.0.0.2",
                    destination_port=8883,
                    protocol="MQTTS"
                )
            }
        ]
        
        all_results = {}
        
        # Benchmark each scenario
        for scenario in test_scenarios:
            print(f"\n\n{'='*70}")
            print(f"Scenario: {scenario['name']}")
            print(f"{'='*70}")
            
            scenario_results = {}
            
            # 1. Latency measurement
            print("\n1️⃣  Latency Measurement")
            scenario_results['latency'] = await self.measure_single_request_latency(
                scenario['alert'],
                num_runs=10  # Reduced for speed
            )
            
            print(f"\n   Results:")
            print(f"   - Average: {scenario_results['latency'].get('avg_ms', 0):.1f}ms")
            print(f"   - P95: {scenario_results['latency'].get('p95_ms', 0):.1f}ms")
            print(f"   - P99: {scenario_results['latency'].get('p99_ms', 0):.1f}ms")
            
            # 2. Component breakdown
            print("\n2️⃣  Component Breakdown")
            scenario_results['components'] = await self.measure_component_breakdown(scenario['alert'])
            
            # 3. Throughput (only for first scenario to avoid API limits)
            if scenario == test_scenarios[0]:
                print("\n3️⃣  Throughput Test")
                scenario_results['throughput'] = await self.measure_throughput(
                    scenario['alert'],
                    concurrent=5,  # Conservative to avoid hitting limits
                    duration_sec=5
                )
            
            all_results[scenario['name']] = scenario_results
        
        # 4. Resource usage
        print(f"\n\n{'='*70}")
        print("Resource Usage")
        print(f"{'='*70}")
        all_results['resource_usage'] = self.measure_resource_usage()
        print(f"  Memory: {all_results['resource_usage']['memory_mb']:.1f} MB")
        print(f"  CPU: {all_results['resource_usage']['cpu_percent']:.1f}%")
        
        # Summary
        print(f"\n\n{'='*70}")
        print("📊 BENCHMARK SUMMARY")
        print(f"{'='*70}")
        
        avg_latencies = [r['latency']['avg_ms'] for r in all_results.values() if 'latency' in r]
        if avg_latencies:
            print(f"\nAverage Latency (across scenarios): {statistics.mean(avg_latencies):.1f}ms")
        
        if 'User Auth + LLM (Camera)' in all_results and 'throughput' in all_results['User Auth + LLM (Camera)']:
            tp = all_results['User Auth + LLM (Camera)']['throughput']
            print(f"Throughput: {tp['requests_per_second']:.1f} RPS")
            print(f"Success Rate: {tp['success_rate_percent']:.1f}%")
        
        print(f"\nResource Usage:")
        print(f"  Memory: {all_results['resource_usage']['memory_mb']:.1f} MB")
        print(f"  CPU: {all_results['resource_usage']['cpu_percent']:.1f}%")
        
        # Save results
        report = {
            "timestamp": datetime.now().isoformat(),
            "benchmark_results": all_results
        }
        
        report_path = Path("results/performance_report.json")
        report_path.parent.mkdir(exist_ok=True)
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✅ Benchmark complete! Report saved to: {report_path}")
        print(f"{'='*70}\n")
        
        return report


async def main():
    benchmark = PerformanceBenchmark()
    await benchmark.run_full_benchmark()


if __name__ == "__main__":
    asyncio.run(main())
