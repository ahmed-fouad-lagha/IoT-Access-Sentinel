"""
Threshold Calibration Tool
Evaluates the impact of different confidence thresholds on False Permit Rate (FPR)
and Overall Accuracy to justify the 0.75 selection.
"""

import json
from pathlib import Path

def calibrate():
    # Load detailed results from the comparison script
    results_file = Path("results/results_comparison.json")
    if not results_file.exists():
        print("❌ results/results_comparison.json not found. Run tools/run_baseline_comparison.py first.")
        return

    with open(results_file, 'r') as f:
        data = json.load(f)

    hybrid_decisions = data['hybrid']['decisions']
    
    thresholds = [0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]
    metrics = []

    for t in thresholds:
        tp = 0 # True Positives (Denied correctly)
        fp = 0 # False Positives (Denied incorrectly - but in access control FP is False Deny)
        tn = 0 # True Negatives (Allowed correctly)
        fn = 0 # False Negatives (Allowed incorrectly - False Permit)
        
        # We define: 
        # Target = DENY (Security focus)
        # Prediction = ALLOW if model says ALLOW OR model says DENY with confidence < t
        
        for d in hybrid_decisions:
            expected = d['expected'] # ALLOW or DENY
            actual_action = d['actual']
            confidence = d.get('confidence', 0.5)
            
            # Application Logic:
            # If action is DENY and confidence >= t -> Decision is DENY
            # Else -> Decision is ALLOW (or retry, but here we assume thresholding for the DENY action)
            # Actually, our system defaults to DENY on low confidence? 
            # Let's check decision_pipeline.py
            
            # From decision_pipeline.py:
            # action=policy_decision["action"], confidence=policy_decision["confidence"]
            # The enforcement layer (Wazuh/Active Response) usually just takes the Action.
            # But the reviewer says: "decision thresholding (>=0.75 confidence for DENY)"
            
            effective_action = actual_action
            if actual_action == "DENY" and confidence < t:
                # If it was a DENY but low confidence, maybe we should have ALLOWED or it's a "Soft Deny"?
                # Usually thresholding means if confidence < t, we DON'T take the action.
                # If the action is DENY, and we don't take it, we ALLOW.
                effective_action = "ALLOW"

            if expected == "DENY":
                if effective_action == "DENY":
                    tp += 1
                else:
                    fn += 1 # False Permit (UNSAFE)
            else: # expected == "ALLOW"
                if effective_action == "ALLOW":
                    tn += 1
                else:
                    fp += 1 # False Deny (Unavailability)

        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        fpr = fn / (fn + tp) if (fn + tp) > 0 else 0 # False Permit Rate
        fdr = fp / (fp + tn) if (fp + tn) > 0 else 0 # False Deny Rate
        
        metrics.append({
            'threshold': t,
            'accuracy': accuracy,
            'fpr': fpr,
            'fdr': fdr
        })

    print(f"{'Threshold':<10} {'Accuracy':<10} {'FPR (Permit)':<12} {'FDR (Deny)':<12}")
    print("-" * 50)
    for m in metrics:
        print(f"{m['threshold']:<10.2f} {m['accuracy']:<10.2f} {m['fpr']:<12.2f} {m['fdr']:<12.2f}")

if __name__ == "__main__":
    calibrate()
