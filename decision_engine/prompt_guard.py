"""
Prompt Guard - IoT-Access-Sentinel Decision Engine

Two-layer injection detection:
1. ML-based: meta-llama/llama-prompt-guard-2-86m detects classical prompt injection
   (e.g. "ignore previous instructions", "you are now admin", etc.)
2. Deterministic: regex patterns catch domain-specific metadata smuggling
   (e.g. "DECISION=ALLOW" injected into rule_description)

The guard runs BEFORE the LLM agents as a pre-filter in the decision pipeline.
"""

import re
import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Union
from openai import AsyncOpenAI

from common.logging_config import get_logger

logger = get_logger(__name__)

# Probability threshold above which text is classified as prompt injection
# Calibrated against llama-prompt-guard-2-86m on Groq:
#   - "Ignore previous instructions..." → 0.9996 (classic injection)
#   - "Disregard all previous rules..."  → 0.9993 (classic injection)
#   - "Standard security staff access"  → 0.44   (benign, high-security context)
INJECTION_THRESHOLD = 0.5

# Deterministic patterns for domain-specific metadata smuggling attacks.
# These are injections that are phrased naturally and evade the ML guard.
# Each entry: (compiled_regex, human-readable description)
_SMUGGLING_PATTERNS: List[tuple] = [
    (re.compile(r'DECISION\s*=\s*(ALLOW|DENY)', re.IGNORECASE),
     "Decision override directive (DECISION=ALLOW/DENY)"),

    (re.compile(r'\b(manually|explicitly|already)\s+(authorized|approved|granted|allowed)\b', re.IGNORECASE),
     "False authorization claim"),

    (re.compile(r'\b(admin|root|superuser|system)\s+(authorized|approved|granted|confirmed)\b', re.IGNORECASE),
     "Privileged authorization claim"),

    (re.compile(r'\b(bypass|skip|disable|ignore)\s+(security|policy|check|rule|auth|authentication)\b', re.IGNORECASE),
     "Security bypass directive"),

    (re.compile(r'\baccess\s+(granted|approved|allowed|permitted)\b', re.IGNORECASE),
     "Pre-emptive access grant claim"),
]

# Fields within the alert that contain user-supplied text and should be scanned
_FIELDS_FOR_ML_SCAN = ['rule_description', 'device_id', 'user_id', 'user_role']
_FIELDS_FOR_DETERMINISTIC_SCAN = ['rule_description']  # Most likely smuggling vector


@dataclass
class GuardViolation:
    field: str
    score: float          # 0.0 for deterministic violations, injection probability for ML
    description: str
    layer: str            # "ml" | "deterministic"


@dataclass
class GuardResult:
    is_injection: bool
    violations: List[GuardViolation] = field(default_factory=list)

    @property
    def reason(self) -> str:
        if not self.violations:
            return "No injection detected"
        parts = [f"[{v.layer.upper()}] {v.field}: {v.description}" for v in self.violations]
        return "; ".join(parts)


async def _ml_scan_field(
    client: AsyncOpenAI,
    text: str,
    field_name: str,
    threshold: float = INJECTION_THRESHOLD,
) -> Optional[GuardViolation]:
    """
    Call llama-prompt-guard-2-86m on a single text field.
    Returns a GuardViolation if injection detected, None otherwise.
    Fails open (returns None) on API errors to avoid blocking legitimate traffic.
    """
    if not text or not text.strip():
        return None

    try:
        resp = await client.chat.completions.create(
            model="meta-llama/llama-prompt-guard-2-86m",
            messages=[{"role": "user", "content": text}],
        )
        score = float(resp.choices[0].message.content)
        logger.debug("prompt_guard_ml_score", field=field_name, score=round(score, 4))

        if score > threshold:
            logger.warning(
                "prompt_injection_ml_detected",
                field=field_name,
                score=round(score, 4),
                threshold=threshold,
            )
            return GuardViolation(
                field=field_name,
                score=score,
                description=f"ML classifier score {score:.3f} > threshold {threshold}",
                layer="ml",
            )
        return None

    except Exception as e:
        logger.error("prompt_guard_ml_error", field=field_name, error=str(e))
        return None  # Fail open — guard errors must not block legitimate traffic


def _deterministic_scan_field(text: str, field_name: str) -> List[GuardViolation]:
    """
    Scan a single text field for domain-specific metadata smuggling patterns.
    Deterministic, zero latency — no LLM call required.
    """
    if not text or not text.strip():
        return []

    violations = []
    for pattern, description in _SMUGGLING_PATTERNS:
        if pattern.search(text):
            logger.warning(
                "prompt_injection_deterministic_detected",
                field=field_name,
                pattern=description,
            )
            violations.append(
                GuardViolation(
                    field=field_name,
                    score=1.0,
                    description=description,
                    layer="deterministic",
                )
            )
    return violations


async def scan_alert(
    client: AsyncOpenAI,
    alert_fields: dict,
    threshold: float = INJECTION_THRESHOLD,
) -> GuardResult:
    """
    Full two-layer prompt injection scan on an alert's user-supplied fields.

    Layer 1 — Deterministic (instant, zero-cost):
        Regex patterns for domain-specific metadata smuggling in rule_description.

    Layer 2 — ML-based (parallel async, ~100ms):
        llama-prompt-guard-2-86m scans all user-supplied text fields.

    Args:
        client: AsyncOpenAI client configured for Groq
        alert_fields: dict with keys: rule_description, device_id, user_id, user_role
        threshold: injection probability threshold for ML scanner (default 0.5)

    Returns:
        GuardResult with is_injection flag and list of violations found
    """
    all_violations: List[GuardViolation] = []

    # --- Layer 1: Deterministic scan (synchronous, instant) ---
    for field_name in _FIELDS_FOR_DETERMINISTIC_SCAN:
        text = alert_fields.get(field_name, "")
        violations = _deterministic_scan_field(str(text), field_name)
        all_violations.extend(violations)

    # --- Layer 2: ML scan (parallel async calls to guard model) ---
    ml_tasks = [
        _ml_scan_field(client, str(alert_fields.get(f, "")), f, threshold)
        for f in _FIELDS_FOR_ML_SCAN
        if alert_fields.get(f)
    ]
    ml_results = await asyncio.gather(*ml_tasks)
    for result in ml_results:
        if result is not None:
            all_violations.append(result)

    is_injection = len(all_violations) > 0

    if is_injection:
        logger.warning(
            "prompt_guard_blocked_alert",
            num_violations=len(all_violations),
            violations=[v.description for v in all_violations],
        )
    else:
        logger.debug("prompt_guard_cleared_alert")

    return GuardResult(is_injection=is_injection, violations=all_violations)
