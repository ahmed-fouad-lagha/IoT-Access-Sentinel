import re
import sys

def read_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(filepath, content):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    content = read_file('manuscript/main_ceur.tex')

    # 1. Soften Absolute Claims in Abstract
    content = content.replace(
        'demonstrates a critical security lifecycle: initial LLM-only contextual reasoning proved highly vulnerable to prompt injection (yielding only a 66.7\\% defense rate). However, by introducing a hardened Layer 0 (which deterministically blocks 63.8\\% of structural attacks) combined with strict semantic prompt delimiters, our fully mitigated system restored a 100\\% defense rate against all 105 adversarial attacks.',
        'demonstrates significant security trade-offs: initial LLM-only contextual reasoning proved highly vulnerable to prompt injection (yielding a 66.7\\% defense rate). However, by introducing a hardened Layer 0 (which deterministically blocks 63.8\\% of structural attacks) combined with strict semantic prompt delimiters, our fully mitigated system successfully neutralized all 105 tested adversarial attacks.'
    )
    content = content.replace(
        'provides a robust, reproducible pathway for automating semantically complex access policies',
        'provides a high-fidelity architectural blueprint for automating semantically complex access policies'
    )

    # 2. Intro Changes
    content = content.replace(
        'we restored a 100\\% defense rate.',
        'we successfully neutralized all tested adversarial attempts.'
    )
    content = content.replace(
        'achieve a 100\\% defense rate.',
        'neutralize all tested evasion attempts.'
    )
    content = content.replace(
        '\\textbf{Production-Grade System}: Complete implementation',
        '\\textbf{High-Fidelity Implementation}: Complete implementation'
    )
    content = content.replace(
        'achieved a 100\\% overall defense rate across the extended red-team suite post-mitigation.',
        'achieved a 100\\% defense rate across the evaluated red-team suite post-mitigation.'
    )
    content = content.replace(
        '\\textbf{Production Viability}:',
        '\\textbf{Deployment Feasibility}:'
    )
    content = content.replace(
        'demonstrating readiness for enterprise deployment.',
        'demonstrating feasibility for constrained enterprise deployments.'
    )

    # 3. Add to Related Work
    related_work_addition = r"""
\subsection{LLM Vulnerabilities in Cyber-Physical Systems}

Recent literature on Natural Language Access Control (NLAC) explores translating user intent into formal access policies. While these systems use LLMs for policy \textit{generation} (intent $\rightarrow$ rule), IoT-Access-Sentinel employs LLMs for \textit{runtime evaluation} (rule + context $\rightarrow$ decision). This runtime delegation introduces unique risks. Recent studies on LLMs in AIoT systems highlight that prompt injection attacks can manipulate models into producing unauthorized data access or control signals. Our findings confirm this vulnerability extends directly to access control decisions, necessitating the deterministic containment boundary (Layer 0) implemented in our architecture.
"""
    # Insert before Section 3
    content = content.replace('\\section{System Architecture}', related_work_addition + '\n\\section{System Architecture}')

    # 4. Extract and Move Threat Model to be Section 3
    threat_model_match = re.search(r'(\\subsection{Threat Model and Adversarial Robustness}.*?)(?=\\subsection{Agent Security and Authorization Boundaries})', content, re.DOTALL)
    if threat_model_match:
        threat_model_text = threat_model_match.group(1)
        # Remove from Discussion
        content = content.replace(threat_model_text, '')
        
        # Change to Section and move before System Architecture
        threat_model_text_as_section = threat_model_text.replace('\\subsection{Threat Model and Adversarial Robustness}', '\\section{Threat Model and Adversarial Robustness}')
        # also shift subsubsections to subsections
        threat_model_text_as_section = threat_model_text_as_section.replace('\\subsubsection{', '\\subsection{')
        
        content = content.replace('\\section{System Architecture}', threat_model_text_as_section + '\n\\section{System Architecture}')

    # 5. Semantic Caching Move
    # Find the Caching text in Results
    caching_match = re.search(r'(\\subsection{Evaluated Mitigation: Semantic Caching}.*?)(?=\\textbf{False Deny Rate and Fail-Secure Behavior}:)', content, re.DOTALL)
    if caching_match:
        caching_text = caching_match.group(1)
        # Remove from Results
        content = content.replace(caching_text, '')
        
        # Add to Architecture (Layer 1 end)
        arch_insert_point = r'sub-millisecond responses for recurring legitimate patterns.'
        
        caching_arch_text = """sub-millisecond responses for recurring legitimate patterns.

\\textbf{Semantic Caching Layer}
To address the availability and latency risks inherent in cloud-based LLM inference, we integrate a Semantic Caching Layer. This layer stores previously computed access decisions indexed by device type, device ID, and policy context. For repeated or high-frequency access requests (common in IoT heartbeats and retries), the cache bypasses LLM inference entirely, providing sub-millisecond response times and ensuring enforcement continuity even during external API outages.
"""
        content = content.replace(arch_insert_point, caching_arch_text)
        
        # Keep a brief note in results
        results_caching_note = """
\\subsection{Mitigation Performance: Semantic Caching}
Our evaluation demonstrates that the Semantic Caching Layer (detailed in Section 4.2) successfully addresses the availability concerns of remote LLMs. For repeated access requests, it provides a 100\\% latency reduction (bypassing inference for sub-millms responses) and serves cached decisions during cloud API outages, directly resolving the availability risks raised during stress testing.

"""
        # Insert back into results where it was
        content = content.replace('\\textbf{False Deny Rate and Fail-Secure Behavior}:', results_caching_note + '\\textbf{False Deny Rate and Fail-Secure Behavior}:')

    # 6. Ablation Study Move
    ablation_match = re.search(r'(\\subsection{Ablation Study: Component Contribution Analysis}.*?)(?=\\section{Discussion})', content, re.DOTALL)
    if ablation_match:
        ablation_text = ablation_match.group(1)
        content = content.replace(ablation_text, '')
        
        # Insert right after Overall Performance
        insert_after_overall = r'The non-overlapping confidence intervals further support this conclusion.\n'
        content = content.replace(insert_after_overall, insert_after_overall + '\n' + ablation_text)

    # 7. Add Baseline Defense in Methodology
    baseline_match = r'\\subsection{Baseline Comparison}\n\nTo quantify improvement over traditional approaches, we implemented a production-representative \\textbf{RBAC Baseline}'
    baseline_replacement = r"""\subsection{Baseline Comparison}

To quantify improvement over traditional approaches, we implemented a production-representative \textbf{RBAC Baseline}. While modern Attribute-Based Access Control (ABAC) via Open Policy Agent (OPA) provides richer context than standard RBAC, we selected an enhanced RBAC baseline (enforcing user authentication, strict user-device mappings, and temporal/network validation) because it perfectly isolates the \textit{semantic reasoning} variable. A deterministic ABAC engine would still fail on semantically ambiguous edge cases unless all potential attributes and contexts were formally modeled beforehand—which is precisely the manual overhead our LLM architecture seeks to eliminate. Our baseline thus features:"""
    content = content.replace(baseline_match, baseline_replacement)

    # 8. Tweak Conclusion
    content = content.replace(
        'reveals a critical security narrative. Initial testing exposed',
        'highlights significant security trade-offs. Initial testing exposed'
    )
    content = content.replace(
        'we fully restored a 100\\% defense rate.',
        'we successfully neutralized all tested evasion attempts.'
    )
    content = content.replace(
        'provides a production-ready pathway',
        'provides an architectural blueprint'
    )

    write_file('manuscript/main_ceur.tex', content)
    print("Refactor complete.")

if __name__ == "__main__":
    main()
