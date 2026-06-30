"""planner.py

Minimal rule-based tool selector for agent-prober.

The assignment (Section 6) leaves tool-selection strategy up to each team —
ReAct loop, LLM tool-calling, or plain rules. This is a transparent
keyword-rule selector: easy to demo, easy to explain in the 3-minute review,
and has no external API dependency. Swap in an LLM-based selector later if
you want — the API contract (prompt in -> response out) does not change.
"""

from __future__ import annotations

from tools import PROBER_ALLOWLIST

# keyword -> tool_key, checked in order against the lowercased prompt
_KEYWORD_RULES: list[tuple[str, str]] = [
    ("tls", "testssl_deep"),
    ("ssl", "testssl_deep"),
    ("cipher", "testssl_deep"),
    ("cors", "corsy"),
    ("wordpress", "wpscan_full"),
    ("wp-", "wpscan_full"),
    ("drupal", "droopescan"),
    ("fuzz", "ffuf"),
    ("directory", "ffuf"),
    ("brute", "wfuzz"),
    ("reflect", "kxss"),
    ("xss param", "kxss"),
    ("nikto", "nikto"),
    ("general", "nikto"),
    ("misconfig", "nuclei_active"),
    ("cve", "nuclei_active"),
    ("template", "nuclei_active"),
    ("exposed", "nuclei_active"),
]


def select_tools(prompt: str, context: dict | None = None) -> list[str]:
    """Return an ordered, de-duplicated list of allowlisted tool keys to run.

    Always includes httpx first (live-target confirmation), then nuclei_active
    as the general-purpose active-scan default, then any keyword matches.
    """
    prompt_lower = prompt.lower()
    selected: list[str] = ["httpx", "nuclei_active"]

    for keyword, tool_key in _KEYWORD_RULES:
        if keyword in prompt_lower and tool_key not in selected:
            selected.append(tool_key)

    # context from an upstream agent (e.g. Prober) may name injectable params,
    # which is a strong signal to fuzz/scan more aggressively
    if context and context.get("injectable_params_found"):
        if "ffuf" not in selected:
            selected.append("ffuf")

    return [t for t in selected if t in PROBER_ALLOWLIST]
