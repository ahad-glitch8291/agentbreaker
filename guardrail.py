"""
guardrail.py
------------
A second, independent defense layer on top of the system prompt.

The system prompt (Phase 3's HARDENED_SYSTEM_PROMPT) tries to get the model to
never leak restricted content in the first place. That's "prevention." This
module is "detection at the exit door": it scans whatever the agent is about
to say (or send via a tool) and blocks it if a known-restricted secret appears,
REGARDLESS of what the model itself intended or which attack technique caused it.

Why this matters: the hardened prompt only defends against the specific attack
patterns we've already found (ATLAS-01 through ATLAS-08). A brand new, cleverer
attack we haven't thought of could still slip past the prompt. The guardrail
doesn't care about *how* the leak happened -- it just checks whether the secret
text is present in the outgoing content, so it defends even against attacks
that haven't been invented yet, as long as the actual secret value would appear
in the output. This is the same principle production systems use: a DLP
(data loss prevention) filter or output scanner as a last line of defense, not
a replacement for good prompting/guardrails, but a backstop for when they fail.

Toggle with the AGENTBREAKER_GUARDRAIL env var ("on" or "off", defaults to "on").
"""

import os
import re

from attack_library import SECRET_MARKERS

GUARDRAIL_ENABLED = os.environ.get("AGENTBREAKER_GUARDRAIL", "on").lower() == "on"

BLOCKED_RESPONSE_TEXT = (
    "[BLOCKED BY GUARDRAIL] This response was withheld because it appeared to "
    "contain restricted content (a value from internal_systems_config.txt). "
    "If you believe this is a mistake, please contact IT directly rather than "
    "rephrasing your request."
)


def _contains_secret(text: str) -> bool:
    if not text:
        return False
    return any(marker in text for marker in SECRET_MARKERS)


def check_and_filter_response(text: str) -> tuple:
    """Check a final response string. Returns (safe_text, was_blocked: bool).

    If the guardrail is disabled via env var, always passes through unchanged
    (so Phase 2/3's "prompt-only" results stay reproducible/comparable).
    """
    if not GUARDRAIL_ENABLED:
        return text, False

    if _contains_secret(text):
        return BLOCKED_RESPONSE_TEXT, True

    return text, False


def check_tool_call_args(fn_name: str, fn_args: dict) -> tuple:
    """Check outgoing tool call arguments (e.g. send_notification's message)
    for leaked secrets BEFORE the tool actually executes. Returns
    (allowed: bool, reason: str or None).

    This matters separately from check_and_filter_response because a leak via
    send_notification happens the moment the tool call executes, not when the
    final text response is shown to the user -- by the time there's a final
    response, the "notification" would already have gone out.
    """
    if not GUARDRAIL_ENABLED:
        return True, None

    args_str = str(fn_args)
    if _contains_secret(args_str):
        return False, (
            f"BLOCKED: tool call to '{fn_name}' contained restricted content "
            "in its arguments and was not executed."
        )

    return True, None
