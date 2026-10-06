"""Findings in what a message shows, and findings only text it may hide makes.

Since 2026-10-05 the request and lure rules that set a floor also read text that styles
may hide (app.analyze_email_content). A finding only that reading makes keeps its code,
carries the prefix.hidden_text prefix and sets a Medium floor. Tests of how the CSS reader
judges visibility compare the shown codes; tests of that rule compare the hidden ones.
"""

HIDDEN_PREFIX = 'prefix.hidden_text'


def _hidden(item):
    return any(prefix.get('code') == HIDDEN_PREFIX for prefix in item.get('prefixes', ()))


def shown_codes(result):
    """Codes of the findings made in what the message shows."""
    return {item.get('code') for item in result['extra_indicators'] if not _hidden(item)}


def hidden_codes(result):
    """Codes of the findings made only in text the message may hide."""
    return {item.get('code') for item in result['extra_indicators'] if _hidden(item)}
