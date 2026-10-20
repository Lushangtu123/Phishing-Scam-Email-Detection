"""A message as a reader would paste it into the page: its subject and visible text, no headers.

docs/evaluation.md, "Pasted cohorts without truncation or ARC" (2026-10-20):

- The text is read with ARC verification off (arc_result=None). Extracting text needs no
  authentication, and verifying a seal would look up keys in DNS.
- Nothing is truncated. A subject or body longer than the page accepts, or a source file over the
  read limit, is excluded with a fixed reason, for the caller to count.
- Every field but the message content stays on the row, so a holdout marker (cohort_role)
  survives the conversion.
- A row read from an input file goes through from_input(), which drops internal fields first: a
  row cannot replace the file its eml_path names with bytes of its own.
- One size check covers every source: a file or bytes by their length, a string by its UTF-8
  encoding.
"""
from __future__ import annotations

from pathlib import Path

# A pasted message has no .eml limit of its own; its source is read up to the browser's 3 MiB
# request limit. The text limits are the page's (app.ContentRequest).
MAX_SOURCE_BYTES = 3 * 1024 * 1024
MAX_SUBJECT_CHARS = 500
MAX_BODY_CHARS = 50_000
EXCLUSION_REASONS = ('empty_source', 'source_too_large', 'subject_too_long', 'body_too_long', 'no_text')
_CONTENT_FIELDS = frozenset({'eml_path', '_eml_bytes', 'raw_email', 'subject', 'body'})


class PasteExcluded(ValueError):
    """A row that cannot be pasted whole; reason is one of EXCLUSION_REASONS."""

    def __init__(self, reason: str) -> None:
        if reason not in EXCLUSION_REASONS:
            raise ValueError('Unknown exclusion reason')
        super().__init__(reason)
        self.reason = reason


def checked_source(raw: str | bytes) -> str | bytes:
    """The source unchanged, if it holds text and is within the limit: bytes by their length, a
    string by its UTF-8 encoding."""
    size = len(raw) if isinstance(raw, (bytes, bytearray)) else len(raw.encode('utf-8', 'surrogatepass'))
    if not raw.strip():
        raise PasteExcluded('empty_source')
    if size > MAX_SOURCE_BYTES:
        raise PasteExcluded('source_too_large')
    return raw


def read_source(path: str | Path) -> bytes:
    """An original message's bytes, reading at most one byte past the limit."""
    with Path(path).open('rb') as source:
        return checked_source(source.read(MAX_SOURCE_BYTES + 1))


def pasted(row: dict) -> dict:
    """The row as pasted text, with every other field kept. Raises PasteExcluded instead of
    truncating."""
    import app

    if '_eml_bytes' in row or row.get('raw_email') or 'eml_path' in row:
        if '_eml_bytes' in row:
            raw = checked_source(row['_eml_bytes'])
        elif row.get('raw_email'):
            raw = checked_source(row['raw_email'])
        else:
            raw = read_source(row['eml_path'])
        # ARC off: the text is the same either way, and a seal check would look up keys in DNS.
        structure = app.analyze_raw_email(raw, trusted_authserv_ids=(), arc_result=None)
        parts = [app._visible_content_text(part['content']) if part['content_type'] == 'text/html'
                 else part['content'] for part in structure['content_parts']]
        subject, body = structure['subject'], '\n'.join(parts)
    else:
        subject, body = row.get('subject', ''), row.get('body', '')
    subject, body = subject.strip(), body.strip()
    if len(subject) > MAX_SUBJECT_CHARS:
        raise PasteExcluded('subject_too_long')
    if len(body) > MAX_BODY_CHARS:
        raise PasteExcluded('body_too_long')
    if not subject and not body:
        raise PasteExcluded('no_text')
    return {**{key: value for key, value in row.items() if key not in _CONTENT_FIELDS},
            'subject': subject, 'body': body}


def from_input(row: dict) -> dict:
    """pasted() for a row read from an input file. Internal fields (keys starting with "_") are set
    only by the evaluators, so they are dropped first."""
    return pasted({key: value for key, value in row.items() if not key.startswith('_')})
