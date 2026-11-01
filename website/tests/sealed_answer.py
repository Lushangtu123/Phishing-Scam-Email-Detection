"""A verified ARC answer for tests, in the form app._parse_raw_email passes to analyze_raw_email (arc_result) once
Google's seal verifies: Gmail seals the results it wrote as the message's topmost Authentication-Results header,
and signs each From, To, Cc, Subject and Reply-To the message has (once), as the view below records.
Only for Gmail-style headers; Outlook.com downloads have no seal that verifies."""
from email import message_from_bytes, policy

import email_structure as es


def sealed_answer(raw: bytes) -> es.SealedResults | None:
    """None for a message without a Gmail result to seal."""
    headers = message_from_bytes(raw, policy=policy.default).get_all('Authentication-Results')
    if not headers:
        return None
    data = raw if isinstance(raw, bytes) else raw.encode('utf-8', 'surrogateescape')
    view = es._seal_view(data, [b'from', b'to', b'cc', b'subject', b'reply-to'])
    return es.SealedResults('google.com', ' '.join(str(headers[0]).split()), view)


def arc_verified(app_module, raw: bytes | None):
    """Patch the web app's ARC check (app._parse_raw_email starts it for every upload) to answer as if Google's
    seal over this Gmail download verified, without any DNS lookup."""
    from concurrent.futures import Future
    from unittest.mock import patch

    def start(_raw, dnsfunc=None):
        future = Future()
        future.set_result(sealed_answer(raw) if raw is not None else None)
        return future
    return patch.object(app_module, 'start_arc_verification', start)
