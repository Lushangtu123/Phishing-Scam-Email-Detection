import asyncio
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


WEBSITE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEBSITE_DIR))

import app
from case_api import build_case_service
from sender_history import SenderHistoryResult, canonicalize_sender_address
from test_case_api import TOKEN, request

WORKSPACE = "production:cases:team-a"


class _FakeHistoryStore:
    def __init__(self, *, lookup_result=None, observe_result=None):
        self.lookup_result = lookup_result or SenderHistoryResult(status="not_seen")
        self.observe_result = observe_result or SenderHistoryResult(
            status="first_seen",
            first_seen_at="2026-09-20T00:00:00Z",
            last_seen_at="2026-09-20T00:00:00Z",
            seen_count=1,
        )
        self.lookup_calls = []
        self.observe_calls = []

    async def lookup(self, address, workspace):
        self.lookup_calls.append((address, workspace))
        return self.lookup_result

    async def observe(self, address, workspace):
        self.observe_calls.append((address, workspace))
        return self.observe_result


class SenderHistoryIntegrationTests(unittest.TestCase):
    def analyze_sender(self, address):
        return json.loads(asyncio.run(
            app.analyze_email(app.EmailRequest(email=address))
        ).body)

    def analyze_raw(self, raw_email):
        """Public, anonymous analysis."""
        return json.loads(asyncio.run(
            app.analyze_content_endpoint(app.ContentRequest(raw_email=raw_email))
        ).body)

    def analyze_in_workspace(self, raw_email, workspace=WORKSPACE):
        """Analysis for an authenticated case workspace."""
        return json.loads(asyncio.run(
            app._analyze_content(app.ContentRequest(raw_email=raw_email), history_workspace=workspace)
        ).body)

    def test_sender_only_analysis_does_not_expose_the_service_history_or_touch_storage(self):
        store = _FakeHistoryStore()
        baseline = app._analyze_sender_address("alice@gmail.com")

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_sender("alice@gmail.com")

        self.assertEqual(store.lookup_calls, [])
        self.assertEqual(store.observe_calls, [])
        self.assertEqual(result["risk_score"], baseline["risk_score"])
        self.assertEqual(
            result["account_observability"],
            "provider_account_unverifiable",
        )
        self.assertEqual(result["sender_history_status"], "workspace_required")
        self.assertEqual(result["sender_history_scope"], "this_service_history")
        self.assertNotIn("sender_first_seen_at", result)
        self.assertNotIn("sender_last_seen_at", result)
        self.assertNotIn("sender_seen_count", result)

    def test_sender_only_analysis_never_queries_history_for_normalized_variants(self):
        store = _FakeHistoryStore()

        with patch.object(app, "_sender_history_store", store):
            self.analyze_sender("user@éxample.com")
            self.analyze_sender("alice@gmail.com.")

        self.assertEqual(store.lookup_calls, [])

    def test_public_raw_email_neither_reads_nor_records_history(self):
        # Anyone can write any From: a shared record would let a forged message ask
        # whether an address was seen, and change what others are told.
        store = _FakeHistoryStore()
        raw_email = """From: Alice <alice@gmail.com>
To: user@example.com
Subject: Project update

Here is the requested update.
"""

        with patch.object(app, "_sender_history_store", store):
            first = self.analyze_raw(raw_email)
            second = self.analyze_raw(raw_email)

        self.assertEqual(store.observe_calls, [])
        self.assertEqual(store.lookup_calls, [])
        for result in (first, second):
            self.assertEqual(result["sender_analysis"]["sender_history_status"], "workspace_required")
            self.assertEqual(result["sender_analysis"]["sender_history_scope"], "this_service_history")

    def test_public_analysis_reports_a_disabled_store_as_disabled(self):
        with patch.object(app, "_sender_history_store", app.DisabledSenderHistoryStore()):
            result = self.analyze_raw("From: alice@gmail.com\nSubject: Hi\n\nHello.\n")

        self.assertEqual(result["sender_analysis"]["sender_history_status"], "disabled")

    def test_workspace_records_canonical_aliases_once(self):
        store = _FakeHistoryStore()
        raw_email = """From: Alice <a.lice+shopping@gmail.com>, Alice Alias <alice@gmail.com>
To: user@example.com
Subject: Project update

Here is the requested update.
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_in_workspace(raw_email)

        self.assertEqual(len(store.observe_calls), 1)
        self.assertEqual(store.observe_calls[0][1], WORKSPACE)
        self.assertEqual(
            canonicalize_sender_address(store.observe_calls[0][0]),
            "alice@gmail.com",
        )
        self.assertEqual(store.lookup_calls, [])
        self.assertEqual(result["sender_analysis"]["sender_history_status"], "first_seen")
        self.assertEqual(
            result["sender_analysis"]["sender_history_scope"],
            "this_service_history",
        )
        self.assertNotIn("sender_first_seen_at", result["sender_analysis"])
        self.assertNotIn("sender_last_seen_at", result["sender_analysis"])
        self.assertNotIn("sender_seen_count", result["sender_analysis"])
        self.assertEqual(result["total_score"], 0)

    def test_ambiguous_from_headers_observe_only_the_selected_riskiest_sender(self):
        store = _FakeHistoryStore()
        raw_email = """From: Alice <alice@example.com>
From: Security <notice@paypa1-verify.example>
To: user@example.com
Subject: Account update

Review the attached notice.
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_in_workspace(raw_email)

        self.assertEqual(store.observe_calls, [("notice@paypa1-verify.example", WORKSPACE)])
        self.assertEqual(
            result["sender_analysis"]["email"],
            "notice@paypa1-verify.example",
        )

    def test_nested_messages_do_not_amplify_sender_history_requests(self):
        store = _FakeHistoryStore()
        raw_email = """From: Outer Sender <outer@example.com>
To: user@example.com
Subject: Forwarded message
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer-boundary"

--outer-boundary
Content-Type: text/plain; charset=utf-8

See the attached message.
--outer-boundary
Content-Type: message/rfc822

From: Nested Sender <nested@paypa1-verify.example>
To: outer@example.com
Subject: Urgent verification

Verify your password now.
--outer-boundary--
"""

        with patch.object(app, "_sender_history_store", store):
            self.analyze_in_workspace(raw_email)

        self.assertEqual(store.observe_calls, [("outer@example.com", WORKSPACE)])
        self.assertEqual(store.lookup_calls, [])

    def test_missing_sender_does_not_create_history(self):
        store = _FakeHistoryStore()
        raw_email = """To: user@example.com
Subject: Project update

Here is the requested update.
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_in_workspace(raw_email)

        self.assertEqual(store.observe_calls, [])
        self.assertNotIn("sender_analysis", result)

    def test_previously_seen_history_never_suppresses_phishing_evidence(self):
        store = _FakeHistoryStore(observe_result=SenderHistoryResult(
            status="previously_seen",
            first_seen_at="2026-09-01T00:00:00Z",
            last_seen_at="2026-09-20T00:00:00Z",
            seen_count=50,
        ))
        raw_email = """From: Security <alice@outlook.com>
To: user@example.com
Subject: Urgent account verification

Your mailbox will be suspended. Confirm your password now at http://paypa1-secure.example/login
"""

        with patch.object(app, "_sender_history_store", store):
            result = self.analyze_in_workspace(raw_email)

        self.assertIn(result["risk_level"], {"high", "critical"})
        self.assertEqual(
            result["sender_analysis"]["sender_history_status"],
            "previously_seen",
        )
        self.assertNotIn("sender_seen_count", result["sender_analysis"])

    def test_authenticated_case_records_in_its_own_workspace_once(self):
        store = _FakeHistoryStore()
        raw_email = b"From: Alice <alice@example.com>\r\nTo: user@example.com\r\nSubject: Hi\r\n\r\nHello.\r\n"
        previous = getattr(app.app.state, "case_service", None)
        previous_error = getattr(app.app.state, "case_configuration_error", False)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.sqlite3"
            app.app.state.case_configuration_error = False
            app.app.state.case_service = build_case_service({
                "CASE_MANAGEMENT_ENABLED": "true", "CASE_DB_PATH": str(path),
                "CASE_ANALYST_TOKEN_HASHES": json.dumps({"alice": hashlib.sha256(TOKEN.encode()).hexdigest()}),
            })
            app._rate_limit_buckets.clear()
            key = "00000000-0000-4000-8000-0000000000aa"
            try:
                with patch.object(app, "_sender_history_store", store), patch.object(app, "_content_pipeline", None):
                    status, case, _ = asyncio.run(request("POST", "/api/cases/eml", raw=raw_email, key=key))
                    replay, _, _ = asyncio.run(request("POST", "/api/cases/eml", raw=raw_email, key=key))
                    denied, _, _ = asyncio.run(request("POST", "/api/cases/eml", raw=raw_email, token=None,
                                                       key="00000000-0000-4000-8000-0000000000ab"))
            finally:
                app.app.state.case_service = previous
                app.app.state.case_configuration_error = previous_error

        self.assertEqual((status, replay, denied), (201, 201, 401))
        # One observation, in this workspace only; a replayed request does not count twice.
        self.assertEqual(store.observe_calls, [("alice@example.com", f"local:cases-sqlite:{path}")])
        self.assertEqual(case["analysis"]["sender_analysis"]["sender_history_status"], "first_seen")

    def test_disposable_and_privacy_relay_categories_are_not_account_age_claims(self):
        store = _FakeHistoryStore()
        with patch.object(app, "_sender_history_store", store):
            disposable = self.analyze_sender("user@mailinator.com")
            relay = self.analyze_sender("user@simplelogin.com")

        self.assertEqual(disposable["account_observability"], "not_applicable")
        self.assertEqual(relay["account_observability"], "not_applicable")

    def test_public_capability_output_is_secret_free(self):
        health = json.loads(asyncio.run(app.health()).body)
        config = json.loads(asyncio.run(app.get_public_config()).body)

        for payload in (health, config):
            self.assertIn("sender_history_enabled", payload)
            self.assertIn("sender_history_available", payload)
            self.assertIn("sender_history_configured", payload)
            serialized = json.dumps(payload)
            self.assertNotIn("UPSTASH_REDIS_REST_TOKEN", serialized)
            self.assertNotIn("SENDER_HISTORY_HMAC_KEY", serialized)


if __name__ == "__main__":
    unittest.main()
