# Design: offline ARC verification for evaluations

**Status: design and criteria only.** Drafted on 2026-10-20 at the owner's request, and revised the
same day after a technical review.

- Nothing is implemented. No private or holdout mail is read, and no measurement runs.
- Each of these is a separate later decision:
  - implementing it;
  - collecting a real key snapshot;
  - using snapshot mode in any evaluation.
- Live ARC verification in the served application does not change.

## Why

The evaluators no longer make RDAP, sender-history, Jev or local-review calls (2026-10-19,
`docs/evaluation.md`, "Evaluators without registry lookups"). ARC verification is the one
remaining path to the network.

- **When it runs.** For a raw message with no trusted Authentication-Results and no chosen mailbox,
  `analyze_raw_email` verifies an ARC chain sealed only by known sealers (`ARC_SEALERS`, today
  `google.com`).
- **What it asks.** The public key of each seal, by a DNS TXT lookup of
  `<selector>._domainkey.google.com`.
- **The scope of the zero-outbound result.** It covered only synthetic inputs without ARC seals.
  Sealed mail can still trigger these lookups, so the evaluators are not yet fully offline.
- **Two problems with live lookups:**
  - **privacy:** a lookup shows that a Google-sealed message is being evaluated, and when;
  - **reproducibility:** a key can be rotated or withdrawn, or DNS can fail, between two runs of
    the same message.

Turning ARC off in evaluations would change how Google-sealed downloads without a mailbox are
read. That would no longer measure the served behaviour. This design keeps the cryptography and
removes the network.

## Today (served behaviour, unchanged)

`email_structure.py`:

- **Which chains.** `start_arc_verification` looks up keys only when every seal and message
  signature names a known sealer.
- **Limits.** `_guarded_arc_dns` answers only `selector._domainkey.<known sealer>`, at most 10
  lookups within 4 seconds, each limited to 2 seconds.
- **Verification.** `dkim.arc_verify` (dkimpy) checks the chain with those keys. Trust follows
  only from a `pass` whose newest set was sealed and signed by the same known sealer, with that
  sealer's authserv-id.
- **Caching.** `_arc_dns_txt` caches keys in process for an hour, in `_ARC_KEY_CACHE`.

## Design

1. **A key snapshot.** A JSON file of public keys, versioned and hashed. For each key it records:
   - the sealer domain, the selector and the record name;
   - the TXT value exactly as returned;
   - when it was retrieved (UTC) and how (resolver);
   - its SHA-256.

   The file has a schema version and a SHA-256 of the whole.
   - **Outside the repository.** A real snapshot sits beside the evaluation data. The keys are
     public, but the list of selectors and when and why they were collected need not be.
   - **In the repository:** only the format definition and synthetic snapshots built from keys
     generated in tests.
2. **Collecting a real snapshot is its own step, approved each time:**
   - **Narrow lookups.** A separate tool looks up only the named records
     `<selector>._domainkey.<known sealer>`.
   - **Selectors.** They come from an explicit list the owner provides, or from a header source the
     owner names and authorizes (selectors and sealer domains only, counted, no message text). By
     default no private or holdout mail is read.
   - **When.** After implementation and synthetic validation, and before the 2026-10-13 plan is
     frozen. It is then fixed, and never replaced in view of scores.
   - **Versions.** Each new snapshot is a new version; earlier ones are kept.
3. **A snapshot mode for the evaluators only.**
   - **Selection.** Evaluator arguments name the snapshot path. The expected SHA-256 of the whole
     file comes from the external frozen configuration, not from the snapshot or the repository.
     No request, setting or environment variable of the served application selects this mode.
   - **Refusal.** The evaluator refuses to start if the file's hash differs.
   - **What the hash proves.** That the content is the one frozen. It does not prove that the keys
     came from the real sealer; the collection record in 2 is the only provenance.
   - **Lookups.** `dnsfunc` becomes a lookup in the snapshot, behind the same guard: known sealers
     only, the same lookup limits.
4. **Real verification, no fallback.**
   - **Same verifier.** Signatures are verified with `dkim.arc_verify`, as in serving.
   - **Missing key.** A key that is not in the snapshot returns nothing. It **never** falls back to
     live DNS, and the chain is not trusted.
   - **Withdrawn key.** An empty `p=` in the snapshot means the key was withdrawn, and the
     signature fails ([RFC 6376 §6.1.2](https://www.rfc-editor.org/rfc/rfc6376.html#section-6.1.2)).
   - **Failure.** A failed or partial verification never grants trust.
5. **No key crosses between sources.**
   - **Its own lookup table.** Snapshot mode reads keys only from the snapshot loaded for this run,
     never from `_ARC_KEY_CACHE`.
   - **No writes either.** It never writes to that cache, so a live lookup in the same process
     cannot see a snapshot key.
   - **Two snapshots in one process** (tests, or a bridging run) never share keys.
6. **Outcomes, kept apart** (counted in reports, never listed per message):
   - **verified:** a chain that passes;
   - **failed:** a signature or body mismatch, or a withdrawn key;
   - **unverified:** a key missing from the snapshot;
   - **not looked up:** a seal from a sealer that is not known;
   - **not applicable:** no seal, a chosen mailbox, or a trusted result already present.

   **Counting.** Each input included in the baseline counts exactly one primary ARC outcome.
   Counterfactual replays, the identity replay and the paired run without intent rules are counted
   in separate tables. They never add to the baseline counts.
7. **What reports record.**
   - **ARC mode:** `live`, `snapshot` or `off`, with the snapshot's version, whole-file SHA-256 and
     retrieval date.
   - **The outcome counts** above.
   - **External services.** In snapshot mode `external_services.arc_key_lookups` is empty. So
     `network_services_enabled` is false when every other service is off too.
8. **What a snapshot result means.**
   - **It reflects the key state of the named snapshot.** It does not show that a key is valid now,
     or was valid when the mail was received.
   - **It can say more than live DNS:** a key withdrawn after the snapshot still verifies in
     snapshot mode, while live DNS, now returning an empty `p=`, makes the same seal fail.
   - **It can say less:** a key added after the snapshot is missing from it, so a seal made with
     that key is `unverified`.
   - **The two modes may therefore differ.** A difference is reported, not resolved in either
     direction.
9. **Comparing with live verification and with baselines:**
   - **Different configurations.** A run in snapshot mode and a run in live mode are different
     configurations. `compare_evaluations.py` refuses to compare them, and that is intended.
   - **Bridging check.** It runs on synthetic or development inputs only. The same inputs run live,
     with a stub resolver in tests, and in snapshot mode. Results must be byte-identical **only
     where the stub and the snapshot give the same key responses**. Cases where they differ, such as
     a key withdrawn after the snapshot, are listed apart with each mode's outcome.
   - **The 2026-10-13 plan.** The proposed answer below is snapshot mode. Its frozen configuration
     would then record the mode, the snapshot version and the whole-file hash. The baseline and
     every candidate are scored with the same snapshot. A snapshot-mode result is labelled as such
     and is not presented as the served result.

## Security and privacy

- **No DNS during an evaluation in snapshot mode.** A network guard checks this, as for RDAP.
- **What a real snapshot holds.** Public keys, plus a selector list and a collection record that
  stay outside the repository.
- **Tampering** is caught by the whole-file hash before any message is read.
- **Untrusted input** keeps today's limits: message size, known sealers, the number of lookups and
  time.

## Criteria for the implementation (fixed now, before any implementation)

1. **Synthetic seals.** Messages are sealed with keys generated in the test, as in
   `test_arc_sealed_results.py`. Synthetic snapshots are built from those keys:

   | Case | Expected |
   |---|---|
   | Valid Google-style seal, key in snapshot | `verified`; ARC trust as in live mode |
   | Body or signed header changed | `failed`; no trust |
   | Key missing from the snapshot | `unverified`; no trust; **no DNS attempt** |
   | Withdrawn key (`p=` empty) in the snapshot | `failed`; no trust |
   | Key valid in the snapshot, withdrawn in the live stub (`p=` empty) | snapshot mode `verified`, live mode `failed`. The modes differ, the report says so, and the case is outside bridging equality |
   | Seal from an unknown sealer | `not looked up`; no trust |
   | Snapshot file with a wrong whole-file hash | the evaluator refuses to start |
   | Mailbox chosen, or a trusted result present | `not applicable`; unchanged from today |

2. **No key crosses between sources.**
   - **Between snapshots.** In one process, snapshot A is used, then snapshot B with a different key
     for the same selector. Each run verifies only with its own key.
   - **Between modes.** A live-mode lookup after a snapshot run does not see the snapshot's key,
     and a snapshot run does not see a cached live key.
3. **Zero outbound, now with sealed inputs.** Under the network guard of
   `website/tests/network_guard.py`, nothing may be recorded during:
   - each evaluator's baseline;
   - the identity replay and every counterfactual family;
   - attribution;
   - a command-line run of each evaluator.

   The inputs include ARC-sealed synthetic messages, in snapshot mode.
4. **Bridging.** Every synthetic sealed input whose key responses match gives a byte-identical
   result in snapshot mode and in live mode with the stub resolver. The inputs whose responses
   differ are listed apart.
5. **Counting.** Each baseline input contributes exactly one primary ARC outcome. A test with
   replays and intent-rule pairs shows the baseline counts unchanged and the other counts
   separate.
6. **Serving unchanged.**
   - No request, setting or environment variable of the served application selects snapshot mode.
   - With the evaluators in live mode, a golden replay of the unit suite's inputs is byte-identical
     to `main`.
7. **Recorded settings.** Reports state:
   - the ARC mode;
   - the snapshot version, whole-file hash and retrieval date;
   - the outcome counts.

   `network_services_enabled` is false only when every service, ARC included, is off.
8. **Planted defects.** Each must make a test fail:
   - a missing key falling back to live DNS (the guard records it);
   - a missing key counted as verified;
   - a snapshot whose hash is not checked;
   - a failed verification granting trust;
   - a snapshot key read from, or written to, the live cache;
   - a replay counted in the baseline's ARC outcomes.

## Proposed answers to the open questions

These come from the technical review the owner forwarded on 2026-10-20. They are proposals, not
decisions.

| Question | Proposed answer |
|---|---|
| Where a real snapshot lives | Outside the repository, beside the evaluation data. The repository holds only the format definition and synthetic test snapshots: the keys are public, but the selector list and collection record need not be |
| Where selectors come from | An explicit list from the owner, or a header source the owner names and authorizes. By default no private or holdout mail is read |
| When to collect | After implementation and synthetic validation, before the plan is frozen. Then fixed, and never replaced in view of scores |
| The mode for the frozen plan | Snapshot mode, only after the bridging and zero-outbound checks pass. The baseline and every candidate use the same snapshot. The plan is still not declared frozen until D12 and its other conditions are met |

Until this exists, any diagnostic run with ARC off is labelled separately and not taken as the
served result.
