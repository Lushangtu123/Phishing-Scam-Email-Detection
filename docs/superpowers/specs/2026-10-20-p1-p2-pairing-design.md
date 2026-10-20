# Design: pairing P1 and P2 in memory

**Status: design and acceptance criteria only, not approved.** Drafted on 2026-10-20 at the owner's
request. Revised the same day twice after technical reviews: first for the blockers found, then to
settle how unhashed members and the conservation denominator are stated.

- Nothing is implemented.
- No mail is read, extracted, downloaded or measured.
- Implementing it is a separate decision.

## Why

Step 1 of the false-alert diagnosis
([criteria](2026-10-20-false-alert-diagnosis-criteria.md)) compares two ways of reading the owner's
92 downloads:

- **P1:** each original `.eml`, with its mailbox recorded;
- **P2:** the same originals as pasted text.

The comparison may use only the messages both modes actually analyse, paired by source message.
Since #81, reports hold reason counts only. No report, log, error or archive may say which message
was excluded or paired. So the pairing has to happen in memory, inside one run, and only aggregates
may leave it.

## Shape

A new thin tool, `website/tools/evaluate_paired_modes.py`, that reuses the existing evaluation
logic:

- `evaluate_records`;
- `pasted_cohort`;
- the counterfactual and attribution sidecars.

The existing evaluators keep their behaviour.

## Design

1. **Clean the input first, then take one trusted snapshot.**
   - **Reading.** Each row is read from the input file and validated once. A holdout row is refused
     before any source is read. Internal fields (keys starting with `_`) are dropped first, as
     `pasted_cohort.from_input()` does.
   - **The snapshot.** The tool then reads each original **once** into a trusted in-memory
     snapshot, up to the paste source limit of 3 MiB.
   - **Everything comes from it:** the source digest, the P1 view and the P2 view. Nothing reads the
     file again.
   - **Too large or empty.** A file over 3 MiB gets no snapshot and **no digest**; a prefix is
     never hashed as if it were the whole original. Such a source, or an empty one, is in
     "neither", with its reason.
2. **Two views of each snapshot.**
   - **The P1 view.** The snapshot as the `.eml` the serving evaluator reads. It exists only if the
     snapshot is within 60,000 bytes; otherwise the reason is `eml_too_large`.
   - **The P2 view.** `pasted_cohort.pasted()` on the cleaned row with the trusted snapshot
     supplied in process. It is never taken from a field a JSONL row could carry. It has the fixed
     exclusion reasons and ARC off.
   - **Analysing the P1 view.** `evaluate_records` re-reads `eml_path` for an `.eml` row, and must
     not here. It gains an in-process-only way to take rows already prepared from the snapshot: a
     separate argument, never a row field. The pasted view needs no bytes.
   - **That entry changes nothing else.** Through it, holdout refusal, the conflicting-metadata
     check and the size limits still apply. A JSONL row cannot turn it on, and the existing entry
     behaves as before (criterion 10).
3. **Duplicates by a stable rule, not by input order.** `evaluate_records` keeps the first exact
   duplicate it meets, so input order could change which source is paired.
   - **The tool decides duplicates itself,** per mode and before any evaluation, by that mode's
     content digest. It passes only representatives on.
   - **Within each group of equal content,** the representative is the source with the **smallest
     source digest**.
   - **Byte-identical originals** share a source digest. They are one source: the copies are
     "neither", with reason `duplicate_source`.
   - **Conflicts.** Equal content with conflicting labels or group metadata is rejected, as today.
4. **Sets, by source.**
   - **Pairs:** sources that represent their content in both modes.
   - **P1 only:** a P1 view and no P2 view. Examples: visible text over 50,000 characters in an
     `.eml` under 60,000 bytes, or text that duplicates another source in P2 only.
   - **P2 only:** a P2 view and no P1 view, for example an `.eml` over 60,000 bytes whose text fits.
   - **Neither:** no view in either mode: excluded, too large, empty or a duplicate source. Counted
     by reason.

   Membership is never written. A set's **set digest** is the SHA-256 of the sorted source digests
   of its members, under a fixed domain-separation prefix. The P1 and P2 reports of the pair set
   carry the same set digest. That shows they cover the same sources without listing them.

   - **Members without a digest.** A source over 3 MiB has no digest, and it can only be in
     "neither". If "neither" holds any such member, its set digest is `null`, and its number of
     unhashed members is reported beside it. Pairs, P1 only and P2 only always have digests for
     every member.
   - **What a set digest does not show.** It identifies the bytes the run read. That these are the
     right originals still rests on the separately pinned input version (step 1 criteria).
5. **Evaluation.**
   - **Each non-empty set and mode** is evaluated with the unchanged analyzer and sidecars: the pairs
     in P1, the pairs in P2, P2 only, and P1 only. Each gets an aggregate report, a counterfactual
     sidecar and an attribution sidecar.
   - **An empty set** is not evaluated: `evaluate_records` refuses an empty cohort. It is reported
     as a zero count, with no report or sidecar.
   - **Failures.** An analysis failure aborts the run with no partial report. A failed
     counterfactual replay is counted as `analysis_failed` (step 1 criteria).
6. **Errors carry no position.** `evaluate_records` names the input line in its errors
   (`Row {index}: …`). The tool catches every error inside the run and reports it without a row
   number, identifier, path or text. A test checks the standard error and the exception messages of
   failing runs. The existing evaluators' messages are left as they are; changing them would be a
   separate decision.
7. **Paired comparison, in the private report only.**
   - **The table.** For the pairs, a 3 × 3 table of decisions (alerted, not alerted, undetermined)
     in P1 against P2, by label. Its cells sum to the number of pairs.
   - **Private only.** It stays in the private report beside the data.
   - **No shareable version yet.** Masking single cells as "< 5" can be undone from the totals and
     the other cells. A shareable version needs its own disclosure rule, approved separately, with
     an inference check: suppressing complementary cells, or sharing only coarser counts.
8. **What leaves the process.**
   - **Kept out:** identifiers, line numbers, paths, subjects, text, per-message results and
     positions in error messages.
   - **Integrity counts.** Each report's input integrity carries:
     - the count of each set;
     - exclusions and duplicates by mode and reason;
     - the set digests.
   - **Conservation.** Pairs + P1 only + P2 only + neither = the number of input records that pass
     the initial validation, **duplicate copies included**. It is not the number of unique sources:
     every duplicate copy is counted, in "neither".
9. **Network.** The run starts under `website/tests/network_guard.py`, and any recorded attempt
   voids it. P1 reads with the mailbox recorded, so ARC does not run. P2 reads with ARC off.

## Acceptance criteria (fixed now, before any implementation)

All on synthetic inputs.

1. **Sets.** One synthetic source per case falls in the expected set:

   | Source | Expected set |
   |---|---|
   | An ordinary message | pairs |
   | An `.eml` over 60,000 bytes whose visible text fits | P2 only |
   | An `.eml` under 60,000 bytes whose visible text is over 50,000 characters | P1 only |
   | Two different originals with the same visible text | the one with the smaller source digest is a pair; the other is P1 only |
   | Two byte-identical originals | one source in its set; the copy is "neither", `duplicate_source` |
   | An empty source; a source over 3 MiB | "neither", by reason, with no digest for the large one: the "neither" set digest is `null` and its unhashed count is 1 |
   | A holdout row | refused before any source is read |

2. **Order does not matter.** Reversing and shuffling the input rows leaves:
   - every set's count;
   - every set digest;
   - every report, byte for byte.

   This includes the two duplicate cases.
3. **Read once.** Each original file is opened exactly once in a run, as counted in a test. A file
   changed after its snapshot does not change the run's result.
4. **Conservation.** The four sets sum to the input records that pass the initial validation,
   duplicate copies included. Each evaluated set's count matches its
   report's evaluated rows. The decision table sums to the pairs.
5. **Same sources.** The P1 and P2 pair reports carry the same set digest. Changing one original's
   bytes changes it.
6. **Unchanged analysis, compared within its boundary.** For each evaluated set and mode, the
   report's existing part is byte-identical to the existing evaluator run on the same rows in that
   mode, at the same pinned full commit SHA as criterion 10: the existing evaluator with `--mailbox-setting recorded` for P1, and `--paste` for P2. The
   new pairing fields are verified separately, by criteria 1–5.
7. **Empty sets.** A run whose P1-only and P2-only sets are empty succeeds. It reports zero counts
   for them and calls no evaluator for them.
8. **No membership leaves the process.**
   - **Successful runs.** Standard output, standard error, the reports and the sidecars hold no
     input identifier, path, line number, subject or text. A scan for the synthetic markers checks
     this.
   - **Failing runs.** The same holds for standard error and exception messages, with a malformed
     row, an unreadable file and a failing analysis.
   - **The decision table** appears only in the private report.
9. **Zero outbound.** A run with an ARC-sealed synthetic source records no attempt under the guard,
   in process and from the command line.
10. **Prepared rows.**
    - **Outside callers cannot use them.** No JSONL field and no command-line option turns the
      in-process entry for prepared rows on. A test supplies every plausible field and option and
      sees the file read as usual.
    - **The rules still apply.** Through that entry, a holdout row is refused, conflicting metadata
      is rejected and an over-limit `.eml` is refused.
    - **The existing entry is unchanged.** On the unit suite's inputs, `evaluate_records` without
      prepared rows gives reports byte-identical to those of a **pinned full commit SHA**: the `main`
      commit the implementation branches from, recorded before the first test run. Never a moving
      `main`.
11. **Planted defects.** Each must make a test fail:
    - representatives chosen by input order;
    - a second read of an original;
    - a prefix hashed for a source over 3 MiB;
    - a P2-only source counted as a pair;
    - an identifier written to a report;
    - a row number in an error message;
    - default ARC verification in the P2 view;
    - an empty set passed to the evaluator;
    - a "neither" set digest computed although it holds an unhashed member, where it should be `null`;
    - the conservation denominator counting unique sources instead of records;
    - the prepared-rows entry reachable from a JSONL field.

## Positions taken (following the review of 2026-10-20)

| Question | Position |
|---|---|
| Shape | A new thin tool reusing the existing logic |
| The 3 × 3 table | In the private report only; a shareable version waits for an approved disclosure rule with an inference check |
| P1 only | Reported on its own, never folded into "neither" |
| Status of the step 1 criteria | Merging that document is not approval. Its status changes only when the owner records an explicit approval, with its date and scope |
