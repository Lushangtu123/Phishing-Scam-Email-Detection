# A language model as the teacher for a model of your own

The text model's weakness is its training data: public corpora whose genuine mail is mostly
from 2002–2008 ([evaluation log](evaluation.md)). The owner's own recent mail is the missing
ingredient, and labelling thousands of messages by hand is the obstacle. A local language
model can propose those labels (a teacher), a person checks the ones that matter, and the
small text model the page serves (the student) is retrained on the result. The teacher is
never served and never fine-tuned here; it only labels.

## Rules

1. **A person decides every phishing label.** The teacher's legitimate readings above a
   confidence floor are used as they are; every phishing reading, every reading below the
   floor, every unanswered message and every message the mail provider filed as spam goes
   to a review queue.
2. **The evaluation set is labelled by people, and the teacher never sees it.** Scoring a
   student on teacher labels would only measure agreement with the teacher.
3. **Private mail and any model trained on it stay out of Git.** The model artifact is in a
   public repository, and a TF-IDF vocabulary keeps words from its training mail (names,
   order numbers, addresses). `website/tests/test_artifact_provenance.py` fails if the
   committed artifact names a training source outside the public corpora.
4. **Replace the served model only on a clear, measured gain** on the independent holdout of
   the [rollout plan](llm-review-rollout.md#1-an-independent-holdout), with the release review.
5. **Check the model's licence** before using its output to train another model. `ollama show`
   gives Apache 2.0 for `qwen3.8:27b-mxfp8` and `qwen3.8:27b-mlx` (2026-10-06); the model's
   own page is authoritative.

## Steps

1. **Measure the teacher** on messages with human labels (`website/tools/evaluate_llm_labeler.py`,
   results below): how often each of its labels is right, and how many messages it can label
   without a person at each confidence floor.
2. **Export a consented mailbox**, for example Google Takeout's mbox, kept outside the
   repository.
3. **Label it** and check the queue:

   ```bash
   ollama serve
   .venv/bin/python website/tools/label_with_llm.py label /absolute/private/All-mail.mbox \
     --output-dir /absolute/private/teacher-labels --model qwen3.8:27b-mxfp8 \
     --floor 90 --since 2025-01-01 --exclude /absolute/private/evaluation-exclusions.jsonl
   # Fill human_label (phishing or legitimate) in teacher-labels/review.csv, then:
   .venv/bin/python website/tools/label_with_llm.py merge --output-dir /absolute/private/teacher-labels
   ```

   `labelled.csv` uses the column layout `content_model.py` reads for CEAS_08 and Nazario.
   The tool refuses an output directory inside the repository, and `--exclude` (JSONL with
   `message_id`) skips evaluation messages, so they never become training rows. A Takeout
   message labelled Spam goes to the queue whatever the teacher reads; for an export without
   Takeout's `X-Gmail-Labels` header, list such messages in a `--review` manifest. `merge`
   rebuilds `labelled.csv` each time, so it can run again as more rows are reviewed, and
   `label` refuses a directory whose `review.csv` already holds a person's labels.
4. **Train a candidate privately** with these rows added on the training side only (as the
   synthetic hard negatives are), and compare it with the served model on the holdout. The
   training pipeline does not read a private corpus yet; that switch is the next code change,
   once a reviewed mailbox exists.

## The owner's mailbox (2026-10-06)

The complete Gmail export of 2026-10-06 holds 87 messages, from 2026-05-11 to 2026-10-06, one
of them in Spam; none has a human label yet. 69 of them are already evaluation messages (52 of
the 92 genuine downloads, the 11 new brand emails and 6 rechecked messages), so 18 were
labelled: 11 marketing or service notices, 5 community digests and 2 learning reminders. The
teacher read all 18 as legitimate at 90 or more, including the community digest Gmail had
filed in Spam (95). That is why provider spam now goes to a person whatever the teacher
reads; this export has no `X-Gmail-Labels` header, so the message was listed with `--review`.
The owner labelled it legitimate, as the teacher had: all 18 are training rows, all legitimate.

That is far too few to move a model trained on about 30,000 messages; a useful pilot needs
thousands of recent messages, for example a mailbox with a longer history or the Outlook.com
account. At about 700 messages an hour, 10,000 messages take an overnight run.

## The teacher, measured

On 1,095 messages with human labels ([evaluation log](evaluation.md#a-local-language-model-as-a-labelling-teacher-2026-10-06)),
`qwen3.8:27b-mxfp8` with the local review's prompt:

- **read 10 of the owner's 92 genuine messages as phishing**, all at 90 or more. Phishing
  readings need a person, and about one genuine message in ten will be in the queue.
- **missed 9 of 890 phishing messages** with a legitimate reading at 90 or more (1.0%). In a
  mailbox where 2% of mail is phishing, that is about 1 phishing row in 4,000 accepted ones.
- **gave 97% of its readings at 90 or more**, wrong ones included, so the floor is no
  safeguard; the review queue and the spam rule are.
- **took 5.1 s a message** on average on an Apple M2 Max (about 700 an hour).
