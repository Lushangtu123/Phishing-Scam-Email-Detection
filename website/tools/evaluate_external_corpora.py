"""Score the content-model recipe on public corpora it has never been trained on.

Trains the deployed configuration once on every local training corpus (the same
set as evaluate_source_holdout.py) and scores external test sets:

- DiFraud phishing subset (redasers/difraud, MIT): legitimate mail is mostly
  2014-2016 organisational mail (DNC, Sony, Hacking Team) plus some Enron.
- PhishFuzzer (DataPhish/PhishFuzzer): seeds marked Source "Manual" are recent
  private emails; entity-rephrased rows are LLM variants, split by whether their
  seed was Manual or from older public corpora. Spam is scored separately: it is
  neither phishing nor legitimate here.

External messages whose normalized family already occurs in training are removed
and counted, so the scores measure unseen mail. Evaluation only; the served
artifact is never touched. Reports hold aggregate counts and rates.

    .venv/bin/python website/tools/evaluate_external_corpora.py \
        --difraud-dir .evaluation-data/external/difraud \
        --phishfuzzer-dir .evaluation-data/external/phishfuzzer \
        --output .evaluation-data/external/report.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable

import numpy as np

WEBSITE_DIR = Path(__file__).resolve().parents[1]
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

import content_model  # noqa: E402
from tools import evaluate_source_holdout as holdout  # noqa: E402

Sets = dict[str, tuple[list[str], list[int]]]
PHISHFUZZER_SEEDS = "PhishFuzzer_emails_original_seed_v1.json"
PHISHFUZZER_REPHRASED = "PhishFuzzer_emails_entity_rephrased_v1.json"
_LABELS = {"phishing": 1, "valid": 0}


def load_difraud(directory: Path) -> Sets:
    texts, labels = [], []
    for split in ("train", "validation", "test"):
        path = directory / f"{split}.jsonl"
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                texts.append(str(row["text"])); labels.append(int(row["label"]))
    return {"difraud": (texts, labels)} if texts else {}


def _email_text(row: dict) -> str:
    # Same "subject, blank line, body" shape the training loaders build.
    return (str(row.get("Subject") or "") + "\n\n" + str(row.get("Body") or "")).strip()


def load_phishfuzzer(directory: Path) -> tuple[Sets, Sets]:
    """Return (phishing/legitimate sets, spam-only sets), split by seed provenance."""
    seeds_path, rephrased_path = directory / PHISHFUZZER_SEEDS, directory / PHISHFUZZER_REPHRASED
    if not seeds_path.exists():
        return {}, {}
    seeds = json.loads(seeds_path.read_text(encoding="utf-8"))
    manual = {str(seed["No."]) for seed in seeds if seed.get("Source") == "Manual"}
    groups: dict[str, list[dict]] = {"phishfuzzer_recent_seed": [s for s in seeds if str(s["No."]) in manual]}
    if rephrased_path.exists():
        rephrased = json.loads(rephrased_path.read_text(encoding="utf-8"))
        groups["phishfuzzer_llm_from_recent_seed"] = [r for r in rephrased if str(r["Original_ID"]) in manual]
        groups["phishfuzzer_llm_from_legacy_seed"] = [r for r in rephrased if str(r["Original_ID"]) not in manual]
    labelled: Sets = {}
    spam: Sets = {}
    for name, rows in groups.items():
        kept = [(_email_text(r), _LABELS[str(r["Type"]).lower()]) for r in rows if str(r["Type"]).lower() in _LABELS]
        labelled[name] = ([t for t, _ in kept], [y for _, y in kept])
        spam_texts = [_email_text(r) for r in rows if str(r["Type"]).lower() == "spam"]
        spam[f"{name}_spam"] = (spam_texts, [1] * len(spam_texts))  # "flagged" rate only
    return labelled, spam


def load_recent_families(directory: Path) -> tuple[tuple[list, list, list], tuple[list, list, list]]:
    """Recent (Manual) seeds and their LLM variants as (texts, labels, seed ids), phishing/valid only."""
    seeds = json.loads((directory / PHISHFUZZER_SEEDS).read_text(encoding="utf-8"))
    rephrased = json.loads((directory / PHISHFUZZER_REPHRASED).read_text(encoding="utf-8"))
    manual = {str(s["No."]) for s in seeds if s.get("Source") == "Manual"}

    def pick(rows, id_key):
        rows = [r for r in rows if str(r[id_key]) in manual and str(r["Type"]).lower() in _LABELS]
        return ([_email_text(r) for r in rows], [_LABELS[str(r["Type"]).lower()] for r in rows],
                [str(r[id_key]) for r in rows])
    return pick(seeds, "No."), pick(rephrased, "Original_ID")


def augmentation_experiment(training: holdout.Sources, extra_training: Sets, recent_seeds, recent_variants, *,
                            make_model: Callable = holdout.make_production_model, folds: int = 5, seed: int = 42,
                            thresholds=holdout.DEFAULT_THRESHOLDS, progress: Callable[[str], None] = print) -> dict:
    """Score recent real seeds under three training sets, never training on a tested seed's family.

    C0: training corpora. C1: + extra_training (no recent-seed information).
    C2: C1 + LLM variants of the recent seeds in the other folds (grouped by seed id).
    """
    from sklearn.model_selection import StratifiedGroupKFold
    base_texts = [t for texts, _l, _g in training.values() for t in texts]
    base_labels = [y for _t, labels, _g in training.values() for y in labels]
    extra_texts = [t for texts, _l in extra_training.values() for t in texts]
    extra_labels = [y for _t, labels in extra_training.values() for y in labels]
    seed_texts, seed_labels, seed_ids = recent_seeds
    variant_texts, variant_labels, variant_ids = recent_variants
    labels = np.asarray(seed_labels)
    scores = {}
    for name, texts, ys in (("C0_training_corpora", base_texts, base_labels),
                            ("C1_plus_difraud_and_legacy_llm", base_texts + extra_texts, base_labels + extra_labels)):
        model = make_model().fit(texts, ys)
        scores[name] = model.predict_proba(seed_texts)[:, 1]
        progress(f"{name} fitted")
    c2 = np.full(labels.size, np.nan)
    splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
    for fold, (train_idx, test_idx) in enumerate(splitter.split(seed_texts, labels, seed_ids), 1):
        held_ids = {seed_ids[i] for i in test_idx}
        keep = [i for i, sid in enumerate(variant_ids) if sid not in held_ids]
        model = make_model().fit(base_texts + extra_texts + [variant_texts[i] for i in keep],
                                 base_labels + extra_labels + [variant_labels[i] for i in keep])
        c2[test_idx] = model.predict_proba([seed_texts[i] for i in test_idx])[:, 1]
        progress(f"C2 fold {fold}/{folds} fitted ({len(keep)} recent-seed variants, {len(held_ids)} held-out seeds)")
    scores["C2_plus_recent_llm_variants_grouped"] = c2
    return {name: holdout.score_metrics(labels, values, thresholds) for name, values in scores.items()}


def remove_training_overlap(external: Sets, training_families: set[str]) -> tuple[Sets, dict]:
    kept: Sets = {}
    removed: dict = {}
    for name, (texts, labels) in external.items():
        pairs = [(t, y) for t, y in zip(texts, labels)
                 if content_model._normalized_text_family(t) not in training_families]
        kept[name] = ([t for t, _ in pairs], [y for _, y in pairs])
        removed[name] = {"input": len(texts), "overlap_removed": len(texts) - len(pairs)}
    return kept, removed


def evaluate(training: holdout.Sources, external: Sets, *, make_model: Callable = holdout.make_production_model,
             thresholds=holdout.DEFAULT_THRESHOLDS) -> dict:
    texts = [t for texts, _labels, _groups in training.values() for t in texts]
    labels = [y for _texts, labels, _groups in training.values() for y in labels]
    model = make_model().fit(texts, labels)
    results = {}
    for name, (set_texts, set_labels) in external.items():
        if not set_texts:
            results[name] = None
            continue
        scores = model.predict_proba(set_texts)[:, 1]
        results[name] = holdout.score_metrics(set_labels, scores, thresholds)
    return results


def markdown_table(report: dict, threshold: float = holdout.DEPLOYED_THRESHOLD) -> str:
    key = f"{threshold:g}"
    rows = [f"| External set | Rows (phish/legit) | Overlap removed | PR AUC | Recall @{key} | FPR @{key} |",
            "|---|---|---|---|---|---|"]
    for name, metrics in report["results"].items():
        overlap = report["overlap"].get(name, {})
        if metrics is None:
            rows.append(f"| {name} | 0 | {overlap.get('overlap_removed', '—')} | — | — | — |")
            continue
        at = metrics["at_threshold"][key]
        spam_only = name.endswith("_spam")
        recall = holdout._fmt(at["phishing_recall"])
        rows.append(f"| {name} | {metrics['rows']} ({metrics['phishing']}/{metrics['legitimate']}) "
                    f"| {overlap.get('overlap_removed', '—')}/{overlap.get('input', '—')} "
                    f"| {metrics['pr_auc'] if metrics['pr_auc'] is not None else '—'} "
                    f"| {('flagged ' + recall) if spam_only else recall} "
                    f"| {holdout._fmt(at['false_positive_rate'])} |")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-dir", type=Path, default=content_model._DEFAULT_DATA_DIR,
                        help="training corpora (same as evaluate_source_holdout.py)")
    parser.add_argument("--difraud-dir", type=Path)
    parser.add_argument("--phishfuzzer-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--augmentation-experiment", action="store_true",
                        help="also score recent PhishFuzzer seeds with DiFraud and LLM variants added to training")
    args = parser.parse_args(argv)

    training, dedup = holdout.deduplicate_across_sources(holdout.load_sources(args.data_dir, seed=args.seed))
    families = {content_model._normalized_text_family(t) for texts, _l, _g in training.values() for t in texts}
    external: Sets = {}
    spam: Sets = {}
    if args.difraud_dir:
        external.update(load_difraud(args.difraud_dir))
    if args.phishfuzzer_dir:
        labelled, spam = load_phishfuzzer(args.phishfuzzer_dir)
        external.update(labelled)
    external.update(spam)
    external, overlap = remove_training_overlap(external, families)
    print("training:", ", ".join(f"{n}={len(s[0])}" for n, s in training.items()))
    print("external:", ", ".join(f"{n}={len(s[0])}" for n, s in external.items()))
    report = {"results": evaluate(training, external), "overlap": overlap,
              "settings": {"training_deduplication": dedup, "seed": args.seed,
                           "thresholds": list(holdout.DEFAULT_THRESHOLDS)}}
    if args.augmentation_experiment:
        if not (args.difraud_dir and args.phishfuzzer_dir):
            parser.error("--augmentation-experiment needs --difraud-dir and --phishfuzzer-dir")
        extra = {"difraud": external["difraud"],
                 "phishfuzzer_llm_from_legacy_seed": external["phishfuzzer_llm_from_legacy_seed"]}
        seeds, variants = load_recent_families(args.phishfuzzer_dir)
        report["augmentation_experiment"] = augmentation_experiment(training, extra, seeds, variants, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("\n" + markdown_table(report) + f"\n\nReport written to {args.output}")
    for name, metrics in report.get("augmentation_experiment", {}).items():
        at = metrics["at_threshold"][f"{holdout.DEPLOYED_THRESHOLD:g}"]
        print(f"{name}: PR AUC {metrics['pr_auc']}, recall {holdout._fmt(at['phishing_recall'])}, "
              f"FPR {holdout._fmt(at['false_positive_rate'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
