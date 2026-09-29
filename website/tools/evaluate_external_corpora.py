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
import codecs
import csv
import json
import mailbox
import re
import sys
from email.header import decode_header, make_header
from html import unescape
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


# ── Additional public sources (Nazario yearly mbox, Marketing-Emails, templates) ──
_TAGS = re.compile(r"<[^>]+>")
_SCRIPT_STYLE = re.compile(r"<(script|style)\b.*?</\1>", re.I | re.S)
_SPACE = re.compile(r"\s+")


def _codec(charset: str | None) -> str:
    """Declared charset if Python knows it; phishing mail often declares broken ones."""
    try:
        return codecs.lookup(charset).name if charset else "utf-8"
    except LookupError:
        return "utf-8"


def _message_text(message) -> str:
    """Subject, blank line, plain body; HTML-only bodies have tags stripped.

    Matches the whitespace-collapsed plain text of the training Nazario.csv.
    """
    plain, html = [], []
    for part in (message.walk() if message.is_multipart() else [message]):
        if part.get_content_maintype() != "text" or part.get_filename():
            continue
        payload = part.get_payload(decode=True) or b""
        text = payload.decode(_codec(part.get_content_charset()), errors="replace")
        (plain if part.get_content_subtype() == "plain" else html if part.get_content_subtype() == "html" else []).append(text)
    # Phishing often puts HTML in the text/plain part; strip tags everywhere, as Nazario.csv has none.
    raw = " ".join(plain) if plain else " ".join(html)
    body = unescape(_TAGS.sub(" ", _SCRIPT_STYLE.sub(" ", raw)))
    try:
        subject = str(make_header(decode_header(message.get("Subject", "") or "")))
    except (LookupError, UnicodeError, ValueError):  # malformed headers are common in phishing
        subject = str(message.get("Subject", "") or "")
    return (_SPACE.sub(" ", subject).strip() + "\n\n" + _SPACE.sub(" ", body).strip()).strip()


def load_nazario_years(directory: Path, years) -> list[str]:
    texts = []
    for year in years:
        path = directory / f"phishing-{year}.mbox"
        if path.exists():
            texts += [text for text in (_message_text(m) for m in mailbox.mbox(str(path))) if len(text) > 20]
    return texts


def load_marketing(path: Path) -> list[str]:
    """marketeam/Marketing-Emails rows are 'Subject: ...' then the body."""
    csv.field_size_limit(sys.maxsize)
    texts = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            raw = row[0] if row else ""
            if raw == "0" or not raw.strip():
                continue
            match = re.match(r"\s*Subject:\s*(.*?)\n(.*)", raw, re.S)
            texts.append(((match.group(1) + "\n\n" + match.group(2).strip()) if match else raw).strip())
    return texts


def load_uniquedata(path: Path) -> tuple[list[str], list[str]]:
    """UniqueData/email-spam-classification: (legitimate, spam) texts as 'title\n\ntext'."""
    legitimate, spam = [], []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            text = (_SPACE.sub(" ", row["title"]).strip() + "\n\n" + row["text"].strip()).strip()
            (spam if row["type"].strip() == "spam" else legitimate).append(text)
    return legitimate, spam


_PLACEHOLDER_VALUES = (("name", "Alex"), ("url", "https://app.example.com/account"), ("product", "Acme"),
                       ("company", "Acme Inc."), ("email", "alex@example.com"), ("date", "March 3"),
                       ("amount", "$29.00"), ("total", "$29.00"), ("code", "482913"), ("id", "1042"))


def fill_template(text: str) -> str:
    """Remove mustache sections and replace variables with neutral example values."""
    text = re.sub(r"\{\{\s*[#/^][^}]*\}\}", " ", text)

    def value(match):
        key = match.group(1).lower()
        return next((v for k, v in _PLACEHOLDER_VALUES if k in key), "details")
    return re.sub(r"\{\{\{?\s*([^}]+?)\s*\}?\}\}", value, text)


def load_templates(directory: Path) -> list[str]:
    """Distinct Postmark plain-text transactional templates, placeholders filled."""
    seen, texts = set(), []
    for path in sorted(directory.glob("postmark-templates/templates/*/*/content.txt")):
        if path.parent.name == "example":  # the library's demo template, not a transactional message
            continue
        text = (path.parent.name.replace("-", " ").capitalize() + "\n\n" + fill_template(path.read_text(encoding="utf-8"))).strip()
        key = _SPACE.sub(" ", text.lower())
        if key not in seen:
            seen.add(key); texts.append(text)
    return texts


def split_by_family(texts: list[str], test_fraction: float, seed: int) -> tuple[list[str], list[str]]:
    """Deterministic split that keeps each normalized family on one side."""
    import hashlib
    train, test = [], []
    for text in texts:
        digest = hashlib.sha256(f"{seed}:{content_model._normalized_text_family(text)}".encode()).digest()
        (test if digest[0] < 256 * test_fraction else train).append(text)
    return train, test


def extended_experiment(training: holdout.Sources, conditions: dict, recent_seeds, recent_variants,
                        test_sets: Sets, *, make_model: Callable = holdout.make_production_model, folds: int = 5,
                        seed: int = 42, thresholds=holdout.DEFAULT_THRESHOLDS,
                        progress: Callable[[str], None] = print) -> dict:
    """Score recent seeds (grouped folds when a condition trains on recent variants) and other test sets.

    conditions maps a name to (extra training Sets, include_recent_variants).
    """
    from sklearn.model_selection import StratifiedGroupKFold
    base_texts = [t for texts, _l, _g in training.values() for t in texts]
    base_labels = [y for _t, labels, _g in training.values() for y in labels]
    seed_texts, seed_labels, seed_ids = recent_seeds
    variant_texts, variant_labels, variant_ids = recent_variants
    labels = np.asarray(seed_labels)
    results = {}
    for name, (extra, with_variants) in conditions.items():
        texts = base_texts + [t for ts, _l in extra.values() for t in ts]
        ys = base_labels + [y for _t, ls in extra.values() for y in ls]
        full = make_model().fit(texts + (variant_texts if with_variants else []),
                                ys + (list(variant_labels) if with_variants else []))
        progress(f"{name}: full model fitted ({len(texts) + (len(variant_texts) if with_variants else 0)} rows)")
        if with_variants:
            seed_scores = np.full(labels.size, np.nan)
            splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
            for fold, (_train_idx, test_idx) in enumerate(splitter.split(seed_texts, labels, seed_ids), 1):
                held = {seed_ids[i] for i in test_idx}
                keep = [i for i, sid in enumerate(variant_ids) if sid not in held]
                model = make_model().fit(texts + [variant_texts[i] for i in keep], ys + [variant_labels[i] for i in keep])
                seed_scores[test_idx] = model.predict_proba([seed_texts[i] for i in test_idx])[:, 1]
                progress(f"{name}: fold {fold}/{folds}")
        else:
            seed_scores = full.predict_proba(seed_texts)[:, 1]
        results[name] = {"recent_seeds": holdout.score_metrics(labels, seed_scores, thresholds)}
        for set_name, (set_texts, set_labels) in test_sets.items():
            if set_texts:
                results[name][set_name] = holdout.score_metrics(set_labels, full.predict_proba(set_texts)[:, 1], thresholds)
    return results


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
    parser.add_argument("--nazario-dir", type=Path, help="yearly phishing-YYYY.mbox files from monkey.org/~jose/phishing")
    parser.add_argument("--marketing-csv", type=Path, help="marketeam/Marketing-Emails train.csv")
    parser.add_argument("--templates-dir", type=Path, help="directory containing postmark-templates/")
    parser.add_argument("--uniquedata-csv", type=Path,
                        help="optional UniqueData/email-spam-classification email_spam.csv (real legitimate mail, test only)")
    parser.add_argument("--extended-experiment", action="store_true",
                        help="C0-C3 training sets scored on recent seeds, Nazario 2023-2025, held-out marketing mail "
                             "and transactional templates")
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
    if args.extended_experiment:
        if not all((args.difraud_dir, args.phishfuzzer_dir, args.nazario_dir, args.marketing_csv, args.templates_dir)):
            parser.error("--extended-experiment needs all five source options")
        seeds, variants = load_recent_families(args.phishfuzzer_dir)
        marketing_train, marketing_test = split_by_family(load_marketing(args.marketing_csv), 0.2, args.seed)
        extra_sets = {"nazario_2015_2022": (lambda ts: (ts, [1] * len(ts)))(load_nazario_years(args.nazario_dir, range(2015, 2023))),
                      "marketing_train": (marketing_train, [0] * len(marketing_train))}
        extra_sets, extra_overlap = remove_training_overlap(extra_sets, families)
        seen = families | {content_model._normalized_text_family(t) for ts, _l in extra_sets.values() for t in ts}
        nazario_test = load_nazario_years(args.nazario_dir, range(2023, 2026))
        templates = load_templates(args.templates_dir)
        test_sets, test_overlap = remove_training_overlap(
            {"nazario_2023_2025": (nazario_test, [1] * len(nazario_test)),
             "marketing_held_out": (marketing_test, [0] * len(marketing_test)),
             "transactional_templates": (templates, [0] * len(templates)),
             **({"uniquedata_legitimate": (lambda ts: (ts, [0] * len(ts)))(load_uniquedata(args.uniquedata_csv)[0])}
                if args.uniquedata_csv else {})}, seen)
        base_extra = {"difraud": external["difraud"],
                      "phishfuzzer_llm_from_legacy_seed": external["phishfuzzer_llm_from_legacy_seed"]}
        conditions = {"C0_training_corpora": ({}, False),
                      "C1_plus_difraud_and_legacy_llm": (base_extra, False),
                      "C2_plus_recent_llm_variants": (base_extra, True),
                      "C3_plus_marketing_and_nazario_2015_2022": ({**base_extra, **extra_sets}, True)}
        print("extended extras:", {k: len(v[0]) for k, v in extra_sets.items()},
              "tests:", {k: len(v[0]) for k, v in test_sets.items()})
        report["extended_experiment"] = {"overlap": {**extra_overlap, **test_overlap},
                                         "results": extended_experiment(training, conditions, seeds, variants,
                                                                        test_sets, seed=args.seed)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("\n" + markdown_table(report) + f"\n\nReport written to {args.output}")
    key = f"{holdout.DEPLOYED_THRESHOLD:g}"
    for condition, sets in report.get("extended_experiment", {}).get("results", {}).items():
        print(condition)
        for set_name, metrics in sets.items():
            at = metrics["at_threshold"][key]
            print(f"  {set_name:26s} PR AUC {metrics['pr_auc']}  recall {holdout._fmt(at['phishing_recall'])}  "
                  f"FPR {holdout._fmt(at['false_positive_rate'])}")
    for name, metrics in report.get("augmentation_experiment", {}).items():
        at = metrics["at_threshold"][f"{holdout.DEPLOYED_THRESHOLD:g}"]
        print(f"{name}: PR AUC {metrics['pr_auc']}, recall {holdout._fmt(at['phishing_recall'])}, "
              f"FPR {holdout._fmt(at['false_positive_rate'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
