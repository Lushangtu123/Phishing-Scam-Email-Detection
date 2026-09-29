"""Leave-one-source-out evaluation of the content model configuration.

For each corpus, train the deployed model configuration (same TF-IDF features and
Logistic Regression settings) on every *other* corpus and score the held-out one.
Compare it with an in-distribution baseline: grouped K-fold over all corpora
pooled, which is how the README's mixed-corpus figures were produced. A large gap
for a corpus means the model relies on features that identify where a message
came from rather than whether it is phishing.

This evaluates a training recipe, not the committed artifact. It never replaces
the served model. Reports contain aggregate counts and rates only.

    .venv/bin/python website/tools/evaluate_source_holdout.py \
        --output .evaluation-data/source-holdout/report.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Callable, Iterable

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline

WEBSITE_DIR = Path(__file__).resolve().parents[1]
if str(WEBSITE_DIR) not in sys.path:
    sys.path.insert(0, str(WEBSITE_DIR))

import content_model  # noqa: E402

# The committed artifact's decision threshold (README, "Observed email-text
# evaluation"); a test checks it against the artifact.
DEPLOYED_THRESHOLD = 0.3736
DEFAULT_THRESHOLDS = (0.5, DEPLOYED_THRESHOLD)
HARD_NEGATIVE_SOURCE = "synthetic_hard_negatives"

Sources = dict[str, tuple[list[str], list[int], list[str]]]


def production_classifier() -> LogisticRegression:
    """Logistic Regression exactly as content_model.build_content_pipeline configures it."""
    return LogisticRegression(C=4.0, max_iter=2000, solver="liblinear", class_weight="balanced")


def make_production_model():
    return make_pipeline(content_model._build_vectorizer(), production_classifier())


def load_sources(data_dir: Path, *, seed: int = 42) -> Sources:
    """Load every locally available corpus the content model can train on."""
    sources: Sources = {}
    for name, _url, schema in content_model._DATASETS:
        loaded = content_model._load_one_corpus(data_dir / name, schema)
        if loaded is not None and loaded[0]:
            sources[Path(name).stem] = tuple(list(part) for part in loaded)
    spaphish = data_dir / content_model._SPAPHISH_FILENAME
    if spaphish.exists():
        parts = content_model._load_spaphish_partitions(spaphish)
        texts, labels, groups = [], [], []
        for partition in ("train", "validation", "holdout"):
            p_texts, p_labels, p_groups = parts[partition]
            texts += list(p_texts); labels += list(p_labels); groups += list(p_groups)
        if texts:
            sources[Path(content_model._SPAPHISH_FILENAME).stem] = (texts, labels, groups)
    hard = content_model.generate_hard_negative_corpus(seed=seed)
    sources[HARD_NEGATIVE_SOURCE] = tuple(list(part) for part in hard)
    return sources


def deduplicate_across_sources(sources: Sources) -> tuple[Sources, dict]:
    """Keep each normalized message family once, in the first source that has it.

    Families seen with both labels are dropped everywhere, so a held-out corpus
    never shares a message family with the corpora the model is trained on.
    """
    family_labels: dict[str, set[int]] = {}
    for texts, labels, _groups in sources.values():
        for text, label in zip(texts, labels):
            family_labels.setdefault(content_model._normalized_text_family(text), set()).add(int(label))
    conflicting = {family for family, seen in family_labels.items() if len(seen) > 1}
    kept: set[str] = set()
    result: Sources = {}
    stats = {"input_rows": 0, "duplicate_rows_removed": 0, "label_conflict_rows_removed": 0,
             "label_conflict_families": len(conflicting)}
    for name, (texts, labels, groups) in sources.items():
        out = ([], [], [])
        for text, label, group in zip(texts, labels, groups):
            stats["input_rows"] += 1
            family = content_model._normalized_text_family(text)
            if family in conflicting:
                stats["label_conflict_rows_removed"] += 1
            elif family in kept:
                stats["duplicate_rows_removed"] += 1
            else:
                kept.add(family)
                out[0].append(text); out[1].append(int(label)); out[2].append(f"{name}:{group}")
        if out[0]:
            result[name] = out
    stats["output_rows"] = sum(len(texts) for texts, _, _ in result.values())
    return result, stats


def _sample(sources: Sources, max_per_source: int | None, seed: int) -> Sources:
    if not max_per_source:
        return sources
    rng = np.random.default_rng(seed)
    sampled: Sources = {}
    for name, (texts, labels, groups) in sources.items():
        if len(texts) <= max_per_source:
            sampled[name] = (texts, labels, groups)
            continue
        index = sorted(rng.choice(len(texts), size=max_per_source, replace=False))
        sampled[name] = tuple([part[i] for i in index] for part in (texts, labels, groups))
    return sampled


def _rate(numerator: int, denominator: int) -> dict | None:
    if denominator == 0:
        return None
    low, high = content_model._wilson_interval(numerator, denominator)
    return {"value": round(numerator / denominator, 4), "count": numerator, "of": denominator,
            "wilson_95": [round(low, 4), round(high, 4)]}


def score_metrics(labels: Iterable[int], scores: Iterable[float], thresholds: Iterable[float]) -> dict:
    labels = np.asarray(list(labels), dtype=int)
    scores = np.asarray(list(scores), dtype=float)
    phishing, legitimate = int(labels.sum()), int((labels == 0).sum())
    both = phishing > 0 and legitimate > 0
    metrics = {
        "rows": int(labels.size), "phishing": phishing, "legitimate": legitimate,
        "pr_auc": round(float(average_precision_score(labels, scores)), 4) if both else None,
        "roc_auc": round(float(roc_auc_score(labels, scores)), 4) if both else None,
        "at_threshold": {},
    }
    for threshold in thresholds:
        flagged = scores >= threshold
        metrics["at_threshold"][f"{threshold:g}"] = {
            "phishing_recall": _rate(int((flagged & (labels == 1)).sum()), phishing),
            "false_positive_rate": _rate(int((flagged & (labels == 0)).sum()), legitimate),
        }
    return metrics


def evaluate(sources: Sources, *, make_model: Callable = make_production_model,
             thresholds: Iterable[float] = DEFAULT_THRESHOLDS, folds: int = 5, seed: int = 42,
             in_distribution: bool = True, progress: Callable[[str], None] = print) -> dict:
    """Per-source metrics for the in-distribution baseline and leave-one-source-out."""
    thresholds = tuple(thresholds)
    names = list(sources)
    texts = [t for name in names for t in sources[name][0]]
    labels = np.array([y for name in names for y in sources[name][1]], dtype=int)
    groups = np.array([g for name in names for g in sources[name][2]])
    origin = np.array([name for name in names for _ in sources[name][0]])
    report: dict = {"sources": {}}

    if in_distribution:
        oof = np.full(labels.size, np.nan)
        splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
        for fold, (train, test) in enumerate(splitter.split(texts, labels, groups), 1):
            started = time.monotonic()
            model = make_model().fit([texts[i] for i in train], labels[train])
            oof[test] = model.predict_proba([texts[i] for i in test])[:, 1]
            progress(f"in-distribution fold {fold}/{folds} ({time.monotonic() - started:.0f}s)")
        report["pooled_in_distribution"] = score_metrics(labels, oof, thresholds)

    for name in names:
        held = origin == name
        train_labels = labels[~held]
        entry: dict = {}
        if in_distribution:
            entry["in_distribution"] = score_metrics(labels[held], oof[held], thresholds)
        if len(set(train_labels.tolist())) < 2:
            entry["held_out"] = None
            entry["skipped"] = "remaining corpora lack one of the two labels"
        else:
            started = time.monotonic()
            model = make_model().fit([texts[i] for i in np.flatnonzero(~held)], train_labels)
            scores = model.predict_proba([texts[i] for i in np.flatnonzero(held)])[:, 1]
            entry["held_out"] = score_metrics(labels[held], scores, thresholds)
            progress(f"held out {name} ({int(held.sum())} rows, {time.monotonic() - started:.0f}s)")
        report["sources"][name] = entry
    return report


def _fmt(rate: dict | None) -> str:
    return "—" if rate is None else f"{rate['value'] * 100:.1f}% ({rate['count']}/{rate['of']})"


def markdown_table(report: dict, threshold: float = DEPLOYED_THRESHOLD) -> str:
    key = f"{threshold:g}"
    rows = ["| Held-out corpus | Rows (phish/legit) | PR AUC in-dist → held-out | "
            f"Recall @{key} in-dist → held-out | FPR @{key} in-dist → held-out |",
            "|---|---|---|---|---|"]
    for name, entry in report["sources"].items():
        held, base = entry.get("held_out"), entry.get("in_distribution")
        ref = held or base
        def pair(pick):
            return f"{pick(base) if base else '—'} → {pick(held) if held else 'skipped'}"
        rows.append(
            f"| {name} | {ref['rows']} ({ref['phishing']}/{ref['legitimate']}) "
            f"| {pair(lambda m: m['pr_auc'] if m['pr_auc'] is not None else '—')} "
            f"| {pair(lambda m: _fmt(m['at_threshold'][key]['phishing_recall']))} "
            f"| {pair(lambda m: _fmt(m['at_threshold'][key]['false_positive_rate']))} |")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-dir", type=Path, default=content_model._DEFAULT_DATA_DIR)
    parser.add_argument("--output", type=Path, required=True,
                        help="JSON report path; keep it outside version control (e.g. .evaluation-data/)")
    parser.add_argument("--max-per-source", type=int, default=None,
                        help="seeded cap per corpus for a faster, smaller run")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--skip-in-distribution", action="store_true")
    args = parser.parse_args(argv)

    sources = load_sources(args.data_dir, seed=args.seed)
    sources, dedup = deduplicate_across_sources(sources)
    sources = _sample(sources, args.max_per_source, args.seed)
    print("corpora:", ", ".join(f"{n}={len(s[0])}" for n, s in sources.items()))
    report = evaluate(sources, folds=args.folds, seed=args.seed,
                      in_distribution=not args.skip_in_distribution)
    report["settings"] = {
        "model": "TF-IDF word(1-2)+char_wb(3-5) FeatureUnion + LogisticRegression(C=4, balanced)",
        "thresholds": list(DEFAULT_THRESHOLDS), "folds": args.folds, "seed": args.seed,
        "max_per_source": args.max_per_source, "deduplication": dedup,
        "source_sha256": {p.name: content_model._file_sha256(p)
                          for p in sorted(args.data_dir.glob("*.csv"))},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("\n" + markdown_table(report))
    print(f"\nReport written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
