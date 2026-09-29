"""Experimental model-input text normalization (evaluation only; the served model does not use it).

A leave-one-source-out run with this normalization (docs/evaluation.md section 4)
did not improve transfer to unseen corpora, so it is kept only as an
evaluate_source_holdout.py --normalize option for reproducing that result.

The deployed model's strongest features include corpus and era details rather
than phishing cues: years (2005, 2026), clock times ("pm"), quoted-reply markers
("> "), and specific URLs and addresses. This replaces those surface details with
fixed tokens so a classifier cannot key on them. The tokens are plain letters so
both the word (\\w\\w+) and char_wb n-gram vectorizers treat them as ordinary words.

Person and list names (enron, jose, opensuse) are not handled here: removing them
needs corpus-specific rules, which belong in corpus selection and balancing.
"""
from __future__ import annotations

import re
from typing import Iterable

URL_TOKEN = "zzurl"
EMAIL_TOKEN = "zzemail"
TIME_TOKEN = "zztime"
YEAR_TOKEN = "zzyear"
NUMBER_TOKEN = "zznum"

_QUOTE_MARKERS = re.compile(r"^[ \t]*(?:>[ \t]?)+", re.MULTILINE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b", re.IGNORECASE)
# Trailing sentence punctuation is not part of the URL.
_URL = re.compile(r"\b(?:https?://|www\.)\S+?(?=[.,;:!?)\]]*(?:\s|$))", re.IGNORECASE)
_TIME = re.compile(r"\b\d{1,2}(?::\d{2}(?::\d{2})?(?:\s*[ap]\.?m\b\.?)?|\s*[ap]\.?m\b\.?)", re.IGNORECASE)
_YEAR = re.compile(r"\b(?:19|20)\d{2}\b")
_NUMBER = re.compile(r"\b\d+(?:[.,]\d+)*\b")
_SPACE = re.compile(r"\s+")


def normalize_for_model(text: str) -> str:
    """Return text with corpus-identifying surface details replaced by tokens.

    Idempotent: normalizing an already normalized text returns it unchanged.
    """
    text = _QUOTE_MARKERS.sub("", str(text))
    text = _EMAIL.sub(f" {EMAIL_TOKEN} ", text)
    text = _URL.sub(f" {URL_TOKEN} ", text)
    text = _TIME.sub(f" {TIME_TOKEN} ", text)
    text = _YEAR.sub(f" {YEAR_TOKEN} ", text)
    text = _NUMBER.sub(f" {NUMBER_TOKEN} ", text)
    return _SPACE.sub(" ", text).strip()


def normalize_texts(texts: Iterable[str]) -> list[str]:
    """Batch form for use inside a scikit-learn pipeline (FunctionTransformer)."""
    return [normalize_for_model(text) for text in texts]
