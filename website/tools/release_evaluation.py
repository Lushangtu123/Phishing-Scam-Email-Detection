"""Opt-in coverage and human-review contract for a private release comparison.

This validates declarations and their report bindings, not the truth of consent,
labels or independence. Raw mail and audit evidence remain outside this tool.
"""
from datetime import date
import re

if __package__:
    from .compare_evaluations import PRIVATE, compare
else:
    from compare_evaluations import PRIVATE, compare


ATTESTATIONS = (
    'real_consented_mail', 'all_labels_independently_reviewed',
    'provider_language_and_received_dates_verified',
    'families_separated_from_development', 'excluded_from_training_and_tuning',
    'holdout_untouched_before_this_comparison',
)
MINIMUM_CELL_SIZE = 50
IDENTIFIER = re.compile(r'[A-Za-z0-9_.-]{1,80}')
SHA256 = re.compile(r'[a-f0-9]{64}')


def compare_release(baseline, candidate, review):
    """Keep the full regression gate and require bound independent-cohort review."""
    result = compare(baseline, candidate)
    errors = result['errors']
    minimum = None
    try:
        if not isinstance(review, dict) or type(review.get('schema_version')) is not int or review['schema_version'] != 1:
            raise ValueError('A versioned release review is required')
        if any(report.get('evaluation_scope') != PRIVATE for report in (baseline, candidate)):
            raise ValueError('Release review requires private serving reports, not synthetic/public controls')
        declared_minimum = review['minimum_per_class_per_provider_language']
        if type(declared_minimum) is not int or declared_minimum < MINIMUM_CELL_SIZE:
            raise ValueError('Release coverage policy must require at least 50 messages per class per provider/language cell')
        minimum = declared_minimum
        for field in ('dataset_sha256', 'evaluated_cohort_sha256'):
            digest = review[field]
            if (not isinstance(digest, str) or not SHA256.fullmatch(digest)
                    or any(report['input_integrity'][field] != digest for report in (baseline, candidate))):
                raise ValueError('Release review does not bind the evaluated cohort')
        for role, report in (('baseline', baseline), ('candidate', candidate)):
            expected = {'model_artifact_sha256': report['model_artifact_sha256'],
                        'source_sha256': report['reproducibility']['source_sha256']}
            if (review[role] != expected or any(not isinstance(digest, str) or not SHA256.fullmatch(digest)
                                               for digest in expected.values())):
                raise ValueError('Release review does not bind both code/model identities')
        preparer, reviewer = review['cohort_preparer'], review['independent_reviewer']
        if (any(not isinstance(actor, str) or not IDENTIFIER.fullmatch(actor) for actor in (preparer, reviewer))
                or preparer == reviewer):
            raise ValueError('A separate cohort preparer and independent reviewer are required')
        attestations = review['attestations']
        if not isinstance(attestations, dict) or any(attestations.get(key) is not True for key in ATTESTATIONS):
            raise ValueError('Real mail, reviewed metadata, consent and untouched independent holdout attestations are required')
        evidence = review['evidence_reference']
        if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 2000:
            raise ValueError('A private review evidence reference is required')

        def calendar(field):
            value = review[field]
            if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
                raise ValueError('Release review dates must be calendar dates')
            return date.fromisoformat(value)

        cutoff, frozen, started, reviewed = (calendar(field) for field in (
            'training_cutoff', 'cohort_frozen_at', 'candidate_development_started_at', 'reviewed_at'))
        if not cutoff < date.fromisoformat(baseline['first_received_at']):
            raise ValueError('Release cohort must follow the reviewed training/tuning cutoff')
        if not date.fromisoformat(baseline['last_received_at']) <= frozen <= started <= reviewed:
            raise ValueError('Release cohort must be frozen before candidate development and reviewed afterward')
        # The comparator already verifies these marginals against exact three-way
        # counts. Check both reports anyway so a malformed candidate cannot qualify.
        for report in (baseline, candidate):
            groups = report['by_provider_language']
            languages = set(report['by_language'])
            if (set(groups) != {'gmail', 'outlook'} or not {'en', 'zh'} <= languages
                    or 'unlabeled' in languages):
                raise ValueError('Release cohort requires Gmail/Outlook and explicit English/Chinese groups')
            for provider in ('gmail', 'outlook'):
                if not {'en', 'zh'} <= set(groups[provider]):
                    raise ValueError('Every release provider requires both English and Chinese groups')
                for language in ('en', 'zh'):
                    if any(type(groups[provider][language].get(label + '_count')) is not int
                           or groups[provider][language][label + '_count'] < minimum
                           for label in ('phishing', 'legitimate')):
                        raise ValueError('Release cohort is below its per-class provider/language coverage policy')
    except ValueError as exc:
        errors.append(str(exc))
    except (KeyError, TypeError, AttributeError):
        errors.append('Malformed or incomplete release review/cohort metadata')
    result['errors'] = list(dict.fromkeys(errors))
    result['passed'] = not result['errors']
    result['release_review'] = {
        'required': True,
        'minimum_per_class_per_provider_language': minimum,
        'limitation': ('Human review, consent, labels and independence are self-attested, not machine-proven. '
                       'The sample minimum is a coverage floor, not statistical adequacy or acceptable accuracy. '
                       'Passing does not deploy or authorize a release.'),
    }
    return result
