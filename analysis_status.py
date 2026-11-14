# analysis_status.py - Records which parts of an analysis ran, failed or were incomplete
#
# Many parts of the disk analysis can fail or cover only part of the data (an unreadable
# file, a log that is cut at a size limit, a missing library, ...). Logging such events is
# not enough: the person reading the report would not see them and an empty result would
# look like "nothing found". Every stage therefore reports into one AnalysisStatus object
# and the result carries it as 'analysis_status'.
#
# Stage statuses:
#   ok        the stage ran and covered everything it is designed to cover
#   partial   the stage ran, but some input was skipped, cut or unreadable
#   failed    the stage ran into an error and produced no (or unusable) results
#   not_run   the stage could not start (earlier failure, unsupported system)
#   skipped   the stage was left out on purpose (e.g. --quick)
#
# partial, failed and not_run make the whole analysis "incomplete"; skipped does not.

from collections import OrderedDict

OK = 'ok'
PARTIAL = 'partial'
FAILED = 'failed'
NOT_RUN = 'not_run'
SKIPPED = 'skipped'
PENDING = 'pending'          # internal: stage not started yet

STAGE_LABELS = OrderedDict([
    ('filesystem_scan', 'Filesystem scan'),
    ('system_intelligence', 'System intelligence'),
    ('command_history', 'Command history'),
    ('yara_scan', 'YARA scan'),
])

INCOMPLETE_STATUSES = (PARTIAL, FAILED, NOT_RUN)
MAX_EXAMPLES = 3
_SEVERITY_RANK = {PENDING: 0, OK: 1, SKIPPED: 2, PARTIAL: 3, NOT_RUN: 4, FAILED: 5}


class AnalysisStatus:
    """Collects the status of every analysis stage together with the reasons."""

    def __init__(self):
        self._stages = OrderedDict(
            (key, {'status': PENDING, 'problems': OrderedDict(), 'reason': None})
            for key in STAGE_LABELS
        )

    def _stage(self, key):
        if key not in self._stages:
            self._stages[key] = {'status': PENDING, 'problems': OrderedDict(), 'reason': None}
        return self._stages[key]

    def _raise_status(self, stage, status):
        if _SEVERITY_RANK[status] > _SEVERITY_RANK[stage['status']]:
            stage['status'] = status

    def start(self, key):
        """Mark a stage as running; it stays 'ok' unless a problem is reported."""
        stage = self._stage(key)
        if stage['status'] == PENDING:
            stage['status'] = OK

    def _problem(self, key, status, message, example=None, count=1):
        stage = self._stage(key)
        self._raise_status(stage, status)
        entry = stage['problems'].setdefault(
            (status, message), {'status': status, 'message': message, 'count': 0, 'examples': []})
        entry['count'] += count
        examples = example if isinstance(example, (list, tuple)) else [example]
        for item in examples:
            if item is not None and str(item) not in entry['examples'] and len(entry['examples']) < MAX_EXAMPLES:
                entry['examples'].append(str(item))

    def partial(self, key, message, example=None, count=1):
        self._problem(key, PARTIAL, message, example, count)

    def failed(self, key, message, example=None, count=1):
        self._problem(key, FAILED, message, example, count)

    def not_run(self, key, reason):
        stage = self._stage(key)
        self._raise_status(stage, NOT_RUN)
        stage['reason'] = reason

    def skipped(self, key, reason):
        stage = self._stage(key)
        self._raise_status(stage, SKIPPED)
        stage['reason'] = reason

    def status_of(self, key):
        return self._stage(key)['status']

    def is_incomplete(self):
        return any(stage['status'] in INCOMPLETE_STATUSES or stage['status'] == PENDING
                   for stage in self._stages.values())

    def finalize(self):
        """Stages that never started are reported as not run."""
        for stage in self._stages.values():
            if stage['status'] == PENDING:
                stage['status'] = NOT_RUN
                stage['reason'] = stage['reason'] or 'Stage was not reached'

    def to_dict(self):
        self.finalize()
        stages = []
        for key, stage in self._stages.items():
            stages.append({
                'stage': key,
                'name': STAGE_LABELS.get(key, key),
                'status': stage['status'],
                'reason': stage['reason'],
                'problems': [dict(p) for p in stage['problems'].values()],
            })
        incomplete = [s['name'] for s in stages if s['status'] in INCOMPLETE_STATUSES]
        return {
            'overall': 'incomplete' if incomplete else 'complete',
            'incomplete_stages': incomplete,
            'stages': stages,
        }


# Module-level helpers: every analysis function takes an optional `status` argument, so
# these accept None and do nothing (the functions keep working when called standalone).

def report_start(status, key):
    if status is not None:
        status.start(key)


def report_partial(status, key, message, example=None, count=1):
    if status is not None:
        status.partial(key, message, example, count)


def report_failed(status, key, message, example=None, count=1):
    if status is not None:
        status.failed(key, message, example, count)


def report_not_run(status, key, reason):
    if status is not None:
        status.not_run(key, reason)


def report_skipped(status, key, reason):
    if status is not None:
        status.skipped(key, reason)