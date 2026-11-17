"""Recover candidate errors; retry infrastructure; never weaken fixed gates."""
import copy
from types import SimpleNamespace

import pytest

from harbor_pipeline import evidence_resolver
from harbor_pipeline.agent import AgentOutcome
from harbor_pipeline.discovery import Discovery
from harbor_pipeline.errors import TaskError, recovery_decision
from harbor_pipeline.pipeline import CvePipeline
from harbor_pipeline.util import read_json, write_json
from harbor_pipeline.worker import execute_pipeline
from test_author_evidence_review import case as case, request_review, OLD_BAD
from test_sample50_resolver import _proposal

REAL_RESOLVE = evidence_resolver.EvidenceResolver.resolve


@pytest.mark.parametrize("code", ['build_error', 'generation_error', 'validation_error', 'oracle_failure', 'attribution_failure', 'grader_failure'])
def test_all_task_repair_categories_reach_author(case, monkeypatch, code):
    calls = []
    monkeypatch.setattr(case.pipeline, '_resume_author', lambda error: calls.append(error.category.code) or True)
    assert case.pipeline._attempt_repair(TaskError(code, 'candidate defect'))
    assert calls == [code]


def test_task_failure_returns_through_the_pipeline_loop_and_records_why(case, monkeypatch):
    advances, repairs = [], []
    completed = object()

    def advance(until):
        advances.append(until)
        if len(advances) == 1:
            raise TaskError('attribution_failure', 'task does not exercise the cited fix')
        return completed

    monkeypatch.setattr(case.pipeline, '_advance', advance)
    monkeypatch.setattr(case.pipeline, '_resume_author', lambda error: repairs.append(error) or True)
    assert case.pipeline._run('validate') is completed
    assert advances == ['validate', 'validate'] and len(repairs) == 1
    assert case.pipeline.store.read_artifact('recovery-log.json')[0]['error']['recovery']['action'] == 'author'


def test_failed_author_turn_can_use_remaining_repair_allowance(case, monkeypatch):
    calls = []

    def resume(error):
        calls.append(error)
        job = case.pipeline.store.load()
        job.attempts['author_resume'] = len(calls)
        case.pipeline.store.save(job)
        return len(calls) == 2

    monkeypatch.setattr(case.pipeline, '_resume_author', resume)
    assert case.pipeline._attempt_repair(TaskError('validation_error', 'bad PoC'))
    assert len(calls) == 2


def test_failed_author_cannot_loop_past_persisted_allowance(case, monkeypatch):
    calls = []

    def resume(error):
        calls.append(error)
        job = case.pipeline.store.load()
        job.attempts['author_resume'] = len(calls)
        case.pipeline.store.save(job)
        return False

    monkeypatch.setattr(case.pipeline, '_resume_author', resume)
    error = TaskError('validation_error', 'bad PoC')
    assert not case.pipeline._attempt_repair(error)
    assert len(calls) == case.ctx.config.pipeline.author_max_resumes
    assert error.as_record()['recovery']['action'] == 'stop'


def classify(records, task=(), framework=(), abort=''):
    pipeline = object.__new__(CvePipeline)
    records = [{"trial_id": f"trial-{i}", "goal_result": "failed", "health": {"ok": True},
                "trigger_evidence": {"detail": "observed"}, **record} for i, record in enumerate(records)]
    matrix = SimpleNamespace(records=records, aborted_detail=abort)
    outcome = SimpleNamespace(hard_conditions=[{'id': key, 'passed': False, 'detail': key} for key in task],
        evaluation={'admission_status': 'quarantined', 'framework_health': [
            {'id': key, 'passed': False, 'detail': key} for key in framework]})
    snapshot = copy.deepcopy(outcome.evaluation)
    error = pipeline._matrix_repair_error(matrix, outcome)
    assert outcome.evaluation == snapshot
    return error


def test_real_candidate_negative_is_repaired_but_framework_negative_is_blocked():
    record = {'experiment_id': 'T05', 'reward': 1.0, 'health': {'ok': True}, 'goal_result': 'passed'}
    assert recovery_decision(classify([record], framework=['negative_T05']))['action'] == 'author'
    record['_audit'] = {'mode': 'framework-verifier'}
    assert recovery_decision(classify([record], framework=['negative_T05']))['action'] == 'blocked'


def test_measured_app_health_failure_is_not_confused_with_host_oom():
    record = {'experiment_id': 'T04', 'health': {'ok': False}, 'error_category': 'infra_error'}
    assert recovery_decision(classify([record], task=['t02_fixed_health']))['action'] == 'author'
    assert recovery_decision(classify([record], task=['t02_fixed_health'], abort='OOMKilled, exit code 137'))['action'] == 'retry'


def test_observed_failed_fault_injection_requires_framework_fix():
    error = classify([{'experiment_id': 'T12'}], framework=['fault_T12'])
    assert error.as_record()['recovery']['action'] == 'blocked'
    assert not error.as_record()['retryable']


def report(error):
    return SimpleNamespace(error=error, to_json=lambda: {'error': error})


def test_worker_uses_the_same_extended_source_retry_limit_as_pipeline():
    calls = []

    def run():
        calls.append(1)
        error = TaskError('source_error', 'temporary DNS connection reset').as_record() if len(calls) < 4 else None
        return report(error)

    payload = execute_pipeline(SimpleNamespace(run=run), retries=1)
    assert payload['attempts'] == 4 and payload['error'] is None


def test_zero_retry_allowance_also_disables_extended_source_retries():
    error = TaskError('source_error', 'temporary DNS connection reset').as_record()
    calls = []
    execute_pipeline(SimpleNamespace(run=lambda: calls.append(1) or report(error)), retries=0)
    assert calls == [1]


@pytest.mark.parametrize('error', [TaskError('infra_error', 'AgentAuthenticationError'), TaskError('budget_exhausted', 'tokens used')])
def test_worker_does_not_burn_allowance_on_external_blockers_or_exhaustion(error):
    calls = []
    payload = execute_pipeline(SimpleNamespace(run=lambda: calls.append(1) or report(error.as_record())), retries=12)
    assert len(calls) == 1 and payload['attempts'] == 1


def test_explicit_new_invocation_can_retry_after_credentials_are_fixed(case):
    pipeline = case.pipeline
    pipeline.store.fail(pipeline.store.load(), TaskError('infra_error', 'AgentAuthenticationError'))
    assert pipeline.store.load().error['retryable'] is False
    job = pipeline._prepare_retry(pipeline.store.load())
    assert job.state == 'REPAIRING' and job.attempts['retry'] == 1


@pytest.mark.parametrize('review', [False, True])
@pytest.mark.parametrize('failure', ['bad_ref', 'missing_proposal'])
def test_resolver_receives_failed_checks_and_resumes_same_native_session(case, monkeypatch, review, failure):
    request = request_review(case) if review else None
    calls = []
    proposal = _proposal(case)
    if request:
        proposal['review_request_id'] = request['request_id']

    class Runner:
        def run(self, *, workspace, resume=None, **kwargs):
            calls.append(resume)
            value = copy.deepcopy(proposal)
            if len(calls) == 1:
                value['vulnerable']['resolved_commit'] = 'e' * 40
                if failure == 'missing_proposal':
                    return AgentOutcome(status='completed', session_id='resolver-1')
            else:
                feedback = read_json(workspace / 'inputs/proposal-feedback.json')
                assert feedback['error'] and resume == 'resolver-1'
            write_json(workspace / 'reconciliation.json', value)
            return AgentOutcome(status='completed', session_id='resolver-1')

    monkeypatch.setattr(evidence_resolver.EvidenceResolver, 'resolve', REAL_RESOLVE)
    monkeypatch.setattr(evidence_resolver, 'ClaudeCodeAgent', lambda *a, **k: Runner())
    actual, _ = case.pipeline._resolve_evidence(case.initial, case.collector.save(case.initial.cve_id), review_request=request)
    assert actual.vulnerable_ref == OLD_BAD and calls == [None, 'resolver-1']
    assert case.pipeline.store.load().attempts['resolver_correction'] == 1
    assert read_json(case.pipeline.store.path('resolver-feedback.json'))['status'] == 'accepted'


def test_resolver_correction_limit_is_not_reset_by_restart(case, monkeypatch):
    calls = []

    class Interrupted(BaseException):
        pass

    class Runner:
        def run(self, *, workspace, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise Interrupted()
            value = _proposal(case)
            value['vulnerable']['resolved_commit'] = 'e' * 40
            write_json(workspace / 'reconciliation.json', value)
            return AgentOutcome(status='completed', session_id='resolver-1')

    monkeypatch.setattr(evidence_resolver.EvidenceResolver, 'resolve', REAL_RESOLVE)
    monkeypatch.setattr(evidence_resolver, 'ClaudeCodeAgent', lambda *a, **k: Runner())
    with pytest.raises(Interrupted):
        case.pipeline._resolve_evidence(case.initial, case.collector.save(case.initial.cve_id))
    assert case.pipeline.store.load().attempts['resolver_correction'] == 1
    with pytest.raises(TaskError) as caught:
        case.pipeline._resolve_evidence(case.initial, case.collector.save(case.initial.cve_id))
    assert len(calls) == 3 and case.pipeline.store.load().attempts['resolver_correction'] == 2
    assert caught.value.as_record()['recovery']['action'] == 'stop'
    assert Discovery.from_json(read_json(case.pipeline.store.path('discovery.json'))) == case.initial
