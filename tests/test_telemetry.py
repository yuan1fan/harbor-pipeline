"""Per-call history, accurate cache accounting, and restart-safe stage views."""
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from harbor_pipeline import telemetry
from harbor_pipeline.agent import AgentOutcome, ClaudeCodeAgent
from harbor_pipeline.config import Config
from harbor_pipeline.providers.base import ModelResponse
from harbor_pipeline.errors import TaskError
from harbor_pipeline.util import PipelineError, read_json
from test_author_evidence_review import case as case


def native_usage(input_tokens=10):
    return {"input_tokens": input_tokens, "output_tokens": 5,
            "cache_read_input_tokens": 30, "cache_creation_input_tokens": 20}


def view(root):
    return read_json(root / telemetry.SUMMARY)


def test_cache_is_not_added_twice_to_harbor_input():
    native = telemetry.usage(native_usage(), source='anthropic', cost=0.1)
    harbor = telemetry.usage({'n_input_tokens': 60, 'n_output_tokens': 5, 'n_cache_tokens': 30, 'cost_usd': 0.1}, source='harbor')
    assert native['input_tokens'] == harbor['input_tokens'] == 60
    assert native['total_tokens'] == harbor['total_tokens'] == 65
    assert harbor['cache_creation_input_tokens'] is None


def test_estimated_provider_usage_is_separate_from_reported_usage():
    response = ModelResponse('', {}, {'input_tokens': 1000, 'input_tokens_estimated': True, 'input_tokens_reported': 60}, 'test',
                             raw={'usage': native_usage()})
    result = telemetry.response_usage(response)
    assert result['input_tokens'] == 60 and result['estimated_input_tokens'] == 1000


def test_parent_and_same_session_resumes_are_not_double_counted(tmp_path):
    with telemetry.Stage('authoring', root=tmp_path):
        for reason in ('initial', 'repair'):
            with telemetry.details(reason=reason, repair_round=1 if reason == 'repair' else 0):
                with telemetry.Stage('author', expects_usage=True) as parent:
                    with telemetry.Stage('author', kind='model_call', expects_usage=True) as child:
                        child.outcome(AgentOutcome('completed', session_id='same-session', usage=native_usage(), usd=0.1))
                    parent.outcome(AgentOutcome('completed', session_id='same-session', usage=native_usage(), usd=0.1))
    report = view(tmp_path)
    assert report['totals']['total_tokens'] == 130
    assert report['totals']['cost_usd'] == pytest.approx(0.2)
    assert report['metered_invocations'] == 2
    parents = [r for r in report['stages'] if r['stage'] == 'author' and r['kind'] == 'stage']
    assert [r['attempt'] for r in parents] == [1, 2]
    assert [r['reason'] for r in parents] == ['initial', 'repair']
    assert all(r['elapsed_sec'] >= 0 and r['started_at'] <= r['finished_at'] for r in parents)


def test_cached_stages_have_zero_new_usage_but_original_call_remains(tmp_path):
    with telemetry.Stage('solver', root=tmp_path, expects_usage=True) as first:
        first.set_usage({'n_input_tokens': 60, 'n_output_tokens': 5, 'n_cache_tokens': 30, 'cost_usd': 0.1}, source='harbor')
    with telemetry.Stage('solver', root=tmp_path, expects_usage=True) as cached:
        cached.cache('solver-result.json')
    report = view(tmp_path)
    assert report['totals']['total_tokens'] == 65
    assert report['stages'][-1]['usage']['total_tokens'] == 0
    assert report['stages'][-1]['status'] == 'cached'


def test_failed_and_unfinished_calls_remain_unknown_not_zero(tmp_path):
    with pytest.raises(TimeoutError):
        with telemetry.Stage('author', root=tmp_path, kind='model_call', expects_usage=True):
            raise TimeoutError('PRIVATE KEY THAT MUST NOT BE WRITTEN')
    pending = {'event': 'started', 'invocation_id': 'interrupted-process', 'parent_id': None,
               'stage': 'resolver', 'kind': 'model_call', 'expects_usage': True, 'status': 'running'}
    with (tmp_path / telemetry.EVENTS).open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(pending)+'\n')
    report = telemetry.rebuild(tmp_path)
    assert report['incomplete_stages'] == 1
    assert report['stages'][-1]['status'] == 'unfinished'
    assert report['totals']['total_tokens'] is None
    assert report['totals']['missing']['total_tokens'] == 2
    assert 'PRIVATE KEY' not in (tmp_path / telemetry.EVENTS).read_text()


def test_append_preserves_partial_log_and_attempt_numbers(tmp_path):
    with telemetry.Stage('author', root=tmp_path):
        pass
    with (tmp_path / telemetry.EVENTS).open('ab') as handle:
        handle.write(b'{incomplete')
    with telemetry.Stage('author', root=tmp_path):
        pass
    report = telemetry.rebuild(tmp_path)
    assert report['malformed_event_lines'] == 1
    assert [r['attempt'] for r in report['stages']] == [1, 2]


def test_missing_historical_log_is_not_a_zero_cost_candidate(tmp_path):
    with pytest.raises(PipelineError, match='historical usage'):
        telemetry.rebuild(tmp_path)
    assert not (tmp_path / telemetry.SUMMARY).exists()


def test_parallel_writers_keep_distinct_events_and_totals(tmp_path):
    def run(_):
        with telemetry.Stage('reviewer', root=tmp_path, kind='model_call', expects_usage=True) as meter:
            meter.set_usage({'input_tokens': 10, 'output_tokens': 2, 'cost_usd': 0.1})
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(run, range(8)))
    report = view(tmp_path)
    assert len(report['stages']) == 8 and report['totals']['total_tokens'] == 96
    assert sorted(r['attempt'] for r in report['stages']) == list(range(1, 9))


def test_different_candidates_never_inherit_each_others_identity(tmp_path):
    with telemetry.Stage('pipeline', root=tmp_path/'CVE-A', cve_id='CVE-A'):
        with telemetry.Stage('author', root=tmp_path/'CVE-B'):
            pass
    assert view(tmp_path/'CVE-B')['stages'][0]['cve_id'] == 'CVE-B'
    assert view(tmp_path/'CVE-B')['stages'][0]['parent_id'] is None


def test_native_auth_fallback_records_both_attempts(tmp_path, monkeypatch):
    monkeypatch.setattr('harbor_pipeline.agent.shutil.which', lambda _: 'fake-claude')
    agent = ClaudeCodeAgent(Config(), role="resolver")
    calls = []

    def run_once(**kwargs):
        calls.append(kwargs)
        return AgentOutcome('auth_error') if len(calls) == 1 else AgentOutcome('completed', session_id='session', usage=native_usage(), usd=0.1)

    monkeypatch.setattr(agent, '_run_once', run_once)
    agent.run(prompt='PRIVATE PROMPT', workspace=tmp_path/'author', contract='private', settings_path=tmp_path/'settings.json')
    report = view(tmp_path)
    assert len(report['stages']) == 2 and report['metered_invocations'] == 2
    assert report['totals']['total_tokens'] is None  # failed authentication did not report usage
    assert report['totals']['known']['total_tokens'] == 65
    assert 'PRIVATE PROMPT' not in (tmp_path / telemetry.EVENTS).read_text()


def test_invalid_model_output_can_still_report_paid_usage(tmp_path):
    def generate(_):
        failure = PipelineError('invalid JSON including private content')
        failure.metering_usage = telemetry.usage(native_usage(), source='anthropic', cost=0.1)
        raise failure
    with telemetry.Stage('reviewer', root=tmp_path):
        with pytest.raises(PipelineError):
            telemetry.model_request(SimpleNamespace(generate=generate), object())
    assert view(tmp_path)['totals']['total_tokens'] == 65
    assert 'private content' not in (tmp_path / telemetry.EVENTS).read_text()


def test_provider_factory_and_reviewer_wrapper_record_one_billable_call(tmp_path):
    provider = SimpleNamespace(name='fixture', generate=lambda request: ModelResponse('', {}, {'input_tokens': 10, 'output_tokens': 2, 'usd': 0.1}, 'test'))
    provider = telemetry.metered_provider(provider, 'reviewer', 'test')
    with telemetry.Stage('reviewer', root=tmp_path):
        telemetry.model_request(provider, object(), reason='format_correction')
    report = view(tmp_path)
    calls = [r for r in report['stages'] if r['kind'] == 'model_call']
    assert len(calls) == 1 and calls[0]['call_reason'] == 'format_correction'
    assert report['totals']['total_tokens'] == 12


def test_cli_model_fallback_keeps_failed_attempt_and_paid_invalid_output(tmp_path, monkeypatch):
    from harbor_pipeline.providers.claude_cli import ClaudeCliProvider
    from harbor_pipeline.providers.base import ModelRequest
    from harbor_pipeline.config import ModelSettings
    calls = []
    monkeypatch.setattr('harbor_pipeline.providers.claude_cli.shutil.which', lambda _: 'fake-claude')

    def run(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            return SimpleNamespace(returncode=1, stdout='', stderr='unrecognized_model')
        return SimpleNamespace(returncode=0, stdout=json.dumps({'result': 'PRIVATE INVALID OUTPUT', 'usage': native_usage(),
                                                               'total_cost_usd': 0.1}), stderr='')

    monkeypatch.setattr('harbor_pipeline.providers.claude_cli.subprocess.run', run)
    provider = telemetry.metered_provider(ClaudeCliProvider(ModelSettings()), 'reviewer', 'test')
    with telemetry.Stage('reviewer', root=tmp_path):
        with pytest.raises(PipelineError):
            telemetry.model_request(provider, ModelRequest('reviewer', 'PRIVATE SYSTEM', 'PRIVATE PROMPT', schema={'type': 'object'}))
    report = view(tmp_path)
    assert report['metered_invocations'] == 2
    assert report['totals']['known']['total_tokens'] == 65 and report['totals']['total_tokens'] is None
    assert len(calls) == 2 and 'PRIVATE' not in (tmp_path / telemetry.EVENTS).read_text()


def test_author_repair_metadata_survives_same_session_resume(case, monkeypatch):
    pipeline = case.pipeline

    class Agent:
        def run(self, **kwargs):
            return AgentOutcome('completed', session_id='same-session', usage=native_usage(), usd=0.1)

    monkeypatch.setattr('harbor_pipeline.pipeline.ClaudeCodeAgent', lambda *a, **k: Agent())
    monkeypatch.setattr('harbor_pipeline.author_debug.suspend', lambda *a: None)
    pipeline._run_author_session(case.workspace, prompt='initial', resume=None)
    assert not pipeline._resume_author(TaskError('validation_error', 'first repair'))
    assert not pipeline._resume_author(TaskError('validation_error', 'second repair'))
    report = view(pipeline.store.root)
    rows = [r for r in report['stages'] if r['stage'] == 'author']
    assert [r.get('repair_round') for r in rows] == [None, 1, 2]
    assert [r['reason'] for r in rows] == ['initial', 'repair', 'repair']
    assert report['totals']['total_tokens'] == 195
    assert read_json(pipeline.store.path('author-session.json'))['outcome']['session_id'] == 'same-session'


def test_solver_trials_reviewer_and_cache_keep_separate_stage_costs(case, monkeypatch):
    from harbor_pipeline import fixtures, solver_review
    from harbor_pipeline.generator import render_task
    from harbor_pipeline.util import digest
    from test_sample50_retries import _review

    pipeline = case.pipeline
    spec = fixtures.cve_spec()
    task = render_task(spec, scenario_name='fixture', variant='vulnerable')
    pipeline.store.write_artifact('image-set.json', {})
    monkeypatch.setattr(pipeline, '_solver_task', lambda *a: (task, pipeline.store.root/'task'))
    monkeypatch.setattr(solver_review, 'build_evidence_context', lambda *a: 'same evidence')
    solves, reviews = [], []

    def solve(*a, **k):
        solves.append(1)
        measured = {'n_input_tokens': 60, 'n_output_tokens': 5, 'n_cache_tokens': 30, 'cost_usd': 0.1}
        return {'usage': measured, 'trials': [{'reward': 0.0, 'usage': measured, 'duration_sec': 4.5,
            'started_at': '2026-01-01T00:00:00Z', 'finished_at': '2026-01-01T00:00:04.5Z'}]}

    def generate(request):
        reviews.append(1)
        result = _review()
        return ModelResponse(json.dumps(result), result, {'input_tokens': 10, 'output_tokens': 2, 'cost_usd': 0.2}, 'fixture')

    monkeypatch.setattr(solver_review, 'run_solver', solve)
    monkeypatch.setattr(solver_review, 'build_provider', lambda *a: SimpleNamespace(generate=generate))
    pipeline.solver_review(spec)
    first = digest(view(pipeline.store.root)['totals'])
    pipeline.solver_review(spec)
    report = view(pipeline.store.root)
    assert len(solves) == len(reviews) == 1 and digest(report['totals']) == first
    assert report['totals']['total_tokens'] == 77 and report['totals']['cost_usd'] == pytest.approx(0.3)
    assert report['by_stage']['solver']['metered_elapsed_sec'] == 4.5
    assert report['metered_invocations'] == 2
    assert {r['stage'] for r in report['stages'] if r.get('cache_hit')} >= {'solver', 'reviewer'}
