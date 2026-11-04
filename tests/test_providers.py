"""Provider parsing tests: model output is untrusted text, not JSON."""

from __future__ import annotations

from harbor_pipeline.providers.anthropic_api import _parse_json_object, _usage


def test_parse_accepts_fenced_object():
    text = '```json\n{"supported": true, "product": {"name": "x"}}\n```'
    assert _parse_json_object(text) == {"supported": True, "product": {"name": "x"}}


def test_parse_tolerates_prose_before_and_after():
    text = (
        "Here is the bundle you asked for:\n"
        '{"supported": true, "poc": {"reference": "print(1)"}}\n'
        "Note: the reference PoC uses {braces} in its payload."
    )
    value = _parse_json_object(text)
    assert value["supported"] is True
    assert value["poc"]["reference"] == "print(1)"


def test_parse_tolerates_literal_newlines_inside_strings():
    # The completion endpoint sometimes emits a raw newline in a PoC string;
    # strict JSON rejects it even though the object is unambiguous.
    text = '{"supported": true, "note": "line one\nline two"}'
    value = _parse_json_object(text)
    assert value["note"] == "line one\nline two"


def test_parse_returns_none_without_an_object():
    assert _parse_json_object("I cannot build a task for this CVE.") is None


def test_usage_counts_cached_prompt_tokens():
    # The gateway bills cache reads separately, so they are part of the
    # context that max_total_tokens must account for.
    usage = {
        "input_tokens": 2178,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 384,
        "output_tokens": 10,
    }

    result = _usage(usage, "", "x" * 8000)

    assert result["input_tokens"] == 2562
    assert result["output_tokens"] == 10
    assert "input_tokens_estimated" not in result


def test_usage_floors_an_implausibly_low_input_report():
    # Observed once: 134 input tokens for an 8 KB prompt. Trusting it would
    # let a campaign exceed its token budget without noticing.
    result = _usage({"input_tokens": 134, "output_tokens": 10}, "", "x" * 8000)

    assert result["input_tokens"] == 2000
    assert result["input_tokens_reported"] == 134
    assert result["input_tokens_estimated"] is True
