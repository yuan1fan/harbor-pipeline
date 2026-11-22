import os

from harbor_pipeline.util import read_json, write_json


def test_write_json_retries_transient_windows_replace_lock(tmp_path, monkeypatch):
    real_replace = os.replace
    calls = []

    def flaky_replace(source, destination):
        calls.append((source, destination))
        if len(calls) < 3:
            raise PermissionError(13, "destination is temporarily locked")
        return real_replace(source, destination)

    monkeypatch.setattr("harbor_pipeline.util.os.replace", flaky_replace)
    path = tmp_path / "state.json"
    write_json(path, {"ok": True})
    assert read_json(path) == {"ok": True}
    assert len(calls) == 3
