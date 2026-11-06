"""Smoke-check a built wheel outside the source tree (used by CI)."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

wheel = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="harbor-wheel-") as directory:
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(directory)
    script = '''
from harbor_pipeline.contracts import load_schema, load_policy
from harbor_pipeline.generator import harbor_task_schema
from pathlib import Path
import harbor_pipeline
assert load_schema('cve-spec')['title'] == 'CveSpec'
assert load_policy().profile('qualification').trials >= 3
assert harbor_task_schema()
assert (Path(harbor_pipeline.__file__).parent / 'assets' / 'fixed_runner.py').is_file()
print('wheel resources and imports OK:', harbor_pipeline.__version__)
'''
    subprocess.run([sys.executable, "-c", script], cwd=directory,
        env={**os.environ, "PYTHONPATH": directory}, check=True)
