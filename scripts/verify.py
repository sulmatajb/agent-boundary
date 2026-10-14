import datetime
import hashlib
import json
import platform
from pathlib import Path
import sys
import time
import unittest

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / 'src'))
suite = unittest.defaultTestLoader.discover(str(root / 'tests'))
start = time.monotonic()
result = unittest.TextTestRunner(verbosity=1).run(suite)
source = hashlib.sha256()
for file in sorted((root / 'src').rglob('*.py')):
    source.update(file.relative_to(root).as_posix().encode() + b'\0' + file.read_bytes() + b'\0')
report = {
 'kind': 'deterministic_automated_suite_not_live_model_evaluation',
 'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'python': platform.python_version(), 'platform': platform.system(),
 'tests_run': result.testsRun, 'failures': len(result.failures),
 'errors': len(result.errors), 'skipped': len(result.skipped),
 'duration_seconds': round(time.monotonic()-start, 3),
 'passed': result.wasSuccessful(), 'source_sha256': source.hexdigest(),
 'source_hash_recipe': 'Sorted src/**/*.py: UTF-8 relative POSIX path + NUL + file bytes + NUL, SHA-256.'
}
(root / 'evidence' / 'tests.json').write_text(json.dumps(report, indent=2) + '\n')
sys.exit(0 if result.wasSuccessful() else 1)
