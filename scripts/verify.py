"""Run repository checks without contacting real services or using live configs."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    missing = [name for name in ('go', 'node') if not shutil.which(name)]
    if missing:
        print('Required tools missing:', ', '.join(missing)); return 2
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env.pop('LOVELYLOG_PRIVATE_FIXTURE_DIR', None)
    commands = [
        (ROOT, [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py']),
        (ROOT/'apps/lovelylivelog', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py']),
        (ROOT/'apps/lovelylivelog', ['node', '--test', 'tests/log-parser.test.mjs', 'tests/local-mode-ui.test.mjs']),
        (ROOT/'apps/lovelylog', ['go', 'test', './...']),
        (ROOT/'apps/lovelylog', ['go', 'vet', './...']),
        (ROOT/'apps/lovelylog', ['node', '--check', 'web/app.js']),
        (ROOT/'honeypots', ['go', 'test', './...']),
        (ROOT/'honeypots', ['go', 'vet', './...']),
        (ROOT, [sys.executable, 'scripts/test_honeypots.py']),
    ]
    commands.extend((ROOT, ['node', '--check', str(path.relative_to(ROOT))])
                    for path in sorted((ROOT/'honeypots/vpn/web').glob('*.js')))
    if os.name == 'nt':
        commands += [(ROOT/'tools/jsp-cleaner', ['go', 'test', './...']),
                     (ROOT/'tools/jsp-cleaner', ['go', 'vet', './...'])]
    else:
        print('SKIP: JSP Cleaner requires Windows; run the Windows CI job for it.')
    # Use a long, known absolute path rather than inherited Windows 8.3 TEMP paths.
    with tempfile.TemporaryDirectory(prefix='blue-team-verify-', dir=ROOT.parent) as temp:
        env['TEMP'] = env['TMP'] = env['TMPDIR'] = temp
        for cwd, command in commands:
            print('CHECK', cwd.relative_to(ROOT), ' '.join(command), flush=True)
            result = subprocess.run(command, cwd=cwd, env=env, check=False)
            if result.returncode:
                return result.returncode
    print('Core verification passed. Run release_scan.py before packaging; run test_nginx.py for native Nginx.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
