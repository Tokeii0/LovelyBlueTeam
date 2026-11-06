"""Fail-closed source release checks. Findings never include matched secrets."""
import argparse
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', '__pycache__', '.venv', 'node_modules'}
TEXT_SUFFIXES = {'.py', '.go', '.mod', '.sum', '.js', '.mjs', '.html', '.css', '.svg',
                 '.md', '.txt', '.json', '.jsonl', '.cmd', '.bat', '.ps1', '.sh', '.conf',
                 '.example', '.xml', '.config', '.lua', '.yml', '.yaml', '.toml', '.csv', '.sha256'}
TEXT_NAMES = {'.gitignore', '.editorconfig', '.gitattributes', '.dockerignore', 'Dockerfile'}
DENIED_DIRS = {'runtime', '.artifacts', 'backups', 'evidence', 'dist', 'build'}
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'provider-token': re.compile(r'\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{25,}|AIza[A-Za-z0-9_-]{30,})'),
    'personal-home': re.compile(r'(?:[A-Za-z]:[\\/]+Users[\\/]+|/Users/|/home/)(?!operator(?:[\\/]|\b)|example(?:[\\/]|\b))[A-Za-z0-9_.-]+'),
    'phone': re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)'),
    'identity-number': re.compile(r'(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)'),
}
SECRET_ASSIGNMENT = re.compile(
    r'''(?i)(?:["']?(?:[A-Z_]*(?:API_KEY|PASSWORD|ACCESS_TOKEN|AGENT_TOKEN)|key_base64|iv_base64)["']?)\s*[:=]\s*["']([^"'\r\n]{12,})["']''')


def linked(path):
    # lstat also detects Windows junctions on Python versions without is_junction.
    attributes = getattr(path.lstat(), 'st_file_attributes', 0)
    return path.is_symlink() or bool(attributes & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))


def source_files(root):
    """Use exactly the same traversal for scan and packaging; refuse symlinks."""
    def visit(directory):
        for path in sorted(directory.iterdir()):
            if linked(path):
                yield path
            elif path.is_dir():
                if path.name not in SKIP_DIRS:
                    yield from visit(path)
            elif path.suffix not in {'.pyc', '.pyo'}:
                yield path
    yield from visit(root)


def scan(root, deny_values=()):
    findings = []
    files = list(source_files(root))
    for path in files:
        rel = path.relative_to(root).as_posix()
        def add(rule, line=0): findings.append({'file': rel, 'line': line, 'rule': rule})
        if linked(path):
            add('linked-path'); continue
        if any(part in DENIED_DIRS for part in path.relative_to(root).parts):
            add('runtime-or-evidence'); continue
        if (path.name == '.env' or (path.name.startswith('.env.') and path.name != '.env.example')
                or path.name == 'config.local.json' or '.private.' in path.name
                or ('agent' in path.parts and path.name == 'config.json')):
            add('private-config'); continue
        if 'honeypots' in path.parts and (
                path.name in {'secret_config.go', 'host_logs.go', 'probe.go', 'desktop_windows.go',
                              'proc_phone_windows.go', 'qq_uin.go', 'wx_uin.go', 'config.json'}
                or any(part in {'screenshot', 'obf', 'mockserver', 'encstr'} for part in path.parts)
                or path.name.startswith(('uds-diag-', 'uds-channels-'))):
            add('excluded-honeypot-artifact'); continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in TEXT_NAMES:
            add('unapproved-file-type'); continue
        try:
            content = path.read_text(encoding='utf-8-sig')
        except (UnicodeError, OSError):
            add('not-readable-utf8'); continue
        if '\x00' in content:
            add('binary-content'); continue
        # Exact private values are provided locally; do not put the deny list here.
        for value in deny_values:
            if value and (value.casefold() in content.casefold() or value.casefold() in rel.casefold()):
                add('private-reference'); break
        fixture = ('tests/' in rel or path.name.endswith('_test.go')
                   or (rel.startswith('scripts/test_') and path.suffix == '.py'))
        for number, line in enumerate(content.splitlines(), 1):
            for rule, regex in PATTERNS.items():
                for match in regex.finditer(line):
                    if fixture and rule == 'phone' and match.group() == ('13800' + '138000'):
                        continue  # Explicit, synthetic fixture used to test redaction.
                    # Do not classify digits inside cryptographic digests as IDs.
                    if rule in {'phone', 'identity-number'} and (
                        (match.start() and line[match.start()-1].isalnum()) or
                        (match.end() < len(line) and line[match.end()].isalnum())):
                        continue
                    add(rule, number)
            for match in SECRET_ASSIGNMENT.finditer(line):
                value = match.group(1)
                if fixture and re.search(r'fixture|test|secret|private|dummy', value, re.I):
                    continue
                if re.fullmatch(r'(?:REDACTED_[A-Z_]+|replace_with_[a-z_]+)', value):
                    continue
                add('credential-literal', number)
    return files, findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--deny-values', type=Path, help='Private JSON array OUTSIDE this repository')
    parser.add_argument('--json', action='store_true', help='Machine-readable findings without values')
    args = parser.parse_args()
    values = json.loads(args.deny_values.read_text(encoding='utf-8')) if args.deny_values else []
    if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
        parser.error('--deny-values must contain a JSON array of strings')
    files, findings = scan(args.root.resolve(), values)
    result = {'files_checked': len(files), 'passed': not findings, 'findings': findings}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == '__main__':
    raise SystemExit(main())
