"""Find exact ciphertext/plaintext pairs in existing gateway logs. Never prints bodies or keys."""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.request import urlopen

HEADER = re.compile(r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+ \[[^\]]+\] \[([^\]]*)\] \[[^\]]*\][：:]?(.*)')


def digest(text):
    return hashlib.sha256(text.encode('utf8')).hexdigest()


def containers(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, (dict, list)):
                return parsed
        except ValueError:
            pass
    return value


def ciphertexts(value):
    value = containers(value)
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ('body', 'body_content') and isinstance(child, str) and not isinstance(containers(child), (dict, list)):
                yield digest(child)
            yield from ciphertexts(child)
    elif isinstance(value, list):
        for child in value:
            yield from ciphertexts(child)


def same_head(data):
    head = data.get('head')
    if not isinstance(head, dict) or not all(head.get(k) for k in ('app_id', 'method', 'timestamp', 'sign')):
        return None
    return digest(json.dumps({k: head.get(k) for k in ('app_id','method','timestamp','sign','enterprise_id')}, sort_keys=True, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs', type=Path, required=True, help='Directory of authorized backend logs')
    parser.add_argument('--output', type=Path, required=True, help='Private JSON index, outside the public repository')
    parser.add_argument('--encoding', default='utf-8')
    args = parser.parse_args()
    if not args.logs.is_dir():
        parser.error('--logs must be an existing directory')
    public_root = Path(__file__).resolve().parents[3]
    if public_root == args.output.resolve() or public_root in args.output.resolve().parents:
        parser.error('--output must be outside the public source repository')
    if args.output.exists():
        parser.error('--output already exists; choose a new path')
    targets, before = set(), 0
    while True:
        page = json.load(urlopen(f'http://127.0.0.1:8790/api/entries?before={before}', timeout=15))
        for row in page['entries']:
            entry = json.load(urlopen(f"http://127.0.0.1:8790/api/entry?id={row['id']}", timeout=15))['entry']
            try:
                targets.update(ciphertexts(json.loads(entry.get('body', ''))))
            except ValueError:
                pass
        if not page['has_more']:
            break
        before = page['before']
    pending, found, conflicts = {}, {}, set()
    stats = Counter(target_ciphertexts=len(targets))
    for directory in (args.logs,):
        for path in directory.rglob('*.log'):
            with path.open('rb') as stream:
                for lineno, raw in enumerate(stream, 1):
                    line = raw.decode(args.encoding, 'replace')
                    if '入参报文' not in line and '解密后报文-入参' not in line:
                        continue
                    match = HEADER.match(line)
                    if not match:
                        continue
                    trace, message = match.groups()
                    pos = message.find('{')
                    if pos < 0:
                        continue
                    try:
                        data = json.loads(message[pos:])
                    except ValueError:
                        continue
                    if '解密后报文-入参' in message[:pos]:
                        label = message[:pos].replace('解密后报文-入参', '').strip('：:- ')
                        previous = pending.pop((trace, label), None)
                        if not previous:
                            continue
                        encrypted, source, original_path, original_line, original_time = previous
                        if original_path != path or not 0 < lineno-original_line <= 3 or line[:19] != original_time[:19] or len(trace.strip()) < 8:
                            stats['rejected_nonadjacent_pairs'] += 1
                            continue
                        plain = containers(data.get('body')) if isinstance(data.get('head'),dict) else data
                        if isinstance(encrypted, str) and isinstance(plain, (dict, list)):
                            hashed = digest(encrypted)
                            if hashed not in targets:
                                continue
                            text = json.dumps(plain, ensure_ascii=False, separators=(',', ':'))
                            item = {'plaintext': text, 'plaintext_sha256': digest(text),
                                    'source': f'{source} -> {path.name}:{lineno}', 'method': 'exact ciphertext, same backend trace and operation label'}
                            if hashed in found and found[hashed]['plaintext_sha256'] != item['plaintext_sha256']:
                                conflicts.add(hashed)
                            found[hashed] = item
                            stats['matching_pair_observations'] += 1
                        stats['paired_requests'] += 1
                    else:
                        if not same_head(data):
                            continue
                        label = message[:pos].replace('入参报文', '').strip('：:- ')
                        pending[(trace, label)] = (data.get('body'), f'{path.name}:{lineno}', path, lineno, line[:23])
                        if len(pending)>10000:
                            pending.clear()
            stats['files_scanned'] += 1
    for hashed in conflicts:
        found.pop(hashed, None)
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf8') as stream:
        json.dump(found, stream, ensure_ascii=False)
    stats.update(unique_exact_ciphertext_matches=len(found), conflicting_pairs=len(conflicts))
    print(json.dumps(stats))


if __name__ == '__main__':
    main()
