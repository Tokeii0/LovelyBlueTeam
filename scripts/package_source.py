"""Build a deterministic source-only ZIP after the release gate passes."""
import argparse
import hashlib
from pathlib import Path
import zipfile

from release_scan import ROOT, scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error('Output must be outside the source repository')
    if output.exists() or output.with_suffix(output.suffix + '.sha256').exists():
        parser.error('Output already exists; choose a new filename')
    files, findings = scan(ROOT)
    if findings:
        print('Release gate failed. Run scripts/release_scan.py for file/line details.')
        return 1
    # Capture the checked file set once. Package from a stopped, clean checkout;
    # generated state cannot enter through a second directory walk.
    entries = [(p.relative_to(ROOT).as_posix(), p.read_bytes()) for p in files]
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = '\n'.join(hashlib.sha256(data).hexdigest() + '  ' + name for name, data in entries) + '\n'
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in entries + [('MANIFEST.sha256', manifest.encode('utf-8'))]:
            item = zipfile.ZipInfo('blue-team-hw/' + name, date_time=(1980, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            archive.writestr(item, data)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(digest + '  ' + output.name + '\n', encoding='ascii')
    print(f'Packaged {len(entries)} source files: {output}')
    print('SHA-256:', digest)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
