"""Fetch pinned upstream production sources for the functional experiment."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

REVISIONS = {'baseline': '34f020fa9daba975747b29885314c2545b7aa040',
             'reference': '0ed4268a4401abcb4472096340477cf4af7d1a2b'}


def fetch(output):
    output.mkdir(parents=True, exist_ok=True)
    receipts = {}
    for name, revision in REVISIONS.items():
        url = f'https://codeload.github.com/google/brotli/tar.gz/{revision}'
        archive = output / (revision + '.tar.gz')
        if not archive.exists():
            with urllib.request.urlopen(url, timeout=90) as response:
                archive.write_bytes(response.read())
        data = archive.read_bytes()
        destination = output / name
        files = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as bundle:
            for member in bundle.getmembers():
                relative = Path(*Path(member.name).parts[1:])
                if (not relative.parts or relative.parts[0] != 'c' or not member.isfile()):
                    continue
                if relative.is_absolute() or '..' in relative.parts:
                    raise ValueError('invalid archive path')
                contents = bundle.extractfile(member).read()
                path = destination / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
                files[relative.as_posix()] = hashlib.sha256(contents).hexdigest()
        receipts[name] = {'revision': revision, 'url': url,
                          'archive_sha256': hashlib.sha256(data).hexdigest(), 'files': files}
    (output / 'source-receipt.json').write_text(json.dumps(receipts, indent=2) + '\n')
    return receipts


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({k: v['revision'] for k, v in fetch(args.output).items()}))
