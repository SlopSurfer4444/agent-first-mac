"""Read-only release structure, provenance, text syntax and guide-link checks.

Not a privacy guarantee, installation test or replacement for independent review.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import stat


def check(root):
    root = root.resolve()
    files = []
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if relative.parts[0] == '.git':
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError('symlink: ' + str(relative))
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode) or mode & 0o111:
            raise ValueError('non-text-payload-mode: ' + str(relative))
        raw = path.read_bytes()
        text = raw.decode('utf-8')
        if '\0' in text:
            raise ValueError('binary: ' + str(relative))
        if path.suffix == '.py' or text.startswith('#!/usr/bin/python3'):
            ast.parse(text, filename=str(relative))
        if path.suffix == '.json':
            json.loads(text)
        if path.suffix == '.md' and relative.parts[0] != 'reference':
            for target in re.findall(r'\]\(([^)]+)\)', text):
                if '://' in target or target.startswith('#'):
                    continue
                destination = (path.parent / target.split('#', 1)[0]).resolve()
                if root not in destination.parents or not destination.exists():
                    raise ValueError('broken guide link: ' + str(relative))
        files.append(path)
    provenance = json.loads((root / 'export-provenance.json').read_text())
    expected = provenance['outputHashes']
    actual = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in files if p.relative_to(root).parts[0] == 'reference'}
    if actual != expected:
        raise ValueError('exported file set or digest mismatch')
    allowlist = root / 'tools/export-files.json'
    if hashlib.sha256(allowlist.read_bytes()).hexdigest() != provenance['allowlistDigest']:
        raise ValueError('allowlist digest mismatch')
    skill = (root / 'examples/skills/manage-workstation/SKILL.md').read_text()
    front = skill.split('---', 2)
    if len(front) != 3 or not front[1].startswith('\nname: manage-workstation\n') or '\ndescription: ' not in front[1]:
        raise ValueError('invalid public skill frontmatter')
    return {'checkedTextFiles': len(files), 'exportedFiles': len(actual),
            'sourceCommit': provenance['sourceCommit'], 'guideLinks': 'PASS',
            'syntaxAndProvenance': 'PASS', 'installationVerified': False,
            'independentPrivacyReviewRequired': True}


if __name__ == '__main__':
    print(json.dumps(check(Path(__file__).resolve().parents[1]), sort_keys=True))
