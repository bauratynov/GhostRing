#!/usr/bin/env python3
"""Batch-update license headers across GhostRing source tree."""
import os
import re

PROJECT = 'D:/apps/GhostRing'

# (path prefix, SPDX tag)
RULES = [
    ('loader/linux/',   'SPDX-License-Identifier: GPL-2.0-only'),
    ('loader/windows/', 'SPDX-License-Identifier: Apache-2.0'),
    ('loader/uefi/',    'SPDX-License-Identifier: Apache-2.0'),
    ('agent/',          'SPDX-License-Identifier: Apache-2.0'),
    ('tests/',          'SPDX-License-Identifier: Apache-2.0'),
    ('src/',            'SPDX-License-Identifier: Apache-2.0'),
]

OLD_HEADER_RE = re.compile(
    r'/\*\s*GhostRing Hypervisor.*?MIT License\s*\*/\s*',
    re.DOTALL,
)

def normalize(p):
    return p.replace('\\', '/')

changed = 0
for root, _, files in os.walk(PROJECT):
    for f in files:
        if not f.endswith(('.c', '.h', '.S', '.asm', '.inf')):
            continue
        path = os.path.join(root, f)
        rel = normalize(os.path.relpath(path, PROJECT))
        if rel.startswith('reference/') or rel.startswith('tools/'):
            continue

        license_tag = None
        for prefix, tag in RULES:
            if rel.startswith(prefix):
                license_tag = tag
                break
        if not license_tag:
            continue

        try:
            with open(path, 'r', encoding='utf-8') as fh:
                content = fh.read()
        except Exception as e:
            print(f'skip {rel}: {e}')
            continue

        # Already has correct SPDX? skip
        header_region = content[:400]
        if license_tag in header_region:
            continue

        new_header = (
            '/* GhostRing Hypervisor — Author: Baurzhan Atynov '
            '<bauratynov@gmail.com> */\n'
            f'/* {license_tag} */\n'
        )

        if OLD_HEADER_RE.match(content):
            new_content = OLD_HEADER_RE.sub(new_header, content, count=1)
        elif 'SPDX-License-Identifier:' in header_region:
            # Different SPDX — replace
            new_content = re.sub(
                r'/\*\s*SPDX-License-Identifier:[^\n]*\*/',
                f'/* {license_tag} */',
                content,
                count=1,
            )
        else:
            # No header — prepend
            new_content = new_header + content

        if new_content != content:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(new_content)
            changed += 1
            print(f'  {rel}  ->  {license_tag.split(": ")[-1]}')

print(f'\nTotal files updated: {changed}')
