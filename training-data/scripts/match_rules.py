#!/usr/bin/env python3
"""Match bad.rules entries to their originals in 4_good_performing.rules."""

import re
import sys

MSG_PAT     = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
PCRE_PAT    = re.compile(r'\bpcre\s*:\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
CONTENT_PAT = re.compile(r'\bcontent\s*:\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)


def fingerprints(rule: str) -> list[tuple[str, str]]:
    fps = []
    if m := MSG_PAT.search(rule):
        fps.append(('msg', m.group(1).lower()))
    for m in PCRE_PAT.finditer(rule):
        fps.append(('pcre', m.group(1)))
    for m in CONTENT_PAT.finditer(rule):
        fps.append(('content', m.group(1)))
    return fps


def find_match(bad: str, good_rules: list[str]) -> str | None:
    fps = fingerprints(bad)

    # 1. Exact msg match
    for ftype, fval in fps:
        if ftype == 'msg':
            for good in good_rules:
                if (m := MSG_PAT.search(good)) and m.group(1).lower() == fval:
                    return good
            break  # only one msg per rule; no point trying others

    # 2. PCRE match (use patterns longer than 15 chars to avoid false positives)
    for ftype, fval in fps:
        if ftype == 'pcre' and len(fval) > 15:
            for good in good_rules:
                if fval in good:
                    return good

    # 3. Long content match
    for ftype, fval in fps:
        if ftype == 'content' and len(fval) > 15:
            for good in good_rules:
                if f'content:"{fval}"' in good or f'content: "{fval}"' in good:
                    return good

    return None


def main():
    bad_path  = '../bad.rules'
    good_path = '../public_rules/4_good_performing.rules'
    out_path  = '../bad_matched.rules'

    with open(bad_path) as f:
        bad_rules = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    with open(good_path) as f:
        good_rules = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    matched_good = []
    unmatched = []

    for bad in bad_rules:
        found = find_match(bad, good_rules)
        if found:
            matched_good.append(found)
        else:
            unmatched.append(bad)

    with open(out_path, 'w') as f:
        for rule in matched_good:
            f.write(rule + '\n')

    print(f"Matched  : {len(matched_good)}/{len(bad_rules)}")
    print(f"Unmatched: {len(unmatched)}")
    if unmatched:
        print("\nUnmatched rules (bad.rules excerpt):")
        for u in unmatched:
            print(f"  {u[:100]}...")
    print(f"\nOutput written to: {out_path}")


if __name__ == '__main__':
    main()
