"""
Transform errors.log:
1. Strip 'E: detect: error parsing signature "' prefix from signature lines
2. Strip '" from file bad.rules at line N' suffix from signature lines
3. Group lines into blocks: each block = E: detect-* error + its signature(s)
4. Sort blocks alphabetically by the E: detect-* error string
5. Write sorted output back
"""

import argparse
import re

parser = argparse.ArgumentParser(description='Transform Suricata errors.log')
parser.add_argument('input', help='Input log file path')
parser.add_argument('output', nargs='?', default=None, help='Output file path (default: overwrite input file)')
args = parser.parse_args()

INPUT = args.input
OUTPUT = args.output if args.output else args.input

SIG_PREFIX = 'E: detect: error parsing signature "'
SIG_SUFFIX_RE = re.compile(r'" from file bad\.rules at line \d+\s*$')
SURICATA_FINAL = 'E: suricata: Loading signatures failed.'

lines = open(INPUT).readlines()

# Strip trailing newlines for processing
lines = [l.rstrip('\n').rstrip('\r') for l in lines]

# Separate the final "Loading signatures failed" line if present
final_lines = []
while lines and lines[-1].strip() == SURICATA_FINAL:
    final_lines.insert(0, lines.pop())

# Build blocks
# A block starts with an E: detect-* line (not a signature line)
# It accumulates subsequent signature lines
blocks = []  # list of (error_desc_line, [rule_lines])

current_error = None
current_rules = []

for line in lines:
    is_sig = line.startswith(SIG_PREFIX)
    is_error = line.startswith('E: detect') and not is_sig

    if is_error:
        # Save previous block if any
        if current_error is not None:
            blocks.append((current_error, current_rules))
        current_error = line
        current_rules = []
    elif is_sig:
        # Strip prefix and suffix
        rule = line[len(SIG_PREFIX):]  # remove prefix
        rule = SIG_SUFFIX_RE.sub('', rule)  # remove suffix
        current_rules.append(rule)
    else:
        # Unexpected line type — preserve as-is in a block with empty error
        if current_error is not None:
            blocks.append((current_error, current_rules))
        current_error = None
        current_rules = [line]

# Don't forget the last block
if current_error is not None:
    blocks.append((current_error, current_rules))
elif current_rules:
    blocks.append(('', current_rules))

# Sort blocks alphabetically by error description string
blocks.sort(key=lambda b: b[0].lower())

# Build output
out_lines = []
for error_desc, rules in blocks:
    if error_desc:
        out_lines.append(error_desc)
    for rule in rules:
        out_lines.append(rule)

out_lines.extend(final_lines)

output = '\n'.join(out_lines) + '\n'

with open(OUTPUT, 'w') as f:
    f.write(output)

print(f"Done. Written {len(out_lines)} lines ({len(blocks)} blocks) to {OUTPUT}")
print(f"Sample first 3 blocks:")
for i, (err, rules) in enumerate(blocks[:3]):
    print(f"  Block {i+1}: {err[:80]}")
    for r in rules[:2]:
        print(f"    Rule: {r[:80]}")
