#!/usr/bin/env python3
import os
import sys

CHUNKS_DIR = 'chunks'

# Create chunks directory if it doesn't exist
os.makedirs(CHUNKS_DIR, exist_ok=True)

if len(sys.argv) < 3:
    print("Usage: python split_rules.py <input_file> <max_rules_per_chunk>")
    print("Example: python split_rules.py good.rules 2500")
    sys.exit(1)

input_file = sys.argv[1]
MAX_RULES_PER_CHUNK = int(sys.argv[2])
if not os.path.exists(input_file):
    print(f"Error: Input file '{input_file}' not found.")
    sys.exit(1)

with open(input_file, 'r') as f:
    lines = f.readlines()

chunk_num = 1
current_chunk = []
current_rule_count = 0

def write_chunk(chunk_num, chunk_lines, rule_count):
    filename = os.path.join(CHUNKS_DIR, f'chunk{chunk_num}.rules')
    with open(filename, 'w') as f:
        f.writelines(chunk_lines)
    size = os.path.getsize(filename)
    print(f"Created {filename} with {rule_count} rules, {len(chunk_lines)} lines, {size} bytes")
    return size

i = 0
while i < len(lines):
    line = lines[i]
    
    # Collect complete rule (handle multi-line rules ending with \)
    rule_lines = [line]
    while line.rstrip().endswith('\\') and i + 1 < len(lines):
        i += 1
        line = lines[i]
        rule_lines.append(line)
    
    # Check if adding this rule would exceed the limit
    if current_rule_count + 1 > MAX_RULES_PER_CHUNK and current_chunk:
        # Write current chunk and start new one
        write_chunk(chunk_num, current_chunk, current_rule_count)
        chunk_num += 1
        current_chunk = []
        current_rule_count = 0
    
    # Add rule to current chunk
    current_chunk.extend(rule_lines)
    current_rule_count += 1
    i += 1

# Write final chunk
if current_chunk:
    write_chunk(chunk_num, current_chunk, current_rule_count)

print(f"\nTotal: {chunk_num} chunk files created")
