#!/usr/bin/env python3
"""
Script to validate Suricata rules using Suricata CLI and separate them into good.rules and bad.rules files.
Handles multi-line rules by joining lines that end with backslash.
Uses iterative Suricata validation to ensure good.rules is valid.
"""

import subprocess
import re
import os
import argparse

SURICATA_CONFIG = "/opt/homebrew/etc/suricata/suricata.yaml"
GOOD_FILE = "good.rules"
BAD_FILE = "bad.rules"

def join_multiline_rules(lines):
    """Join multi-line rules (lines ending with backslash)"""
    rules = []
    current_rule = ""
    
    for line in lines:
        line = line.rstrip('\n\r')
        
        if line.endswith('\\'):
            current_rule += line[:-1] + " "  # Remove backslash and add space
        else:
            current_rule += line
            rules.append(current_rule)
            current_rule = ""
    
    # Don't forget the last rule if file doesn't end with newline
    if current_rule:
        rules.append(current_rule)
    
    return rules

def get_failed_rule_indices(rules):
    """Run Suricata validation and extract failed rule indices"""
    # Write rules to temp file
    with open("temp_rules.rules", 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules))
    
    result = subprocess.run(
        ['suricata', '-T', '-c', SURICATA_CONFIG, '-S', "temp_rules.rules"],
        capture_output=True,
        text=True
    )
    
    # Parse error output to find line numbers
    failed_indices = set()
    
    # Pattern to match line numbers from error messages
    pattern = r'from file temp_rules\.rules at line (\d+)'
    matches = re.findall(pattern, result.stderr)
    
    for match in matches:
        failed_indices.add(int(match) - 1)  # Convert to 0-indexed
    
    os.remove("temp_rules.rules")
    
    return failed_indices, result.returncode == 0

def main():
    parser = argparse.ArgumentParser(description="Validate Suricata rules and separate into good/bad files")
    parser.add_argument("file", help="Path to input rules file")
    args = parser.parse_args()
    
    input_file = args.file
    
    if not os.path.exists(input_file):
        print(f"Error: File {input_file} not found.")
        return
    
    print(f"Reading rules from {input_file}...")
    with open(input_file, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    print(f"Total lines: {len(lines)}")
    
    # Join multi-line rules
    print("Joining multi-line rules...")
    rules = join_multiline_rules(lines)
    print(f"Total rules after joining: {len(rules)}")
    
    # Iteratively remove bad rules until validation passes
    iteration = 1
    max_iterations = 50
    bad_rules = []
    
    while iteration <= max_iterations:
        print(f"\nIteration {iteration}: Validating {len(rules)} rules...")
        failed_indices, is_valid = get_failed_rule_indices(rules)
        
        if is_valid:
            print("Validation passed!")
            break
        
        if not failed_indices:
            print("No failed line numbers found, but validation failed. Check Suricata config.")
            break
        
        print(f"Found {len(failed_indices)} failed rules")
        
        # Collect bad rules and remove them from good rules
        new_rules = []
        for i, rule in enumerate(rules):
            if i in failed_indices:
                bad_rules.append(rule)
            else:
                new_rules.append(rule)
        
        rules = new_rules
        iteration += 1
    
    # Final separation
    good_rules = rules
    
    print(f"\nWriting {len(good_rules)} valid rules to {GOOD_FILE}...")
    with open(GOOD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(good_rules))
    
    print(f"Writing {len(bad_rules)} invalid rules to {BAD_FILE}...")
    with open(BAD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(bad_rules))
    
    # Final verification
    print("\nFinal verification...")
    result = subprocess.run(
        ['suricata', '-T', '-c', SURICATA_CONFIG, '-S', GOOD_FILE],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print("✓ good.rules passes Suricata validation!")
    else:
        print("✗ good.rules still has issues:")
        print(result.stderr[-1000:] if len(result.stderr) > 1000 else result.stderr)
    
    print(f"\nSummary:")
    print(f"  Original lines: {len(lines)}")
    print(f"  Valid rules: {len(good_rules)}")
    print(f"  Invalid rules: {len(bad_rules)}")

if __name__ == "__main__":
    main()
