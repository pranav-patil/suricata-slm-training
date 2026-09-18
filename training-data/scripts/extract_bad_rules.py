#!/usr/bin/env python3
"""
Script to extract failed rules from a chunk output JSON file.
Reads a JSON file and finds matching rules from the corresponding chunk rules file.
"""

import os
import re
import json
import sys


OUTPUT_FILE = 'bad_performance.rules'


def get_failed_sids(data: dict) -> list:
    """Extract FailedRuleSids from the JSON response using the specified path."""
    try:
        # JSONPath: $.actions[0].analyse.get_rule_analysis_result.RuleAnalysisResult.ReportMetadata.FailedRuleSids
        failed_sids = (
            data
            .get('result', {})
            .get('RuleAnalysisResult', {})
            .get('ReportMetadata', {})
            .get('FailedRuleSids', [])
        )
        return failed_sids if failed_sids else []
    except (IndexError, KeyError, TypeError) as e:
        print(f"Warning: Failed to extract FailedRuleSids: {e}")
        return []


def find_and_separate_rules_by_sids(chunk_file: str, sids: list) -> tuple[list, list]:
    """
    Find rules in chunk file that match the given SIDs.
    Returns tuple of (matching_rules, remaining_rules).
    """
    matching_rules = []
    remaining_rules = []
    sid_set = set(str(sid) for sid in sids)
    
    if not os.path.exists(chunk_file):
        print(f"Warning: Chunk file not found: {chunk_file}")
        return [], []
    
    with open(chunk_file, 'r') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Collect complete rule (handle multi-line rules ending with \)
        rule_lines = [line]
        while line.rstrip().endswith('\\') and i + 1 < len(lines):
            i += 1
            line = lines[i]
            rule_lines.append(line)
        
        # Check if this rule contains any of the failed SIDs
        full_rule = ''.join(rule_lines)
        # Match sid:NUMBER; pattern in the rule
        sid_match = re.search(r'sid:\s*(\d+)\s*;', full_rule)
        if sid_match and sid_match.group(1) in sid_set:
            matching_rules.extend(rule_lines)
        else:
            remaining_rules.extend(rule_lines)
        
        i += 1
    
    return matching_rules, remaining_rules


def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_bad_rules.py <chunk_rules_file> <chunk_output_json>")
        print("Example: python extract_bad_rules.py chunks/chunk1.rules chunk_outputs/chunk1_output.json")
        sys.exit(1)

    chunk_file = sys.argv[1]
    json_file = sys.argv[2]

    if not os.path.exists(chunk_file):
        print(f"Error: Chunk rules file '{chunk_file}' not found.")
        sys.exit(1)

    if not os.path.exists(json_file):
        print(f"Error: JSON output file '{json_file}' not found.")
        sys.exit(1)

    print(f"{'='*60}")
    print(f"Processing: {json_file}")
    print(f"Chunk file: {chunk_file}")
    print('='*60)

    # Read JSON file
    try:
        with open(json_file, 'r') as f:
            json_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON from {json_file}: {e}")
        sys.exit(1)

    # Get failed SIDs
    failed_sids = get_failed_sids(json_data)
    print(f"Found {len(failed_sids)} failed SIDs: {failed_sids}")

    bad_rules = []
    remaining_rules = []
    if failed_sids:
        # Find matching rules (bad) and remaining rules (good) from chunk file
        bad_rules, remaining_rules = find_and_separate_rules_by_sids(chunk_file, failed_sids)
        print(f"Extracted {len(bad_rules)} lines of bad rules from {chunk_file}")
        print(f"Remaining {len(remaining_rules)} lines of good rules in {chunk_file}")

    # Append bad rules to output file
    if bad_rules:
        with open(OUTPUT_FILE, 'a') as f:
            f.writelines(bad_rules)
        print(f"Bad rules appended to: {OUTPUT_FILE}")

    # Write remaining (good) rules back to the original chunk file
    if failed_sids:
        with open(chunk_file, 'w') as f:
            f.writelines(remaining_rules)
        print(f"Updated chunk file with remaining rules: {chunk_file}")

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print('='*60)
    print(f"Total failed SIDs: {len(failed_sids)}")
    print(f"Bad rules appended to: {OUTPUT_FILE}")
    print(f"Total bad rule lines: {len(bad_rules)}")
    print(f"Remaining rule lines in chunk: {len(remaining_rules)}")


if __name__ == '__main__':
    main()
