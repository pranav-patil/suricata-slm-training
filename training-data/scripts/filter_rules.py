#!/usr/bin/env python3
"""
Script to remove any classtype pattern from suricata rules present in the input file.
Analyzes flowbits:set and flowbits:isset patterns to identify flowbits that are checked but never set, 
and removes rules that reference these unmatched flowbits.
Also removes rules which has $HTTP_PORTS or $HTTP_SERVERS in them.
Rewrites the input file in place and appends removed rules to bad_output.rules.
"""

import sys
import os
import re

BAD_OUTPUT_FILE = "bad_filtered.rules"

# Regex pattern to match any classtype:*; (e.g., classtype:protocol-command-decode;)
CLASSTYPE_PATTERN = re.compile(r'classtype:[^;]+;')
PRIORITY_PATTERN = re.compile(r'priority:[^;]+;')

# Regex patterns for flowbits
FLOWBITS_SET_PATTERN = re.compile(r'flowbits:set,([^;]+);')
FLOWBITS_ISSET_PATTERN = re.compile(r'flowbits:isset,([^;]+);')
FLOWBITS_UNSET_PATTERN = re.compile(r'flowbits:unset,([^;]+);')

def analyze_flowbits(rules):
    """
    Analyzes rules for flowbits:set and flowbits:isset patterns.
    Returns a list of flowbits that are checked (isset) but never set.
    """
    flowbits_set = set()
    flowbits_isset = set()
    flowbits_unset = set()

    for rule in rules:
        # Find all flowbits:set,*; matches
        set_matches = FLOWBITS_SET_PATTERN.findall(rule)
        for match in set_matches:
            flowbits_set.add(match.strip())

        # Find all flowbits:isset,*; matches
        isset_matches = FLOWBITS_ISSET_PATTERN.findall(rule)
        for match in isset_matches:
            flowbits_isset.add(match.strip())

        # Find all flowbits:unset,*; matches
        unset_matches = FLOWBITS_UNSET_PATTERN.findall(rule)
        for match in unset_matches:
            flowbits_unset.add(match.strip())

    # Find flowbits that are isset but never set
    unmatched_isset = flowbits_isset - flowbits_set
    unmatched_unset = flowbits_unset - flowbits_set

    print(f"[*] Total {len(flowbits_set)} flowbits:set, {len(flowbits_isset)} flowbits:isset, {len(flowbits_unset)} flowbits:unset rules found")
    return unmatched_isset, unmatched_unset

def remove_classtype_rules(input_file):
    """
    Reads rules from input file and strips out any classtype:*; pattern from rules (keeping the rule itself).
    Rewrites the input file with the processed rules, and appends removed rules
    to bad_filtered.rules (creates the file if it doesn't exist).
    """
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        return False

    with open(input_file, 'r') as f:
        rules = f.readlines()

    # Analyze flowbits
    unmatched_isset, unmatched_unset = analyze_flowbits(rules)

    total_rules = len(rules)
    filtered_rules = []
    removed_rules = []
    classtype_stripped_count = 0
    priority_stripped_count = 0

    for rule in rules:
        # Check if rule contains any unmatched flowbits:isset
        should_remove = False
        for fb in unmatched_isset:
            if f'flowbits:isset,{fb};' in rule:
                should_remove = True
                break
        
        for fb in unmatched_unset:
            if f'flowbits:unset,{fb};' in rule:
                should_remove = True
                break
        
        if should_remove:
            removed_rules.append(rule)
            continue
        
        if "$HTTP_PORTS" in rule or "$HTTP_SERVERS" in rule:
            removed_rules.append(rule)
            continue
            
        if CLASSTYPE_PATTERN.search(rule):
            rule = CLASSTYPE_PATTERN.sub('', rule)
            classtype_stripped_count += 1
        if PRIORITY_PATTERN.search(rule):
            rule = PRIORITY_PATTERN.sub('', rule)
            priority_stripped_count += 1
        # Clean up any resulting double spaces
        rule = re.sub(r' +', ' ', rule)
        filtered_rules.append(rule)

    # Rewrite the input file with filtered rules
    with open(input_file, 'w') as f:
        f.writelines(filtered_rules)

    # Append removed rules to bad_filtered.rules (creates if doesn't exist)
    if removed_rules:
        with open(BAD_OUTPUT_FILE, 'a') as f:
            f.writelines(removed_rules)

    print(f"[*] Total rules read: {total_rules}")
    print(f"[*] Rules with classtype:*; stripped: {classtype_stripped_count}")
    print(f"[*] Rules with priority:*; stripped: {priority_stripped_count}")
    print(f"[*] Rules written back to '{input_file}': {len(filtered_rules)}")
    if removed_rules:
        print(f"[+] Removed rules appended to '{BAD_OUTPUT_FILE}'")

    # Print flowbits analysis
    print(f"\n[*] Flowbits Analysis:")
    print(f"[*] Flowbits isset with no matching set ({len(unmatched_isset)}):")
    print(f"[*] Flowbits unset with no matching set ({len(unmatched_unset)}):")
    print(f"[*] Rules with no match for flowbits isset removed: {len(removed_rules)}")
    for fb in sorted(unmatched_isset):
        print(f"    - {fb}")

    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python filter_rules.py <input_file>")
        print("Example: python filter_rules.py input.rules")
        sys.exit(1)

    input_file = sys.argv[1]

    remove_classtype_rules(input_file)
