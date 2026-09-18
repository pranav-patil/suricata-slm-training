import re
import sys
import argparse

def extract_rules_by_sid(filepath):
    """Extract all rules from a Suricata rules file, indexed by SID."""
    rules = {}
    sid_pattern = re.compile(r'\bsid\s*:\s*(\d+)\s*;')
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                match = sid_pattern.search(line)
                if match:
                    sid = match.group(1)
                    rules[sid] = line
    return rules

def remove_duplicates_from_file(filepath, sids_to_remove, rules_to_match):
    """Remove rules with specified SIDs from a file, only if the entire rule matches."""
    sid_pattern = re.compile(r'\bsid\s*:\s*(\d+)\s*;')
    lines_to_keep = []
    removed_count = 0
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            original_line = line
            stripped_line = line.strip()
            
            if stripped_line and not stripped_line.startswith('#'):
                match = sid_pattern.search(stripped_line)
                if match:
                    sid = match.group(1)
                    # Only remove if SID is in removal list AND rule content matches exactly
                    if sid in sids_to_remove and stripped_line == rules_to_match.get(sid):
                        removed_count += 1
                        continue
            
            lines_to_keep.append(original_line)
    
    # Write back to file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(lines_to_keep)
    
    return removed_count

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Compare Suricata rules files and find common/duplicate rules.')
    parser.add_argument('file1', help='First rules file')
    parser.add_argument('file2', help='Second rules file')
    parser.add_argument('-remove', action='store_true', help='Remove duplicate rules (matching SID and entire rule) from the second file')
    
    args = parser.parse_args()
    
    file1 = args.file1
    file2 = args.file2

    # Extract rules (SID -> full rule) from both files
    rules1 = extract_rules_by_sid(file1)
    rules2 = extract_rules_by_sid(file2)

    # Find common SIDs
    common_sids = set(rules1.keys()) & set(rules2.keys())

    # Find SIDs where the entire rule matches perfectly
    perfectly_matching_sids = []
    for sid in common_sids:
        if rules1[sid] == rules2[sid]:
            perfectly_matching_sids.append(sid)

    print(f"File 1 ({file1.split('/')[-1]}): {len(rules1)} rules")
    print(f"File 2 ({file2.split('/')[-1]}): {len(rules2)} rules")
    print(f"\nCommon SIDs: {len(common_sids)}")
    print(f"Perfectly matching rules: {len(perfectly_matching_sids)}")

    # Show perfectly matching SIDs
    if perfectly_matching_sids:
        sorted_perfect = sorted(perfectly_matching_sids, key=int)
        print(f"\nPerfectly matching SIDs: {sorted_perfect}")
    
    # Show SIDs that have same SID but different rule content
    different_rules = [sid for sid in common_sids if sid not in perfectly_matching_sids]
    if different_rules:
        sorted_diff = sorted(different_rules, key=int)
        print(f"\nSIDs with different rule content: {sorted_diff}")
    
    # Remove duplicates if -remove flag is set
    if args.remove:
        if perfectly_matching_sids:
            removed = remove_duplicates_from_file(file2, set(perfectly_matching_sids), rules1)
            print(f"\n✓ Removed {removed} duplicate rules from {file2.split('/')[-1]}")
        else:
            print(f"\nNo perfectly matching rules to remove.")
