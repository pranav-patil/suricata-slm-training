"""
Script to validate Suricata rules using AWS Create RuleGroup command and parse error response to identify bad rules, then separate them into good.rules and bad.rules files.
"""

import boto3
import sys
import time
import re
import os
import glob
import argparse
from botocore.exceptions import ClientError

def extract_bad_rule(error_msg):
    """
    Extracts rule IDs from multiple possible patterns:
    1. 'rule: <ID>, reason:' - direct rule ID reference
    2. 'Checked in <ID> and' - flowbit error reference
    3. 'sid:<ID>' - sid embedded in rule content (handles both numeric and invalid sids like '1000622r')
    """
    # Try pattern 1 and 2 first (direct rule ID references)
    pattern1 = r'(?:rule: |Checked in )(\d+)'
    matches = re.findall(pattern1, error_msg)
    
    if matches:
        return matches
    
    # Try to extract sid from rule content
    # This handles both valid numeric sids and invalid ones like "1000622r"
    # \d+\w* matches digits followed by optional alphanumeric chars
    sid_pattern = r'sid:(\d+\w*)'
    sid_matches = re.findall(sid_pattern, error_msg)
    
    return sid_matches if sid_matches else None

def remove_rules_by_match(rules_lines, match_func, bad_rules_file, bad_rules, description):
    """
    Remove rules that match the given function and save to bad_rules_file.
    Returns (new_rules_lines, removed_count).
    """
    new_rules_lines = []
    removed_count = 0
    for line in rules_lines:
        if match_func(line):
            # Append bad rule to file
            with open(bad_rules_file, 'a') as f:
                f.write(line.strip() + '\n')
            bad_rules.append(line.strip())
            removed_count += 1
            print(f"[*] Removed rule ({description}): {line[:80]}...")
        else:
            new_rules_lines.append(line)
    return new_rules_lines, removed_count

def save_rules_to_file(file_path, rules_lines):
    """Save rules to file."""
    with open(file_path, 'w') as f:
        f.writelines(rules_lines)

def validate_rules_iteratively(file_path, bad_rules_file='bad_ones.rules', region='us-east-1'):
    """
    Validates Suricata rules iteratively, removing bad rules until all pass.
    Bad rules are appended to bad_rules_file.
    """
    
    # 1. Read the rules file
    try:
        with open(file_path, 'r') as f:
            rules_lines = f.readlines()
            if not rules_lines:
                print("[-] Error: Rules file is empty.")
                return False
    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found.")
        return False

    # Initialize bad rules list for this file
    bad_rules = []
    
    iteration = 0
    while True:
        iteration += 1
        rules_content = ''.join(rules_lines)
        
        if not rules_content.strip():
            print("[-] Error: No rules left to validate.")
            return False
            
        print(f"\n[*] Iteration {iteration}: Validating {len(rules_lines)} rules against AWS Network Firewall in {region}...")

        # 2. Initialize AWS Client
        client = boto3.client('network-firewall', region_name=region)
        
        # Generate a temporary name
        temp_name = f"validator-temp-{int(time.time())}"

        # 3. Attempt to create the Rule Group
        try:
            response = client.create_rule_group(
                RuleGroupName=temp_name,
                Type='STATEFUL',
                RuleGroup={
                    'RulesSource': {
                        'RulesString': rules_content
                    }
                },
                Capacity=6000, 
                Description="Temporary group for validation script"
            )
            
            # If we reached here, the rules are valid!
            print("[+] SUCCESS: All remaining rules are valid and compatible with AWS Network Firewall.")
            
            # 4. Cleanup: Delete the temporary group immediately
            rule_group_arn = response['RuleGroupResponse']['RuleGroupArn']
            print(f"[*] Cleaning up temporary rule group: {rule_group_arn}...")
            client.delete_rule_group(RuleGroupArn=rule_group_arn)
            print("[+] Cleanup complete.")
            
            print(f"\n[+] Summary for '{file_path}': Removed {len(bad_rules)} bad rules.")
            print(f"[+] {len(rules_lines)} valid rules remain in '{file_path}'")
            return True

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']

            if error_code == 'InvalidRequestException':
                print(f"[-] VALIDATION FAILED: {error_msg}...")
                
                # Extract the bad rule IDs from error message
                extracted_rule_ids = extract_bad_rule(error_msg)
                
                if extracted_rule_ids:
                    print(f"[*] Found {len(extracted_rule_ids)} bad rule ID(s), removing them...")
                    
                    total_removed = 0
                    for rule_id in extracted_rule_ids:
                        print(f"[*] Processing bad rule ID: {rule_id}...")
                    
                        # Try matching by sid (rule_id is the sid number)
                        new_rules_lines, removed_count = remove_rules_by_match(
                            rules_lines,
                            lambda line, s=rule_id: f'sid:{s}' in line,
                            bad_rules_file,
                            bad_rules,
                            f"sid:{rule_id}"
                        )
                        
                        if removed_count > 0:
                            rules_lines = new_rules_lines
                            total_removed += removed_count
                        else:
                            # Try exact match as fallback (if rule_id appears anywhere in line)
                            new_rules_lines, removed_count = remove_rules_by_match(
                                rules_lines,
                                lambda line, rid=rule_id: rid in line,
                                bad_rules_file,
                                bad_rules,
                                f"exact match {rule_id}"
                            )
                            if removed_count > 0:
                                rules_lines = new_rules_lines
                                total_removed += removed_count
                    
                    if total_removed > 0:
                        save_rules_to_file(file_path, rules_lines)
                        print(f"[*] Removed {total_removed} rules. Saved {len(rules_lines)} rules to '{file_path}'. Retrying validation...")
                    else:
                        print("[-] Could not find any of the bad rules in rules_lines.")
                        print(f"    Full error: {error_msg}")
                        return False
                
                elif 'cannot be null or empty' in error_msg:
                    # Handle variable cannot be null or empty issue
                    var_match = re.search(r'^(\S+)\s+cannot be null or empty', error_msg)
                    if var_match:
                        var_name = var_match.group(1)
                        var_with_prefix = f'${var_name}'
                        print(f"[*] Detected {var_name} variable issue. Removing rules containing {var_with_prefix}...")
                        
                        new_rules_lines, removed_count = remove_rules_by_match(
                            rules_lines,
                            lambda line, v=var_with_prefix: v in line,
                            bad_rules_file,
                            bad_rules,
                            var_with_prefix
                        )
                        
                        if removed_count > 0:
                            rules_lines = new_rules_lines
                            save_rules_to_file(file_path, rules_lines)
                            print(f"[*] Removed {removed_count} rules. Saved {len(rules_lines)} rules to '{file_path}'. Retrying validation...")
                        else:
                            print(f"[-] Could not find rules with {var_with_prefix}.")
                            print(f"    Full error: {error_msg}")
                            return False
                    else:
                        print("[-] Could not extract variable name from error message.")
                        print(f"    Full error: {error_msg}")
                        return False
                
                elif 'stateful rule is invalid, reason:' in error_msg and ('error parsing signature' in error_msg or 'Duplicate signature' in error_msg):
                    # Handle error parsing signature issue - may have multiple occurrences
                    # Split error_msg into lines and process each line
                    error_lines = error_msg.split('\n')
                    total_removed = 0
                    
                    for error_line in error_lines:
                        # Extract sid and rev from the line
                        sid_match = re.search(r'sid:(\d+)', error_line)
                        
                        if sid_match:
                            sid = sid_match.group(1)
                            print(f"[*] Detected signature parsing error. Removing rule with sid:{sid}...")
                            
                            new_rules_lines, removed_count = remove_rules_by_match(
                                rules_lines,
                                lambda line, s=sid: f'sid:{s}' in line,
                                bad_rules_file,
                                bad_rules,
                                f"parsing error sid:{sid}"
                            )
                            
                            if removed_count > 0:
                                rules_lines = new_rules_lines
                                total_removed += removed_count
                    
                    if total_removed > 0:
                        save_rules_to_file(file_path, rules_lines)
                        print(f"[*] Removed {total_removed} rules total. Saved {len(rules_lines)} rules to '{file_path}'. Retrying validation...")
                    else:
                        print(f"[-] Could not find rules matching the parsing errors.")
                        print(f"    Full error: {error_msg}")
                        return False
                
                else:
                    print("[-] Could not extract bad rule from error message.")
                    print(f"    Full error: {error_msg}")
                    return False
                    
            elif error_code == 'LimitExceededException':
                print("[-] Error: Limit Exceeded. You may have too many rule groups or the Capacity is too low.")
                print(f"    Details: {error_msg}")
                return False
            else:
                print(f"[-] AWS API Error: {error_code} - {error_msg}")
                return False

def validate_all_chunks(chunks_dir='chunks', bad_rules_file='bad_ones.rules', region='us-east-1'):
    """
    Validates all .rules files in the chunks directory.
    """
    # Find all .rules files in chunks directory
    pattern = os.path.join(chunks_dir, '*.rules')
    chunk_files = sorted(glob.glob(pattern), key=lambda x: (len(x), x))  # Sort numerically
    
    if not chunk_files:
        print(f"[-] No .rules files found in '{chunks_dir}' directory.")
        return False
    
    print(f"[*] Found {len(chunk_files)} rule files to validate:")
    for f in chunk_files:
        print(f"    - {f}")
    
    # Create bad_rules_file if it doesn't exist
    if not os.path.exists(bad_rules_file):
        print(f"[*] Creating '{bad_rules_file}'...")
        with open(bad_rules_file, 'w') as f:
            pass
    
    # Process each chunk file
    results = {}
    for chunk_file in chunk_files:
        print(f"\n{'='*60}")
        print(f"[*] Processing: {chunk_file}")
        print('='*60)
        
        success = validate_rules_iteratively(chunk_file, bad_rules_file, region)
        results[chunk_file] = success
    
    # Print final summary
    print(f"\n{'='*60}")
    print("[*] FINAL SUMMARY")
    print('='*60)
    
    successful = [f for f, s in results.items() if s]
    failed = [f for f, s in results.items() if not s]
    
    print(f"[+] Successfully validated: {len(successful)} files")
    for f in successful:
        print(f"    ✓ {f}")
    
    if failed:
        print(f"[-] Failed to validate: {len(failed)} files")
        for f in failed:
            print(f"    ✗ {f}")
    
    # Count bad rules
    if os.path.exists(bad_rules_file):
        with open(bad_rules_file, 'r') as f:
            bad_count = len(f.readlines())
        print(f"\n[*] Total bad rules saved to '{bad_rules_file}': {bad_count}")
    
    return len(failed) == 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Validate Suricata rules against AWS Network Firewall.')
    parser.add_argument('chunks_dir', help='Directory containing chunk*.rules files to validate')
    parser.add_argument('-b', '--bad-rules', default='bad.rules', help='Output file for bad rules (default: bad.rules)')
    parser.add_argument('-r', '--region', default='us-east-1', help='AWS region (default: us-east-1)')
    
    args = parser.parse_args()

    # Run Validation on all chunks
    validate_all_chunks(args.chunks_dir, args.bad_rules, args.region)