import re
import hashlib
import argparse
from typing import List, Tuple, Set

# Options that don't affect rule syntax validity or AWS compatibility.
# We strip these out to find the true structural duplicates.
IGNORED_OPTIONS = {"sid", "rev", "metadata", "reference", "classtype", "msg", "priority"}

def parse_suricata_options(options_str: str) -> List[str]:
    """
    A robust state-machine parser to handle Suricata's tricky option formatting.
    Safely ignores semicolons inside quotes and handles escaped characters.
    """
    options = []
    current_opt = []
    in_quotes = False
    escaped = False
    
    for char in options_str:
        if escaped:
            current_opt.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
            current_opt.append(char)
        elif char == '"':
            in_quotes = not in_quotes
            current_opt.append(char)
        elif char == ';' and not in_quotes:
            opt = "".join(current_opt).strip()
            if opt:
                options.append(opt)
            current_opt = []
        else:
            current_opt.append(char)
            
    # Catch any trailing option not closed by a semicolon
    last_opt = "".join(current_opt).strip()
    if last_opt:
        options.append(last_opt)
        
    return options

def generate_fuzzy_fingerprint(rule: str) -> Tuple[str, str]:
    """
    Normalizes a rule and returns its original form alongside its canonical hash.
    Returns (original_rule, fingerprint_hash).
    """
    rule = rule.strip()
    if not rule or rule.startswith('#'):
        return rule, ""

    # 1. Separate Header from Options
    # Matches: action proto src_ip src_port direction dst_ip dst_port (options)
    match = re.match(r'^([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\((.*)\)$', rule)
    
    if not match:
        # If it doesn't parse cleanly, hash the raw string as a fallback
        return rule, hashlib.sha256(rule.encode()).hexdigest()

    options_raw = match.group(8)

    # 2. Parse Options Safely
    parsed_opts = parse_suricata_options(options_raw)

    # 3. Filter and Normalize Options
    normalized_opts = []
    for opt in parsed_opts:
        # Extract the key (e.g., 'content' from 'content:"foo"')
        key = opt.split(':', 1)[0].strip()
        
        if key not in IGNORED_OPTIONS:
            # We keep the exact option string to ensure semantic/AWS checks remain intact, 
            # but we've removed the noise keys.
            normalized_opts.append(opt)

    # 4. Sort Alphabetically (Counters the option-order mutation)
    normalized_opts.sort()

    # 5. Build Canonical String
    # We deliberately IGNORE the header fields (Action, IPs, Ports, Direction, Protocol) 
    # because they were mutated for dataset expansion.
    canonical_string = "; ".join(normalized_opts)
    
    fingerprint = hashlib.sha256(canonical_string.encode()).hexdigest()
    return rule, fingerprint

def deduplicate_file(input_path: str, output_path: str):
    """Reads a rules file, applies fuzzy deduplication, and writes the unique rules."""
    seen_fingerprints: Set[str] = set()
    unique_rules: List[str] = []
    total_rules = 0

    print(f"[*] Processing {input_path}...")

    with open(input_path, 'r', encoding='utf-8') as infile:
        for line in infile:
            rule, fingerprint = generate_fuzzy_fingerprint(line)
            
            # Skip empty lines or comments
            if not fingerprint:
                continue
                
            total_rules += 1
            
            if fingerprint not in seen_fingerprints:
                seen_fingerprints.add(fingerprint)
                unique_rules.append(rule)

    # Write unique rules to output
    with open(output_path, 'w', encoding='utf-8') as outfile:
        for rule in unique_rules:
            outfile.write(rule + "\n")

    duplicate_count = total_rules - len(unique_rules)
    print(f"[+] Deduplication complete for {input_path}")
    print(f"    - Total Input Rules: {total_rules}")
    print(f"    - Unique Rules:      {len(unique_rules)}")
    print(f"    - Duplicates Removed:{duplicate_count}")
    print(f"    - Output saved to:   {output_path}\n")

if __name__ == "__main__":
    # Example Usage:
    # python deduplicator.py --input ../training-data/dataset_rule_check/good.rules --output deduplicated_good.rules
    
    parser = argparse.ArgumentParser(description="Fuzzy Deduplicator for Suricata Rules")
    parser.add_argument("-i", "--input", required=True, help="Path to input rules file")
    parser.add_argument("-o", "--output", required=True, help="Path to output rules file")
    
    args = parser.parse_args()
    deduplicate_file(args.input, args.output)