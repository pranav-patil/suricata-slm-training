import re
import random
import ipaddress
import os

def generate_random_cidr(is_private=True):
    """Generates a random CIDR block."""
    if is_private:
        # Generate a random private network (Class A, B, or C)
        first_octet = random.choice([10, 172, 192])
        if first_octet == 10:
            base_ip = f"10.{random.randint(0, 255)}.0.0"
            prefix = random.randint(8, 24)
        elif first_octet == 172:
            base_ip = f"172.{random.randint(16, 31)}.0.0"
            prefix = random.randint(12, 24)
        else: # 192
            base_ip = f"192.168.{random.randint(0, 255)}.0"
            prefix = random.randint(16, 24)
    else:
        # Generate a random public IP block
        while True:
            first_octet = random.randint(1, 223)
            if first_octet not in [10, 127, 169, 172, 192]: # Avoid special/private ranges
                break
        base_ip = f"{first_octet}.{random.randint(0, 255)}.0.0"
        prefix = random.randint(8, 24)
        
    return ipaddress.IPv4Network(f"{base_ip}/{prefix}", strict=False)

def generate_non_overlapping_cidr(existing_network):
    """Generates a CIDR block that does not overlap with the existing network."""
    while True:
        new_net = generate_random_cidr(is_private=False)
        if not existing_network.overlaps(new_net):
            return new_net

def generate_random_ip():
    """Generates a random valid IP address."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_random_http_port():
    """Generates a random HTTP port value."""
    return str(random.choice([80, 443, 8080, 8000, 8443, 8888, 3000, 5000]))

def process_rule(rule):
    """Process a single Suricata rule and replace variables with valid values."""
    if not rule.strip() or rule.strip().startswith('#'):
        return rule  # Skip empty lines and comments
    
    has_home_net = "$HOME_NET" in rule
    has_external_net = "$EXTERNAL_NET" in rule
    has_http_servers = "$HTTP_SERVERS" in rule
    has_http_ports = "$HTTP_PORTS" in rule
    
    processed_rule = rule
    
    # Generate values for this specific rule
    home_net = None
    external_net = None
    
    if has_home_net:
        home_net = generate_random_cidr(is_private=True)
        processed_rule = processed_rule.replace("$HOME_NET", str(home_net))
    
    if has_external_net:
        if has_home_net and home_net:
            # Both present in same rule - generate non-overlapping external net
            external_net = generate_non_overlapping_cidr(home_net)
        else:
            # Only $EXTERNAL_NET present - generate any random CIDR
            external_net = generate_random_cidr(is_private=False)
        processed_rule = processed_rule.replace("$EXTERNAL_NET", str(external_net))
    
    if has_http_servers:
        http_server_ip = generate_random_ip()
        processed_rule = processed_rule.replace("$HTTP_SERVERS", http_server_ip)
    
    if has_http_ports:
        http_port = generate_random_http_port()
        processed_rule = processed_rule.replace("$HTTP_PORTS", http_port)
    
    return processed_rule

def process_suricata_rules(filename):
    """Process all rules in the given file."""
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found.")
        return

    with open(filename, 'r') as f:
        rules = f.readlines()

    processed_rules = []
    for i, rule in enumerate(rules, 1):
        processed_rule = process_rule(rule)
        processed_rules.append(processed_rule)
        
        # Log what was replaced in this rule
        if "$HOME_NET" in rule or "$EXTERNAL_NET" in rule or "$HTTP_SERVERS" in rule or "$HTTP_PORTS" in rule:
            print(f"[*] Rule {i}: Processed variables")

    new_content = ''.join(processed_rules)

    # Output results
    output_filename = "output.rules"
    with open(output_filename, 'w') as f:
        f.write(new_content)
    
    print(f"\n[+] Processing complete. {len(rules)} rules written to '{output_filename}'")
    print("-" * 40)
    print(new_content)

if __name__ == "__main__":
    process_suricata_rules("processed_chunks/chunk1.rules")