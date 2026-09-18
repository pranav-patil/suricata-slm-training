#!/usr/bin/env python3
"""
Generate random Suricata rules based on BNF grammar with specific constraints.

Requirements:
- Meta/flow/header/threshold keywords: 0-1 times each (randomly)
- msg, sid, rev: exactly once
- sid: incrementing from --sid (default 1000000)
- rev: random 1-10
- classtype: excluded
- Other keywords: repeatable 0-MAX times, no duplicate values
- rev must be the LAST keyword in rule options
- sid must be placed immediately BEFORE rev
- content-modifier must always immediately follow content-keyword
- pcre-keyword follows content-keyword, or if content is missing, follows content-modifier
- prefilter constraints:
  - fast_pattern can only follow content-keyword or content-modifier
  - prefilter keyword can follow: byte, base64, header, http, http2, tls, dns, mdns keywords
"""

import argparse
import random
import sys


# =============================================================================
# Value Generators
# =============================================================================

def gen_quoted_string():
    """Generate a random quoted string."""
    words = ["test", "example", "data", "pattern", "match", "detect", "alert",
             "warning", "scan", "probe", "attack", "malware", "suspicious"]
    return f'"{random.choice(words)}_{random.randint(1, 999)}"'

def gen_content_value():
    """Generate random content value (quoted string or hex)."""
    if random.choice([True, False]):
        # Hex content
        hex_bytes = [f"{random.randint(0, 255):02x}" for _ in range(random.randint(2, 6))]
        return f'"|{" ".join(hex_bytes)}|"'
    else:
        # String content
        patterns = ["GET", "POST", "HTTP", "User-Agent", "Host", "admin", "password",
                    "login", "index", "test", "data", "cmd", "exec"]
        return f'"{random.choice(patterns)}"'

def gen_number(min_val=1, max_val=65535):
    """Generate a random number."""
    return str(random.randint(min_val, max_val))

def gen_signed_number():
    """Generate a random signed number."""
    val = random.randint(-100, 100)
    if val > 0 and random.choice([True, False]):
        return f"+{val}"
    return str(val)

def gen_pcre():
    """Generate a random PCRE pattern."""
    patterns = ["/test/i", "/admin/", "/pass(word)?/i", "/[0-9]{4}/", "/login|logout/i"]
    return f'"{random.choice(patterns)}"'

def gen_reference_type():
    return random.choice(["cve", "url", "bugtraq"])

def gen_reference_value():
    ref_type = gen_reference_type()
    if ref_type == "cve":
        return f"cve,CVE-{random.randint(2020, 2024)}-{random.randint(1000, 9999)}"
    elif ref_type == "url":
        return f"url,example.com/rule{random.randint(1, 999)}"
    else:
        return f"bugtraq,{random.randint(10000, 99999)}"

def gen_metadata():
    keys = ["created_at", "updated_at", "author", "severity", "category"]
    values = ["high", "medium", "low", "test", "production", "2024"]
    items = []
    for _ in range(random.randint(1, 3)):
        items.append(f"{random.choice(keys)} {random.choice(values)}")
    return ", ".join(items)

def gen_flow_options():
    opts = []
    if random.choice([True, False]):
        opts.append(random.choice(["to_server", "to_client", "from_server", "from_client"]))
    if random.choice([True, False]):
        opts.append(random.choice(["established", "not_established", "stateless"]))
    if random.choice([True, False]):
        opts.append(random.choice(["only_stream", "no_stream"]))
    if not opts:
        opts.append("established")
    return ",".join(opts)

def gen_flowbits():
    actions = ["set", "isset", "isnotset", "unset", "toggle"]
    names = ["login", "auth", "session", "file_transfer", "malware_check"]
    return f"{random.choice(actions)},{random.choice(names)}"

def gen_threshold():
    types = ["threshold", "limit", "both"]
    tracks = ["by_src", "by_dst", "by_rule", "by_both"]
    return f"type {random.choice(types)}, track {random.choice(tracks)}, count {random.randint(1, 10)}, seconds {random.randint(30, 300)}"

def gen_tcp_flags():
    flags = ["S", "SA", "A", "F", "FA", "PA", "R", "RA"]
    return random.choice(flags)

def gen_comparison_op():
    return random.choice(["<", ">", "=", ">=", "<="])

def gen_country_code():
    codes = ["US", "CN", "RU", "DE", "FR", "GB", "JP", "KR", "BR", "IN"]
    return random.choice(codes)


# =============================================================================
# Keyword Generators
# =============================================================================

# Keywords that appear exactly once
def gen_msg_keyword():
    words = [
        "Test", "Example", "Attack", "Probe", "Scan", "Alert", "Warning", "Suspicious", "Malicious", "Detected",
        "Exploit", "Vulnerability", "Threat", "Intrusion", "Breach", "Anomaly", "Unauthorized", "Access", "Attempt",
        "Deny", "Block", "Drop", "Reject", "Allow", "Permit", "Traffic", "Network", "Connection", "Session",
        "Protocol", "Packet", "Payload", "Header", "Request", "Response", "Query", "Reply", "Data", "Transfer",
        "Upload", "Download", "Exfiltration", "Infiltration", "Command", "Control", "Execute", "Execution", "Shell",
        "Backdoor", "Trojan", "Virus", "Worm", "Rootkit", "Spyware", "Adware", "Ransomware", "Keylogger", "Botnet",
        "Phishing", "Spam", "Scam", "Fraud", "Injection", "SQLi", "XSS", "CSRF", "RCE", "LFI", "RFI", "XXE",
        "SSRF", "Overflow", "Buffer", "Heap", "Stack", "Memory", "Corruption", "Leak", "Disclosure", "Information",
        "Reconnaissance", "Enumeration", "Fingerprint", "Discovery", "Mapping", "Scanning", "Sweeping", "Brute",
        "Force", "Dictionary", "Password", "Credential", "Authentication", "Authorization", "Privilege", "Escalation",
        "Lateral", "Movement", "Persistence", "Evasion", "Obfuscation", "Encoding", "Encryption", "Decryption",
        "Reverse", "Forward", "Tunnel", "Proxy", "VPN", "Tor", "Anonymous", "Hidden", "Stealth", "Covert",
        "HTTP", "HTTPS", "FTP", "SSH", "Telnet", "SMTP", "POP3", "IMAP", "DNS", "DHCP", "SNMP", "RDP",
        "SMB", "NetBIOS", "LDAP", "Kerberos", "NTP", "ICMP", "TCP", "UDP", "IP", "ARP", "SIP", "VoIP",
        "Port", "Service", "Application", "Web", "Server", "Client", "Host", "Domain", "Subdomain", "URL",
        "URI", "Path", "Directory", "File", "Extension", "Binary", "Script", "Code", "Source", "Destination",
        "Inbound", "Outbound", "Internal", "External", "Public", "Private", "Local", "Remote", "Foreign",
        "Malware", "Malcode", "Payload", "Dropper", "Loader", "Downloader", "RAT", "C2", "CnC", "Beacon",
        "Callback", "Reverse_Shell", "Bind_Shell", "Web_Shell", "Crypto", "Miner", "Mining", "Coin", "Bitcoin",
        "DoS", "DDoS", "Flood", "Amplification", "Reflection", "SYN", "ACK", "FIN", "RST", "PSH", "URG",
        "Fragment", "Fragmentation", "Reassembly", "Evasion", "IDS", "IPS", "Firewall", "Bypass", "Evade",
        "Encoded", "Base64", "Hex", "Unicode", "ASCII", "UTF", "Obfuscated", "Packed", "Compressed", "Archive",
        "ZIP", "RAR", "TAR", "GZIP", "Executable", "DLL", "EXE", "BAT", "PS1", "VBS", "JS", "JAR",
        "APK", "DMG", "PKG", "MSI", "ISO", "PDF", "DOC", "XLS", "PPT", "RTF", "Office", "Macro"
    ]
    msg = "_".join(random.sample(words, random.randint(2, 4)))
    return f'msg:"{msg}"'

def gen_sid_keyword(sid):
    return f"sid:{sid}"

def gen_rev_keyword():
    return f"rev:{random.randint(1, 10)}"

# Meta keywords (0-1 times each, excluding classtype)
def gen_gid_keyword():
    return f"gid:{random.randint(1, 100)}"

def gen_reference_keyword():
    return f"reference:{gen_reference_value()}"

def gen_priority_keyword():
    return f"priority:{random.randint(1, 5)}"

def gen_metadata_keyword():
    return f"metadata:{gen_metadata()}"

def gen_target_keyword():
    return f"target:{random.choice(['src_ip', 'dest_ip'])}"

# Flow keywords (0-1 times each)
def gen_flow_keyword():
    return f"flow:{gen_flow_options()}"

def gen_flowbits_keyword():
    return f"flowbits:{gen_flowbits()}"

def gen_flowint_keyword():
    var = f"var{random.randint(1, 10)}"
    action = random.choice(["+", "-", "=", "isset", "isnotset"])
    if action in ["+", "-", "="]:
        return f"flowint:{var},{action},{random.randint(1, 100)}"
    return f"flowint:{var},{action}"

def gen_stream_size_keyword():
    direction = random.choice(["server", "client", "both", "either"])
    op = gen_comparison_op()
    return f"stream_size:{direction},{op},{random.randint(100, 10000)}"

def gen_noalert_keyword():
    return "noalert"

# Header keywords (0-1 times each)
def gen_tcp_flags_keyword():
    return f"flags:{gen_tcp_flags()}"

def gen_ttl_keyword():
    return f"ttl:{gen_comparison_op()}{random.randint(1, 255)}"

def gen_ipopts_keyword():
    opts = ["rr", "eol", "nop", "ts", "sec", "lsrr", "ssrr", "any"]
    return f"ipopts:{random.choice(opts)}"

def gen_sameip_keyword():
    return "sameip"

def gen_geoip_keyword():
    direction = random.choice(["src,", "dst,", "both,", ""])
    codes = ",".join(random.sample(["US", "CN", "RU", "DE", "FR"], random.randint(1, 3)))
    return f"geoip:{direction}{codes}"

def gen_itype_keyword():
    return f"itype:{random.randint(0, 18)}"

def gen_icode_keyword():
    return f"icode:{random.randint(0, 15)}"

# Threshold keywords (0-1 times each)
def gen_threshold_keyword():
    return f"threshold:{gen_threshold()}"

def gen_detection_filter_keyword():
    tracks = ["by_src", "by_dst"]
    return f"detection_filter:track {random.choice(tracks)}, count {random.randint(1, 10)}, seconds {random.randint(30, 300)}"

# Repeatable keywords (content and modifiers)
def gen_content_keyword():
    return f"content:{gen_content_value()}"

def gen_nocase_keyword():
    return "nocase"

def gen_depth_keyword():
    return f"depth:{random.randint(10, 500)}"

def gen_offset_keyword():
    return f"offset:{random.randint(0, 100)}"

def gen_distance_keyword():
    return f"distance:{gen_signed_number()}"

def gen_within_keyword():
    return f"within:{random.randint(10, 500)}"

def gen_startswith_keyword():
    return "startswith"

def gen_endswith_keyword():
    return "endswith"

def gen_fast_pattern_keyword():
    if random.choice([True, False]):
        return "fast_pattern"
    return f"fast_pattern:{random.randint(0, 10)},{random.randint(5, 20)}"

def gen_pcre_keyword():
    return f"pcre:{gen_pcre()}"

def gen_dsize_keyword():
    if random.choice([True, False]):
        return f"dsize:{gen_comparison_op()}{random.randint(100, 5000)}"
    return f"dsize:{random.randint(100, 1000)}<>{random.randint(1000, 5000)}"

def gen_bsize_keyword():
    return f"bsize:{gen_comparison_op()}{random.randint(10, 1000)}"

def gen_isdataat_keyword():
    neg = "!" if random.choice([True, False, False]) else ""
    rel = ",relative" if random.choice([True, False]) else ""
    return f"isdataat:{neg}{random.randint(1, 500)}{rel}"

# HTTP keywords (repeatable)
def gen_http_sticky_buffer():
    buffers = ["http.uri", "http.host", "http.method", "http.user_agent",
               "http.cookie", "http.header", "http.request_body", "http.response_body"]
    return random.choice(buffers)

def gen_urilen_keyword():
    return f"urilen:{gen_comparison_op()}{random.randint(10, 500)}"

# TLS keywords
def gen_tls_sticky_buffer():
    buffers = ["tls.sni", "tls.cert_subject", "tls.cert_issuer", "ja3.hash", "ja3s.hash"]
    return random.choice(buffers)

# DNS keywords
def gen_dns_sticky_buffer():
    buffers = ["dns.query", "dns.answer", "dns.opcode", "dns.rrtype"]
    return random.choice(buffers)

# MDNS keywords
def gen_mdns_sticky_buffer():
    buffers = ["dns.query", "dns.answer"]  # MDNS uses same buffers as DNS
    return random.choice(buffers)

# HTTP2 keywords
def gen_http2_sticky_buffer():
    buffers = ["http2.header", "http2.header_name", "http2.data"]
    return random.choice(buffers)

# Byte keywords (prefilter-enabled)
def gen_byte_test_keyword():
    num_bytes = random.randint(1, 4)
    op = random.choice(["<", ">", "=", ">=", "<=", "!"])
    value = random.randint(0, 255)
    offset = random.randint(0, 100)
    return f"byte_test:{num_bytes},{op},{value},{offset}"

def gen_byte_jump_keyword():
    num_bytes = random.randint(1, 4)
    offset = random.randint(0, 100)
    opts = random.choice(["", ",relative", ",from_beginning", ",align"])
    return f"byte_jump:{num_bytes},{offset}{opts}"

def gen_byte_extract_keyword():
    num_bytes = random.randint(1, 4)
    offset = random.randint(0, 100)
    var_name = f"var{random.randint(1, 10)}"
    return f"byte_extract:{num_bytes},{offset},{var_name}"

def gen_byte_math_keyword():
    num_bytes = random.randint(1, 4)
    offset = random.randint(0, 100)
    oper = random.choice(["+", "-", "*", "/", "<<", ">>"])
    rvalue = random.randint(1, 10)
    result = f"result{random.randint(1, 5)}"
    return f"byte_math:bytes {num_bytes}, offset {offset}, oper {oper}, rvalue {rvalue}, result {result}"

# Base64 keywords (prefilter-enabled)
def gen_base64_decode_keyword():
    opts = random.choice(["", "bytes 100", "bytes 100, offset 0", "relative"])
    if opts:
        return f"base64_decode:{opts}"
    return "base64_decode"

def gen_base64_data_keyword():
    return "base64_data"

# File keywords
def gen_filesize_keyword():
    return f"filesize:{gen_comparison_op()}{random.randint(1000, 100000)}"

def gen_filename_keyword():
    exts = ["exe", "dll", "pdf", "doc", "zip", "js", "php"]
    return f'filename:"*.{random.choice(exts)}"'

def gen_fileext_keyword():
    exts = ["exe", "dll", "pdf", "doc", "zip", "js", "php", "bat", "ps1"]
    return f'fileext:"{random.choice(exts)}"'

# Prefilter keyword
def gen_prefilter_keyword():
    return "prefilter"


# =============================================================================
# Header Generators
# =============================================================================

def gen_action():
    return random.choice(["alert", "pass", "drop", "reject"])

def gen_protocol():
    network_protocols = ["tcp-pkt", "tcp-stream", "pkthdr", "tcp", "udp", "icmp", "ip"]
    app_protocols = ["http_any", "http1", "http2", "http", "ftp-data", "ftp", "tls", "ssl",
                    "smb", "dns", "dcerpc", "dhcp", "ssh", "smtp", "imap", "pop3", "modbus",
                    "dnp3", "enip", "nfs", "ike", "krb5", "bittorrent-dht", "ntp", "rfb",
                    "rdp", "snmp", "tftp", "sip", "websocket", "quic", "mqtt", "pgsql",
                    "ja4", "mdns"]

    return random.choice(network_protocols + app_protocols)

def gen_address():
    # Define weight mapping: "Choice": Relative Weight
    address_map = {
        "any": 40,
        "$HOME_NET": 20,
        "$EXTERNAL_NET": 15,
        "$DNS_SERVERS": 5,
        "$SMTP_SERVERS": 2,
        "$SQL_SERVERS": 2,
        "$TELNET_SERVERS": 2,
        "$HTTP_SERVERS": 2,
        # Dynamic choices:
        f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}": 5,
        f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.0/{random.choice([8,16,24])}": 5
    }

    # Extract keys and values as lists for random.choices
    choices = list(address_map.keys())
    weights = list(address_map.values())

    return random.choices(choices, weights=weights, k=1)[0]

def gen_port():
    choices = [
        "any",
        "$HTTP_PORTS",
        str(random.randint(1, 65535)),
        f"{random.randint(1,1024)}:{random.randint(1025,65535)}",
    ]
    return random.choice(choices)

def gen_direction():
    return random.choice(["->", "<>"])


# =============================================================================
# Rule Generator
# =============================================================================

# Define keyword categories with their generators and constraints
REQUIRED_KEYWORDS = {
    "msg": gen_msg_keyword,
    # sid and rev handled separately
}

# 0-1 times each (meta keywords, excluding classtype)
META_KEYWORDS_OPTIONAL = {
    "gid": gen_gid_keyword,
    "reference": gen_reference_keyword,
    "priority": gen_priority_keyword,
    "metadata": gen_metadata_keyword,
    "target": gen_target_keyword,
}

# 0-1 times each (flow keywords)
FLOW_KEYWORDS = {
    "flow": gen_flow_keyword,
    "flowbits": gen_flowbits_keyword,
    "flowint": gen_flowint_keyword,
    "stream_size": gen_stream_size_keyword,
    "noalert": gen_noalert_keyword,
}

# 0-1 times each (header keywords - non-prefilter-enabled only)
# Note: tcp_flags, ttl, ipopts, itype, icode are prefilter-enabled and handled separately
HEADER_KEYWORDS = {
    "sameip": gen_sameip_keyword,
    "geoip": gen_geoip_keyword,
}

# 0-1 times each (threshold keywords)
THRESHOLD_KEYWORDS = {
    "threshold": gen_threshold_keyword,
    "detection_filter": gen_detection_filter_keyword,
}

# Repeatable keywords (0-MAX times, generate with unique values)
# Note: content and pcre are handled separately to maintain ordering constraints
# Note: http, tls, dns sticky buffers are prefilter-enabled and handled separately
REPEATABLE_KEYWORDS = {
    "dsize": gen_dsize_keyword,
    "bsize": gen_bsize_keyword,
    "isdataat": gen_isdataat_keyword,
    "urilen": gen_urilen_keyword,
    "filesize": gen_filesize_keyword,
    "filename": gen_filename_keyword,
    "fileext": gen_fileext_keyword,
}

# Content modifiers (applied after content)
# Note: fast_pattern is a prefilter mechanism that can only follow content/content-modifier
CONTENT_MODIFIERS = {
    "nocase": gen_nocase_keyword,
    "depth": gen_depth_keyword,
    "offset": gen_offset_keyword,
    "distance": gen_distance_keyword,
    "within": gen_within_keyword,
    "startswith": gen_startswith_keyword,
    "endswith": gen_endswith_keyword,
    "fast_pattern": gen_fast_pattern_keyword,
}

# Prefilter-enabled keywords: these can be followed by the "prefilter" keyword
# Note: content/content-modifier use fast_pattern instead of prefilter
PREFILTER_ENABLED_KEYWORDS = {
    # Byte keywords
    "byte_test": gen_byte_test_keyword,
    "byte_jump": gen_byte_jump_keyword,
    "byte_extract": gen_byte_extract_keyword,
    "byte_math": gen_byte_math_keyword,
    # Base64 keywords
    "base64_decode": gen_base64_decode_keyword,
    "base64_data": gen_base64_data_keyword,
    # Header keywords (prefilter-enabled)
    "tcp_flags": gen_tcp_flags_keyword,
    "ttl": gen_ttl_keyword,
    "ipopts": gen_ipopts_keyword,
    "itype": gen_itype_keyword,
    "icode": gen_icode_keyword,
    # HTTP keywords
    "http_sticky": gen_http_sticky_buffer,
    # HTTP2 keywords
    "http2_sticky": gen_http2_sticky_buffer,
    # TLS keywords
    "tls_sticky": gen_tls_sticky_buffer,
    # DNS keywords
    "dns_sticky": gen_dns_sticky_buffer,
    # MDNS keywords
    "mdns_sticky": gen_mdns_sticky_buffer,
}


def gen_prefilter_group(gen_func, used_values):
    """
    Generate a prefilter-enabled keyword group: keyword + optional prefilter.

    Prefilter can follow: byte, base64, header, http, http2, tls, dns, mdns keywords.

    Returns a list of keywords forming the group, or empty list if keyword was duplicate.
    """
    group = []

    keyword_val = gen_func()
    if keyword_val in used_values:
        return []

    used_values.add(keyword_val)
    group.append(keyword_val)

    # Optionally add prefilter after the keyword
    if random.choice([True, False, False, False]):  # Low probability
        group.append(gen_prefilter_keyword())

    return group


def gen_content_group(used_values):
    """
    Generate a content group: content -> modifiers -> optional pcre.

    Constraints:
    - content-modifier must always immediately follow content-keyword
    - pcre-keyword follows content-keyword, or if content is missing, follows content-modifier

    Returns a list of keywords forming the group, or empty list if content was duplicate.
    """
    group = []

    content_val = gen_content_keyword()
    if content_val in used_values:
        return []

    used_values.add(content_val)
    group.append(content_val)

    # Add random content modifiers immediately after content
    for mod_name, mod_func in CONTENT_MODIFIERS.items():
        if random.choice([True, False, False]):  # Less likely to add
            mod_val = mod_func()
            group.append(mod_val)

    # Optionally add pcre after content (or after modifiers if present)
    if random.choice([True, False, False]):
        pcre_val = gen_pcre_keyword()
        if pcre_val not in used_values:
            used_values.add(pcre_val)
            group.append(pcre_val)

    return group


def gen_rule_options(sid):
    """Generate rule options following the constraints."""
    used_values = set()

    # Collect individual keywords and keyword groups separately
    # Groups are treated as atomic units during shuffling
    individual_keywords = []
    keyword_groups = []  # Each element is a list of keywords forming a group

    # 1. Add optional meta keywords (0-1 each)
    for name, gen_func in META_KEYWORDS_OPTIONAL.items():
        if random.choice([True, False]):
            individual_keywords.append(gen_func())

    # 2. Add optional flow keywords (0-1 each)
    for name, gen_func in FLOW_KEYWORDS.items():
        if random.choice([True, False]):
            individual_keywords.append(gen_func())

    # 3. Add optional header keywords (0-1 each, non-prefilter-enabled)
    for name, gen_func in HEADER_KEYWORDS.items():
        if random.choice([True, False]):
            individual_keywords.append(gen_func())

    # 4. Add optional threshold keywords (0-1 each)
    for name, gen_func in THRESHOLD_KEYWORDS.items():
        if random.choice([True, False]):
            individual_keywords.append(gen_func())

    # 5. Add content groups (content -> modifiers -> pcre as atomic units)
    # Note: fast_pattern (prefilter for content) is included in modifiers
    max_content = random.randint(0, 5)
    for _ in range(max_content):
        group = gen_content_group(used_values)
        if group:
            keyword_groups.append(group)

    # 6. Add other repeatable keywords (non-prefilter-enabled)
    for name, gen_func in REPEATABLE_KEYWORDS.items():
        repeat_count = random.randint(0, 2)
        for _ in range(repeat_count):
            val = gen_func()
            if val not in used_values:
                used_values.add(val)
                individual_keywords.append(val)

    # 7. Add prefilter-enabled keyword groups (keyword + optional prefilter)
    # prefilter can follow: byte, base64, header, http, http2, tls, dns, mdns keywords
    for name, gen_func in PREFILTER_ENABLED_KEYWORDS.items():
        if random.choice([True, False, False]):  # Low probability
            group = gen_prefilter_group(gen_func, used_values)
            if group:
                keyword_groups.append(group)

    # 8. Create shuffleable units: individual keywords + keyword groups
    # We'll wrap each individual keyword in a list for uniform handling
    shuffleable_units = [[kw] for kw in individual_keywords] + keyword_groups
    random.shuffle(shuffleable_units)

    # 9. Build final options list
    # Start with msg (required, always first)
    options = [gen_msg_keyword()]

    # Flatten shuffled units
    for unit in shuffleable_units:
        options.extend(unit)

    # 10. Add sid immediately before rev, rev must be LAST keyword
    options.append(gen_sid_keyword(sid))
    options.append(gen_rev_keyword())

    return options


def gen_rule(sid):
    """Generate a complete Suricata rule with the given sid."""
    action = gen_action()
    protocol = gen_protocol()
    src_addr = gen_address()
    src_port = gen_port()
    direction = gen_direction()
    dst_addr = gen_address()
    dst_port = gen_port()

    options = gen_rule_options(sid)
    options_str = "; ".join(options)

    return f"{action} {protocol} {src_addr} {src_port} {direction} {dst_addr} {dst_port} ({options_str};)"


def main():
    parser = argparse.ArgumentParser(
        description="Generate random Suricata rules based on BNF grammar with constraints.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Constraints:
  - msg, sid, rev: exactly once
  - Meta/flow/header/threshold keywords: 0-1 times each (randomly)
  - classtype: excluded
  - Other keywords: repeatable 0-MAX times, no duplicate values
  - sid: incrementing from --sid value
  - rev must be the LAST keyword in rule options
  - sid must be placed immediately BEFORE rev
  - content-modifier must always immediately follow content-keyword
  - pcre-keyword follows content-keyword (or content-modifier if present)
  - Prefilter constraints:
    - fast_pattern can only follow content-keyword or content-modifier
    - prefilter keyword can follow: byte, base64, header, http, http2, tls, dns, mdns keywords

Examples:
  python generate_rules.py -n 10
  python generate_rules.py -n 100 --sid 2000000 -o rules.rules
""")
    parser.add_argument("-n", "--num", type=int, default=10,
                        help="Number of rules to generate (default: 10)")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Output file (default: stdout)")
    parser.add_argument("--sid", type=int, default=1000000,
                        help="Starting SID value (default: 1000000)")
    args = parser.parse_args()

    rules = [gen_rule(args.sid + i) for i in range(args.num)]

    if args.output:
        with open(args.output, "w") as f:
            for rule in rules:
                f.write(rule + "\n")
        print(f"Wrote {len(rules)} rules to {args.output}", file=sys.stderr)
    else:
        for rule in rules:
            print(rule)

    return rules


if __name__ == "__main__":
    main()