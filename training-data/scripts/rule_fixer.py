#!/usr/bin/env python3
"""
Suricata Rule Fixer for Suricata 8.0.3

Converts invalid Suricata rules into valid rules by fixing common validation errors
based on BNF grammar and AWS Network Firewall requirements.

Usage:
    python rule_fixer.py input.rules -o output.rules
    echo "rule..." | python rule_fixer.py -
    python rule_fixer.py input.rules --verbose
"""

import re
import sys
import argparse
import random
from dataclasses import dataclass, field
from typing import Optional, Iterator

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

SID_RANGE = (1_000_000, 9_999_999)
VALID_ACTIONS = {"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"}
VALID_DIRECTIONS = {"->", "<>"}
VALID_NETWORK_PROTOCOLS = {"ip", "tcp", "udp", "icmp", "tcp-pkt", "tcp-stream", "pkthdr"}
VALID_APP_PROTOCOLS = {
    "http", "http1", "http2", "ftp", "ftp-data", "tls", "smb", "dns", "dcerpc", 
    "dhcp", "ssh", "smtp", "imap", "modbus", "dnp3", "enip", "nfs", "ike", "krb5",
    "bittorrent-dht", "ntp", "rfb", "rdp", "snmp", "tftp", "sip", "websocket", 
    "quic", "mqtt", "pgsql", "ja4", "mdns"
}
SUPPORTED_VARIABLES = {"$HOME_NET", "$EXTERNAL_NET"}
COMMON_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 27017]

# Protocol/action replacement mappings
UNSUPPORTED_PROTOCOLS = {"ssl": "tls", "pop3": "tcp", "http_any": "http"}
INVALID_ACTIONS = {"log": "alert", "activate": "alert", "dynamic": "alert"}

# Legacy keyword -> sticky buffer conversion
LEGACY_TO_STICKY = {
    "tls_sni": "tls.sni", "tls_cert_subject": "tls.cert_subject",
    "tls_cert_issuer": "tls.cert_issuer", "ssl_version": "tls.version",
    "ssl_state": "tls.version", "ssh_proto": "ssh.proto", "ssh_software": "ssh.software",
}

# HTTP/1 modifiers -> sticky buffer mapping  
HTTP1_TO_STICKY = {
    "http_uri": "http.uri", "http_raw_uri": "http.uri.raw", "http_method": "http.method",
    "http_header": "http.header", "http_raw_header": "http.header.raw",
    "http_cookie": "http.cookie", "http_client_body": "http.request_body",
    "http_stat_code": "http.stat_code", "http_stat_msg": "http.stat_msg",
    "http_user_agent": "http.user_agent", "http_host": "http.host", "http_raw_host": "http.host.raw",
}

MODERN_STICKY_BUFFERS = set(HTTP1_TO_STICKY.values()) | {"pkt_data", "payload", "file.data"}

# Modifiers that belong to a specific content match
CONTENT_MODIFIERS = { "nocase", "rawbytes", "fast_pattern", "startswith", "endswith" }

# All valid content modifiers
UNIQUE_CONTENT_MODIFIERS = {"distance", "within", "depth", "offset", "nocase", 
                            "fast_pattern", "rawbytes", "startswith", "endswith"}

# Modifiers that provide a fixed starting point or boundary
ABSOLUTE_MODIFIERS = {"offset", "depth", "startswith", "endswith"}

# Modifiers that provide a relative position from the previous match
RELATIVE_MODIFIERS = {"distance", "within"}

# Singleton fields (only one allowed per rule)
SINGLETON_FIELDS = {"sid", "rev", "priority", "gid", "msg", "flow", "metadata", 
                    "reference", "threshold", "detection_filter", "tag", "target"}

# PCRE modifiers to remove and their recommended replacements
PCRE_MODIFIERS = {
    'H': "http.header", 'P': "http.request_body", 'C': "http.cookie",
    'U': "http.uri", 'M': "http.method", 'S': 'http.stat_msg', 'Y': 'http.header.raw',
    'V': 'http.user_agent', 'O': 'http.uri.raw',
}

# Protocol-specific keywords for detection
PROTOCOL_KEYWORDS = {
    'http1': {"http_uri", "http_raw_uri", "http_method", "http_header", "http_raw_header",
              "http_cookie", "http_client_body", "http_stat_code", "http_stat_msg",
              "http_user_agent", "http_host", "http_raw_host", "uricontent", "urilen"},
    'http_sticky': {"http.uri", "http.uri.raw", "http.host", "http.host.raw", "http.method",
                    "http.request_line", "http.request_body", "http.response_line", "http.response_body",
                    "http.header", "http.header.raw", "http.header_names", "http.cookie",
                    "http.user_agent", "http.accept", "http.accept_enc", "http.accept_lang",
                    "http.referer", "http.connection", "http.content_len", "http.content_type",
                    "http.location", "http.server", "http.protocol", "http.stat_code",
                    "http.stat_msg", "http.start", "http.request_header", "http.response_header",
                    "file.data", "file.name"},
    'dns': {"dns.query", "dns.answer", "dns.answer.name", "dns.authority", "dns.authority.name", 
            "dns.opcode", "dns.rrtype"},
    'tls': {"tls.cert_subject", "tls.cert_issuer", "tls.cert_serial", "tls.cert_fingerprint",
            "tls.sni", "tls.certs", "tls.version", "tls.subject", "tls.issuerdn",
            "tls.cert_chain_len", "tls.cert_notbefore", "tls.cert_notafter", "tls.random",
            "tls.alpn", "ja3.hash", "ja3.string", "ja3s.hash", "ja3s.string"},
    'tls_legacy': {"ssl_version", "ssl_state", "tls_sni", "tls_cert_subject",
                   "tls_cert_issuer", "tls_cert_serial", "tls_cert_fingerprint"},
    'ssh': {"ssh.proto", "ssh.software", "ssh.hassh", "ssh.hassh.string",
            "ssh.hassh.server", "ssh.hassh.server.string", "ssh_proto", "ssh_software"},
    'smtp': {"smtp.helo", "smtp.mail_from", "smtp.rcpt_to", "app-layer-event:smtp"},
    'packet': {"dsize", "flags", "ttl", "id", "ipopts", "fragbits", "fragoffset", "tos", "seq", "ack", "window"},
}

# Sticky buffers set (computed once)
ALL_STICKY_BUFFERS = (
    PROTOCOL_KEYWORDS['http_sticky'] | PROTOCOL_KEYWORDS['tls'] | 
    PROTOCOL_KEYWORDS['dns'] | PROTOCOL_KEYWORDS['ssh'] |
    {"file_data", "pkt_data", "raw_data", "base64_data"}
)

STICKY_BUFFERS_FOR_CLEANUP = {
    'http.uri', 'http.uri.raw', 'http.method', 'http.request_body', 
    'http.response_body', 'http.header', 'http.cookie', 'http.user_agent',
    'http.host', 'http.stat_msg', 'http.stat_code', 'http.request_header'
}

# ============================================================================
# COMPILED REGEX PATTERNS
# ============================================================================

RE_RULE = re.compile(
    r'^(?P<action>[a-zA-Z]+)\s+(?P<proto>[a-zA-Z0-9_-]+)\s+(?P<src>(?:\[[^\]]+\]|[^\s]+))\s+'
    r'(?P<src_port>(?:\[[^\]]+\]|[^\s]+))\s+(?P<dir>->|<>|=>)\s+(?P<dst>(?:\[[^\]]+\]|[^\s]+))\s+'
    r'(?P<dst_port>(?:\[[^\]]+\]|[^\s]+))\s+\((?P<options>.*)\)\s*;?\s*$'
)
RE_SID = re.compile(r'\bsid\s*:\s*(\d+)')
RE_VAR = re.compile(r'\$[A-Z_][A-Z0-9_]*')
RE_CLASSTYPE = re.compile(r'\s*classtype\s*:\s*[^;]+\s*;', re.IGNORECASE)
RE_GID = re.compile(r'\s*gid\s*:\s*\d+\s*;', re.IGNORECASE)
RE_CONTENT = re.compile(r'(content\s*:\s*")((?:[^"\\]|\\.)*)(")') 
RE_PCRE = re.compile(r'(pcre\s*:\s*")((?:[^"\\]|\\.)*)(")') 
RE_URICONTENT = re.compile(r'uricontent\s*:\s*("[^"]*")', re.IGNORECASE)
RE_COMMA_SPACE = re.compile(r',\s+')
RE_MSG = re.compile(r'(msg\s*:\s*")((?:[^"\\]|\\.)*)(")')
RE_METHOD_SPACE = re.compile(r'(http\.method\s*;\s*content\s*:\s*")\s*([^"]+?)\s*(")', re.IGNORECASE)
RE_PCRE_RAW = re.compile(r'(?<!pkt_data;\s)(pcre\s*:\s*"[^"]*/D[a-zA-Z]*";)', re.IGNORECASE)
RE_FP_ONLY = re.compile(r'fast_pattern\s*:\s*only\s*;', re.IGNORECASE)
RE_RELATIVE_KW = re.compile(r'\b(distance|within|offset|depth)\s*:', re.IGNORECASE)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class RuleComponents:
    """Parsed Suricata rule components"""
    action: str
    proto: str
    src: str
    src_port: str
    direction: str
    dst: str
    dst_port: str
    options: str
    original: str = ""

@dataclass
class FixResult:
    """Result of fixing a rule"""
    original_rule: str
    fixed_rule: str
    is_valid: bool
    actions_taken: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


class SIDManager:
    """Manages unique SIDs across rules"""
    def __init__(self):
        self.used: set[int] = set()
    
    def generate(self) -> int:
        while (sid := random.randint(*SID_RANGE)) in self.used:
            pass
        self.used.add(sid)
        return sid


# ============================================================================
# QUOTE-AWARE PARSING UTILITIES
# ============================================================================

def iter_with_quote_state(text: str) -> Iterator[tuple[int, str, bool, bool]]:
    """
    Iterate through text tracking quote and escape state.
    
    Yields: (index, char, in_quote, is_escaped)
    """
    in_quote = escape = False
    for i, char in enumerate(text):
        if escape:
            yield i, char, in_quote, True
            escape = False
        elif char == '\\':
            escape = True
            yield i, char, in_quote, False
        elif char == '"':
            in_quote = not in_quote
            yield i, char, in_quote, False
        else:
            yield i, char, in_quote, False


def tokenize_options(options_str: str) -> list[str]:
    """Split options by semicolon, respecting quoted strings"""
    tokens, current = [], []
    
    for _, char, in_quote, _ in iter_with_quote_state(options_str):
        if char == ';' and not in_quote:
            if current and (val := ''.join(current).strip()):
                tokens.append(val)
            current = []
        else:
            current.append(char)
    
    if current and (val := ''.join(current).strip()):
        tokens.append(val)
    return tokens


def cleanup_semicolons(text: str) -> str:
    """Normalize semicolons: deduplicate, add spacing, ensure trailing semicolon"""
    result, prev_semi = [], False
    
    for _, char, in_quote, _ in iter_with_quote_state(text):
        if char == ';' and not in_quote:
            if not prev_semi:
                result.append('; ')
                prev_semi = True
        elif char in ' \t' and prev_semi and not in_quote:
            continue  # Skip spaces after semicolon
        else:
            result.append(char)
            prev_semi = False
    
    cleaned = ''.join(result).strip().rstrip('; ').strip()
    return cleaned + ';' if cleaned else ''


def process_pcre_pattern(pattern: str, process_func) -> tuple[str, bool]:
    """
    Process PCRE pattern character by character, tracking character class state.
    
    Args:
        pattern: The PCRE pattern string
        process_func: Function(char, i, pattern, in_char_class) -> (str, skip_count) or None
                     Returns replacement string and chars to skip, or None to use original
    
    Returns: (processed_pattern, was_modified)
    """
    result, i, modified = [], 0, False
    in_char_class = False
    
    while i < len(pattern):
        # Try custom processing first
        if processed := process_func(pattern, i, in_char_class):
            replacement, skip = processed
            result.append(replacement)
            modified = True
            i += skip
            continue
        
        char = pattern[i]
        
        # Handle escape sequences
        if char == '\\' and i + 1 < len(pattern):
            result.append(pattern[i:i+2])
            i += 2
            continue
        
        # Track character class boundaries
        if char == '[' and not in_char_class:
            in_char_class = True
            result.append(char)
            i += 1
            # Handle [^ and [] at start of class
            for special in ('^', ']'):
                if i < len(pattern) and pattern[i] == special:
                    result.append(pattern[i])
                    i += 1
            continue
        
        if char == ']' and in_char_class:
            in_char_class = False
        
        result.append(char)
        i += 1
    
    return ''.join(result), modified


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def has_keyword(keyword: str, text: str) -> bool:
    """Check if keyword exists as a whole word in text"""
    return bool(re.search(rf'(?:^|[;\s]){re.escape(keyword)}(?:[;:\s]|$)', text, re.IGNORECASE))


def detect_keywords(options: str) -> dict[str, list]:
    """Detect protocol-specific keywords in options string"""
    options_lower = options.lower()
    found = {}
    
    for category, keywords in PROTOCOL_KEYWORDS.items():
        if category == 'packet':
            found[category] = [kw for kw in keywords 
                              if re.search(rf'\b{kw}\s*[:;]', options_lower)]
        else:
            found[category] = [kw for kw in keywords 
                              if has_keyword(kw, options_lower)]
    return found


def get_field_name(token: str) -> str:
    """Extract field name from a token (part before colon)"""
    return token.lower().split(':')[0].strip() if ':' in token else token.lower().strip()


# ============================================================================
# FIX FUNCTIONS - HEADER COMPONENTS
# ============================================================================

def parse_rule(rule: str) -> Optional[RuleComponents]:
    """Parse a Suricata rule into components"""
    rule = rule.strip()
    if not rule or rule.startswith('#'):
        return None
    if match := RE_RULE.match(rule):
        return RuleComponents(
            action=match.group('action'), proto=match.group('proto'),
            src=match.group('src'), src_port=match.group('src_port'),
            direction=match.group('dir'), dst=match.group('dst'),
            dst_port=match.group('dst_port'), options=match.group('options'),
            original=rule
        )
    return None


def fix_action(action: str, result: FixResult) -> str:
    """Fix invalid action"""
    action_lower = action.lower()
    if action_lower in VALID_ACTIONS:
        return action
    if replacement := INVALID_ACTIONS.get(action_lower):
        result.actions_taken.append(f"Changed action '{action}' to '{replacement}'")
        return replacement
    result.actions_taken.append(f"Changed invalid action '{action}' to 'alert'")
    return "alert"


def fix_protocol(proto: str, options: str, result: FixResult) -> str:
    """Fix protocol based on content and keywords"""
    proto_lower = proto.lower()
    detected = detect_keywords(options)
    
    # Handle unsupported protocols
    if proto_lower in UNSUPPORTED_PROTOCOLS:
        replacement = UNSUPPORTED_PROTOCOLS[proto_lower]
        result.actions_taken.append(f"Changed unsupported protocol '{proto_lower}' to '{replacement}'")
        return replacement
    
    # tcp-stream with packet keywords
    if proto_lower == "tcp-stream" and detected.get('packet'):
        result.actions_taken.append(f"Changed 'tcp-stream' to 'tcp' due to packet keywords: {detected['packet']}")
        return "tcp"
    
    # http2/http1 conflicts
    if proto_lower == "http2" and (detected.get('http1') or detected.get('http_sticky') or "urilen" in options.lower()):
        result.actions_taken.append("Changed 'http2' to 'http' due to HTTP/1 keywords")
        return "http"
    if proto_lower == "http1" and detected.get('http_sticky'):
        result.actions_taken.append("Changed 'http1' to 'http' due to sticky buffers")
        return "http"
    
    # Protocol mismatches (data-driven)
    mismatches = [
        (("http", "http1", "http2"), 'dns', "dns"),
        (("http", "http1", "http2"), 'ssh', "ssh"),
        (("http", "http1", "http2"), 'smtp', "smtp"),
        (("dns",), 'tls', "tls"), (("dns",), 'tls_legacy', "tls"),
        (("quic",), 'tls', "tls"), (("quic",), 'tls_legacy', "tls"),
        (("ftp",), 'http1', "http"), (("ftp",), 'http_sticky', "http"),
    ]
    for protos, kw_type, target in mismatches:
        if proto_lower in protos and detected.get(kw_type):
            result.actions_taken.append(f"Changed '{proto_lower}' to '{target}' due to {kw_type} keywords")
            return target
    
    # Special cases
    if proto_lower == "tls" and "app-layer-event:smtp" in options.lower():
        result.actions_taken.append("Changed 'tls' to 'smtp' due to SMTP app-layer-event")
        return "smtp"
    if proto_lower == "icmp" and "ip_proto:" in options.lower():
        result.actions_taken.append("Changed 'icmp' to 'ip' due to ip_proto keyword")
        return "ip"
    
    # Validate known protocol
    all_protocols = VALID_NETWORK_PROTOCOLS | VALID_APP_PROTOCOLS | set(UNSUPPORTED_PROTOCOLS)
    if proto_lower not in all_protocols:
        result.warnings.append(f"Unknown protocol '{proto}', keeping as-is")
    
    return proto


def fix_direction(direction: str, result: FixResult) -> str:
    """Fix invalid direction operator"""
    if direction in VALID_DIRECTIONS:
        return direction
    if direction == "=>":
        result.actions_taken.append("Changed direction '=>' to '->'")
        return "->"
    result.warnings.append(f"Unknown direction '{direction}', defaulting to '->'")
    return "->"


def fix_address(address: str, field_name: str, result: FixResult) -> str:
    """Fix invalid addresses"""
    # Remove spaces in groups
    if '[' in address and ',' in address:
        fixed = RE_COMMA_SPACE.sub(',', address)
        if fixed != address:
            result.actions_taken.append(f"Removed spaces in {field_name} address group")
            address = fixed
    
    # Replace unsupported variables
    for var in RE_VAR.findall(address):
        if var not in SUPPORTED_VARIABLES:
            result.actions_taken.append(f"Replaced {var} with $HOME_NET in {field_name}")
            address = address.replace(var, "$HOME_NET")
    return address


def fix_port(port: str, field_name: str, result: FixResult) -> str:
    """Fix invalid port specifications"""
    if port == "!any":
        result.actions_taken.append(f"Changed '!any' to 'any' in {field_name}")
        return "any"
    if port.startswith("!!"):
        result.actions_taken.append(f"Removed double negation in {field_name}")
        return port[2:]
    
    # Replace unsupported variables
    for var in RE_VAR.findall(port):
        if var not in SUPPORTED_VARIABLES:
            random_port = random.choice(COMMON_PORTS)
            result.actions_taken.append(f"Replaced {var} with '{random_port}' in {field_name}")
            port = port.replace(var, str(random_port))
    
    # Remove spaces in groups
    if '[' in port and ',' in port:
        fixed = RE_COMMA_SPACE.sub(',', port)
        if fixed != port:
            result.actions_taken.append(f"Removed spaces in {field_name} port group")
            port = fixed
    return port


# ============================================================================
# FIX FUNCTIONS - OPTIONS
# ============================================================================

def fix_duplicate_options(options_str: str, result: FixResult) -> str:
    """Remove duplicate options and ensure modifiers are not duplicated for the same content."""
    tokens = tokenize_options(options_str)
    fixed_tokens = []
    
    seen_singletons: set[str] = set()
    seen_content: set[str] = set()
    seen_flowbits: set[str] = set()
    current_content_modifiers: set[str] = set()
    in_content_chain = False
    removed_count = 0

    for token in tokens:
        if not token.strip():
            continue

        field_name = get_field_name(token)

        # Handle singletons (msg, sid, etc)
        if field_name in SINGLETON_FIELDS:
            if field_name in seen_singletons:
                removed_count += 1
                continue
            seen_singletons.add(field_name)
            in_content_chain = False
            current_content_modifiers.clear()

        # Handle sticky buffers
        elif field_name in ALL_STICKY_BUFFERS or token.lower().strip() in ALL_STICKY_BUFFERS:
            key = field_name if field_name in ALL_STICKY_BUFFERS else token.lower().strip()
            if key in seen_singletons:
                removed_count += 1
                continue
            seen_singletons.add(key)
            in_content_chain = False
            current_content_modifiers.clear()

        # Handle content (start of modifier chain)
        elif field_name == "content":
            if match := re.match(r'content\s*:\s*(.+)', token, re.IGNORECASE):
                val = match.group(1).strip()
                if val in seen_content:
                    removed_count += 1
                    continue
                seen_content.add(val)
                in_content_chain = True
                current_content_modifiers.clear()

        # Handle content modifiers
        elif field_name in UNIQUE_CONTENT_MODIFIERS:
            if in_content_chain:
                if field_name in current_content_modifiers:
                    removed_count += 1
                    continue
                current_content_modifiers.add(field_name)
            else:
                # Orphaned modifier - remove
                removed_count += 1
                continue

        # Handle flowbits
        elif field_name == "flowbits":
            if match := re.match(r'flowbits\s*:\s*(.+)', token, re.IGNORECASE):
                val = match.group(1).strip()
                if val in seen_flowbits:
                    removed_count += 1
                    continue
                seen_flowbits.add(val)
            in_content_chain = False
            current_content_modifiers.clear()

        else:
            # Other keywords break the content modifier chain
            in_content_chain = False
            current_content_modifiers.clear()

        fixed_tokens.append(token)

    if removed_count > 0:
        result.actions_taken.append(f"Removed {removed_count} duplicate/orphaned options")
    
    return "; ".join(fixed_tokens)

def convert_to_sticky_buffers(options_str: str, result: FixResult) -> str:
    parts = [p.strip() for p in re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', options_str) if p.strip()]
    
    new_options = []
    buffer_stack = []  # Holds content/depth/offset associated with current buffer
    current_active_buffer = None

    for part in parts:
        # 1. Handle Legacy HTTP Modifiers (e.g., http_uri)
        if part in HTTP1_TO_STICKY:
            target_buffer = HTTP1_TO_STICKY[part]
            
            # If we are changing buffers, output the new buffer name
            if target_buffer != current_active_buffer:
                new_options.append(target_buffer)
                current_active_buffer = target_buffer
                result.actions_taken.append(f"Hoisted {target_buffer}")
            
            # Flush any content/modifiers waiting in the stack
            new_options.extend(buffer_stack)
            buffer_stack = []

        # 2. Handle PCRE
        elif part.startswith('pcre:'):
            match = re.search(r'pcre\s*:\s*"(/.+/)([A-Za-z]*)?"', part)
            if match:
                regex_body = match.group(1)
                flags = match.group(2) or ""
                
                found_flag_buffer = None
                new_flags = flags
                
                # Check for legacy buffer flags in the PCRE (e.g., /U, /H)
                for flag, buffer_name in PCRE_MODIFIERS.items():
                    if flag in flags:
                        found_flag_buffer = buffer_name
                        new_flags = new_flags.replace(flag, "")
                        # PCRE flags like /U implied the buffer; remove only one buffer flag
                        break 
                
                # Flush pending content stack before processing the PCRE
                if buffer_stack:
                    new_options.extend(buffer_stack)
                    buffer_stack = []

                # CASE A: PCRE has a specific buffer flag (e.g., /U)
                if found_flag_buffer:
                    if found_flag_buffer == 'pkt_data':
                        # Explicit raw data request (/D)
                        new_options.append("pkt_data")
                        current_active_buffer = "pkt_data"
                        new_options.append(f'pcre:"{regex_body}{new_flags}"')
                        result.actions_taken.append("Reset to pkt_data due to /D flag")
                    elif found_flag_buffer != current_active_buffer:
                        # Switch to the requested buffer
                        new_options.append(found_flag_buffer)
                        current_active_buffer = found_flag_buffer
                        new_options.append(f'pcre:"{regex_body}{new_flags}"')
                        result.actions_taken.append(f"Switched buffer to {found_flag_buffer} based on PCRE flag")
                    else:
                        # Already in correct buffer
                        new_options.append(f'pcre:"{regex_body}{new_flags}"')

                # CASE B: PCRE has NO buffer flag (Legacy default = Payload)
                else:
                    is_relative = 'R' in flags
                    
                    # If we are in a sticky buffer, but the PCRE is NOT relative,
                    # legacy rules implies this matches the PACKET PAYLOAD.
                    # We must reset the buffer.
                    if current_active_buffer and current_active_buffer != "pkt_data" and not is_relative:
                        new_options.append("pkt_data")
                        current_active_buffer = "pkt_data"
                        new_options.append(part)
                        result.actions_taken.append("Injecting pkt_data; for flagless PCRE to match payload")
                    else:
                        # Either we are already in payload/None, or it is relative (/R)
                        # so it stays in the current sticky context.
                        new_options.append(part)
            else:
                # Malformed PCRE, pass through
                new_options.append(part)

        # 3. Handle Content and Modifiers (stack them until buffer is confirmed)
        elif part.startswith(('content:', 'nocase', 'distance:', 'within:', 'offset:', 'depth:', 'fast_pattern', 'isdataat:', 'byte_')):
            buffer_stack.append(part)

        # 4. Handle Metadata/Flow/Classtype (pass through immediately)
        else:
            if buffer_stack:
                new_options.extend(buffer_stack)
                buffer_stack = []
            new_options.append(part)

    # Flush remaining stack
    if buffer_stack:
        new_options.extend(buffer_stack)

    result_str = "; ".join(new_options) + ";"

    # --- Post-Processing Fixes ---

    # 1. Fix method content spacing (e.g. http.method; content: "GET")
    if RE_METHOD_SPACE.search(result_str):
        result_str = RE_METHOD_SPACE.sub(r'\1\2\3', result_str)

    # 2. Heuristic: Http Method usually ends the buffer immediately in legacy rules
    # logic: if http.method is used, subsequent content is often URI or Payload. 
    # To be safe, if we see http.method and no explicit buffer switch follows, we might want pkt_data.
    # (Note: The main loop handles PCRE, but this handles `content`)
    # However, strict blind injection can break things. The loop above handles most cases.
    # We will keep the user's original safely logic for http.method only if needed.
    if "http.method;" in result_str and "pkt_data;" not in result_str and "content" in result_str.split("http.method;")[1]:
         # Only inject if followed by content that might be payload. 
         # This is risky without deeper parsing, but safer for "GET" + Payload rules.
         pass 

    # 3. Handle Encoded URI automatically
    if "http.uri;" in result_str and ("%" in result_str or "| " in result_str):
        result_str = result_str.replace("http.uri;", "http.uri.raw;")
        result.actions_taken.append("Upgraded http.uri to http.uri.raw for encoded content")

    # 4. Clean up empty buffers (e.g. "http.uri; http.header;")
    final_tokens = tokenize_options(result_str)
    cleaned_tokens = []
    for i, token in enumerate(final_tokens):
        current_kw = token.lower().replace(";", "")
        
        # Look ahead to see if the next token is also a buffer start or pkt_data
        next_token = final_tokens[i+1].lower().replace(";", "") if i + 1 < len(final_tokens) else ""
        
        if current_kw in STICKY_BUFFERS_FOR_CLEANUP and (next_token in STICKY_BUFFERS_FOR_CLEANUP or next_token == 'pkt_data'):
            continue # Skip this empty buffer declaration
        cleaned_tokens.append(token)

    return "; ".join(cleaned_tokens) + ";"


def fix_content_pipes(options_str: str, result: FixResult) -> str:
    """Fix escaped pipes in content values where backslash precedes hex notation"""
    def process_content(m):
        prefix, value, suffix = m.group(1), m.group(2), m.group(3)
        original_value = value
        
        # \||hex| → ||hex|
        value = re.sub(r'\\\|(\|[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\|)', r'|\1', value)
        # \|hex| → |hex|
        value = re.sub(r'\\\|([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\|)', r'|\1', value)
        
        return prefix + value + suffix if value != original_value else m.group(0)
    
    fixed = RE_CONTENT.sub(process_content, options_str)
    if fixed != options_str:
        result.actions_taken.append("Removed backslash from escaped pipes followed by hex notation")
    return fixed


def fix_pcre_hex_semicolons(options_str: str, result: FixResult) -> str:
    """Fix |3b| (Suricata hex notation) inside PCRE patterns"""
    def process_pcre(m):
        prefix, pattern, suffix = m.group(1), m.group(2), m.group(3)
        
        if not re.search(r'\\?\|3b\|', pattern, re.IGNORECASE):
            return m.group(0)
        
        def handler(pat: str, i: int, in_char_class: bool):
            # \|3b|) → \)
            if (i + 5 <= len(pat) and pat[i:i+5].lower() == '\\|3b|' and 
                i + 5 < len(pat) and pat[i+5] == ')' and not in_char_class):
                return '\\)', 6
            # \|3b| → \;
            if i + 5 <= len(pat) and pat[i:i+5].lower() == '\\|3b|' and not in_char_class:
                return '\\;', 5
            # |3b| → \;
            if i + 4 <= len(pat) and pat[i:i+4].lower() == '|3b|':
                return (pat[i:i+4], 4) if in_char_class else ('\\;', 4)
            return None
        
        new_pattern, modified = process_pcre_pattern(pattern, handler)
        return prefix + new_pattern + suffix if modified else m.group(0)
    
    fixed = RE_PCRE.sub(process_pcre, options_str)
    if fixed != options_str:
        result.actions_taken.append("Fixed |3b| patterns in PCRE (converted to escaped semicolon/paren)")
    return fixed


def fix_pcre_semicolons(options_str: str, result: FixResult) -> str:
    """Escape unescaped semicolons inside PCRE patterns"""
    def process_pcre(m):
        prefix, pattern, suffix = m.group(1), m.group(2), m.group(3)
        
        if ';' not in pattern:
            return m.group(0)
        
        def handler(pat: str, i: int, in_char_class: bool):
            if pat[i] == ';' and not in_char_class:
                return '\\;', 1
            return None
        
        new_pattern, modified = process_pcre_pattern(pattern, handler)
        return prefix + new_pattern + suffix if modified else m.group(0)
    
    fixed = RE_PCRE.sub(process_pcre, options_str)
    if fixed != options_str:
        result.actions_taken.append("Escaped semicolons in PCRE patterns")
    return fixed


def fix_fast_pattern_only(options_str: str, result: FixResult) -> str:
    """Replace 'fast_pattern:only;' with 'fast_pattern;' when relative keywords follow"""
    if not (match := RE_FP_ONLY.search(options_str)):
        return options_str
    
    if RE_RELATIVE_KW.search(options_str[match.end():]):
        fixed = RE_FP_ONLY.sub('fast_pattern;', options_str, count=1)
        result.actions_taken.append("Replaced 'fast_pattern:only' with 'fast_pattern' (relative keywords used after)")
        return fixed
    return options_str


def fix_content_modifiers(options_str: str, result: FixResult) -> str:
    """Fix conflicting content modifiers (remove absolute when relative present)"""
    tokens = tokenize_options(options_str)
    fixed_tokens = []
    removed_count = 0
    
    i = 0
    while i < len(tokens):
        field_name = get_field_name(tokens[i])
        
        if field_name != "content":
            fixed_tokens.append(tokens[i])
            i += 1
            continue
        
        # Add content token
        fixed_tokens.append(tokens[i])
        i += 1
        
        # Collect subsequent modifiers
        content_modifiers = []
        while i < len(tokens):
            mod_field = get_field_name(tokens[i])
            if mod_field == "content" or mod_field not in UNIQUE_CONTENT_MODIFIERS:
                break
            content_modifiers.append((tokens[i], mod_field))
            i += 1
        
        # Check for conflicts
        has_relative = any(mf in RELATIVE_MODIFIERS for _, mf in content_modifiers)
        has_absolute = any(mf in ABSOLUTE_MODIFIERS for _, mf in content_modifiers)
        
        if has_relative and has_absolute:
            for mod_token, mod_field in content_modifiers:
                if mod_field in ABSOLUTE_MODIFIERS:
                    removed_count += 1
                else:
                    fixed_tokens.append(mod_token)
        else:
            fixed_tokens.extend(mod_token for mod_token, _ in content_modifiers)
    
    if removed_count > 0:
        result.actions_taken.append(f"Removed {removed_count} absolute modifiers conflicting with relative modifiers")
    
    return "; ".join(fixed_tokens)


def fix_options(options_str: str, proto: str, result: FixResult) -> str:
    """Fix rule options for Suricata 8.0.3 compatibility"""
    fixed = options_str

    # Remove unsupported keywords
    for pattern, name in [(RE_CLASSTYPE, 'classtype'), (RE_GID, 'gid')]:
        if pattern.search(fixed):
            fixed = pattern.sub('', fixed)
            result.actions_taken.append(f"Removed '{name}'" + (" (unsupported by AWS)" if name == 'classtype' else ""))

    # Escape semicolons inside content
    def escape_content_semicolons(m):
        return m.group(1) + m.group(2).replace(';', '|3b|') + m.group(3) if ';' in m.group(2) else m.group(0)

    original = fixed
    fixed = RE_CONTENT.sub(escape_content_semicolons, fixed)
    if fixed != original:
        result.actions_taken.append("Escaped semicolons in content strings")

    # Escape semicolons in msg field
    def escape_msg_semicolons(m):
        msg = m.group(2)
        if ';' in msg:
            return m.group(1) + re.sub(r'(?<!\\);', r'\\;', msg) + m.group(3)
        return m.group(0)
    
    original = fixed
    fixed = RE_MSG.sub(escape_msg_semicolons, fixed)
    if fixed != original:
        result.actions_taken.append("Escaped semicolons in msg field")

    # Apply transformations
    fixed = convert_to_sticky_buffers(fixed, result)
    fixed = fix_content_pipes(fixed, result)
    fixed = fix_pcre_hex_semicolons(fixed, result)
    fixed = fix_pcre_semicolons(fixed, result)
    fixed = fix_fast_pattern_only(fixed, result)

    # Fix JA3/JA3S flow direction
    fixed_lower = fixed.lower()
    if 'ja3.hash;' in fixed_lower and 'ja3s' not in fixed_lower:
        if re.search(r'flow\s*:\s*[^;]*to_client', fixed, re.IGNORECASE):
            fixed = re.sub(r'(flow\s*:\s*[^;]*)to_client', r'\1to_server', fixed, flags=re.IGNORECASE)
            result.actions_taken.append("Fixed flow direction: ja3.hash requires to_server (client traffic)")
    
    if 'ja3s.hash;' in fixed_lower:
        if re.search(r'flow\s*:\s*[^;]*to_server', fixed, re.IGNORECASE):
            fixed = re.sub(r'(flow\s*:\s*[^;]*)to_server', r'\1to_client', fixed, flags=re.IGNORECASE)
            result.actions_taken.append("Fixed flow direction: ja3s.hash requires to_client (server traffic)")

    # Remove nocase when ja3.hash or ja3s.hash is present (hash values are case-sensitive hex)
    if 'ja3.hash;' in fixed_lower or 'ja3s.hash;' in fixed_lower:
        if re.search(r'\bnocase\s*;', fixed, re.IGNORECASE):
            fixed = re.sub(r'\s*nocase\s*;', ';', fixed, flags=re.IGNORECASE)
            result.actions_taken.append("Removed nocase modifier (ja3/ja3s hash values are case-sensitive)")

    # Convert legacy keywords to sticky buffers
    for old_kw, new_kw in LEGACY_TO_STICKY.items():
        pattern = rf'\b{old_kw}\s*([;:])'
        if re.search(pattern, fixed, re.IGNORECASE):
            fixed = re.sub(pattern, f'{new_kw}\\1', fixed, flags=re.IGNORECASE)
            result.actions_taken.append(f"Converted '{old_kw}' to '{new_kw}'")

    # Remove PCRE modifiers
    for mod, buffer in PCRE_MODIFIERS.items():
        pattern = re.compile(r'(pcre\s*:\s*"(?:[^"\\]|\\.)*?/[a-zA-Z]*)' + mod + r'([a-zA-Z]*")', re.IGNORECASE)
        if pattern.search(fixed):
            fixed = pattern.sub(r'\1\2', fixed)
            result.actions_taken.append(f"Removed PCRE /{mod} modifier (use {buffer})")

    # Fix uricontent
    if matches := list(RE_URICONTENT.finditer(fixed)):
        if proto in ("http", "http1", "http2", "tcp"):
            for m in reversed(matches):
                fixed = fixed[:m.start()] + f'http.uri; content:{m.group(1)}' + fixed[m.end():]
            result.actions_taken.append(f"Converted {len(matches)} 'uricontent' to 'http.uri; content'")

    # Remove duplicates
    fixed = fix_duplicate_options(fixed, result)
    fixed = fix_content_modifiers(fixed, result)
    fixed = add_fast_pattern(fixed, result)
    
    return cleanup_semicolons(fixed)


def fix_sid(options: str, sid_manager: SIDManager, result: FixResult) -> str:
    """Ensure unique SID"""
    if match := RE_SID.search(options):
        sid = int(match.group(1))
        if sid in sid_manager.used:
            new_sid = sid_manager.generate()
            result.actions_taken.append(f"Replaced duplicate SID {sid} with {new_sid}")
            return re.sub(r'\bsid\s*:\s*\d+', f'sid:{new_sid}', options)
        sid_manager.used.add(sid)
        return options
    
    new_sid = sid_manager.generate()
    result.actions_taken.append(f"Added missing SID: {new_sid}")
    return options.rstrip('; ') + f'; sid:{new_sid}'


# ============================================================================
# RULE RECONSTRUCTION
# ============================================================================

def try_reconstruct_rule(rule: str, result: FixResult) -> Optional[RuleComponents]:
    """Attempt to reconstruct a malformed rule using defaults"""
    rule = rule.strip().rstrip(';').strip()
    
    defaults = {
        'action': 'alert', 'proto': 'tcp', 'src': 'any', 'src_port': 'any',
        'direction': '->', 'dst': 'any', 'dst_port': str(random.choice(COMMON_PORTS)),
        'options': f'msg:"Default message"; sid:{random.randint(*SID_RANGE)}; rev:1'
    }
    
    extracted = {}
    
    # Extract options from parentheses
    if options_match := re.search(r'\((.+)\)\s*;?\s*$', rule):
        extracted['options'] = options_match.group(1)
        rule = rule[:options_match.start()].strip()
    
    tokens = rule.split()
    remaining = []
    all_protocols = VALID_NETWORK_PROTOCOLS | VALID_APP_PROTOCOLS | set(UNSUPPORTED_PROTOCOLS)
    
    for token in tokens:
        token_lower = token.lower()
        
        if token_lower in VALID_ACTIONS or token_lower in INVALID_ACTIONS:
            extracted.setdefault('action', token)
        elif token_lower in all_protocols:
            extracted.setdefault('proto', token)
        elif token in VALID_DIRECTIONS or token == '=>':
            extracted.setdefault('direction', token)
        else:
            remaining.append(token)
    
    # Parse remaining tokens as addr/port pairs
    addr_pattern = re.compile(r'^(\$[A-Z_]+|\[.*\]|any|!?(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?)', re.IGNORECASE)
    port_pattern = re.compile(r'^(any|!?(?:\d+|\[\d+[,:\d\[\]!]+\]|\$[A-Z_]+|\d+:\d*|:\d+))$', re.IGNORECASE)
    
    addr_port_pairs = []
    i = 0
    while i < len(remaining):
        token = remaining[i]
        if addr_pattern.match(token) or token.startswith('!') or token == 'any':
            addr, port = token, 'any'
            if i + 1 < len(remaining) and (port_pattern.match(remaining[i + 1]) or remaining[i + 1].isdigit()):
                port = remaining[i + 1]
                i += 1
            addr_port_pairs.append((addr, port))
        elif port_pattern.match(token) or token.isdigit():
            addr_port_pairs.append(('any', token))
        i += 1
    
    if len(addr_port_pairs) >= 1:
        extracted['src'], extracted['src_port'] = addr_port_pairs[0]
    if len(addr_port_pairs) >= 2:
        extracted['dst'], extracted['dst_port'] = addr_port_pairs[1]
    
    # Merge with defaults
    final = {}
    for key, default_val in defaults.items():
        if key in extracted:
            final[key] = extracted[key]
        else:
            final[key] = default_val
            result.actions_taken.append(f"Added default {key}='{default_val}'")
    
    return RuleComponents(
        action=final['action'], proto=final['proto'],
        src=final['src'], src_port=final['src_port'],
        direction=final['direction'], dst=final['dst'],
        dst_port=final['dst_port'], options=final['options'],
        original=rule
    )

# ============================================================================
# PERFORMANCE FUNCTIONS
# ============================================================================

def is_content_modifier(opt: str) -> bool:
    """Helper to check if an option belongs to the preceding content match."""
    opt_lower = opt.lower()
    if opt_lower in CONTENT_MODIFIERS: return True
    if opt_lower in HTTP1_TO_STICKY: return True
    if any(opt_lower.startswith(prefix) for prefix in ["distance:", "within:", "offset:", "depth:", "fast_pattern:"]):
        return True
    return False

def remove_duplicate_content(options_str: str, result: FixResult = None) -> str:
    """Logic to safely remove redundant duplicate content and its modifiers."""
    # Split safely by semicolon respecting quotes
    options = [opt.strip() for opt in re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', options_str) if opt.strip()]
    
    filtered_options = []
    seen_contents = set()
    current_buffer = "payload"
    removing_current_content = False
    
    for i, opt in enumerate(options):
        opt_lower = opt.lower()
        
        # 1. Update state if we encounter a modern sticky buffer
        if opt_lower in MODERN_STICKY_BUFFERS:
            current_buffer = opt_lower
            removing_current_content = False
            filtered_options.append(opt)
            continue
            
        # 2. Evaluate content matches
        content_match = re.match(r'^content:\s*"([^"]+)"', opt, re.IGNORECASE)
        if content_match:
            val = content_match.group(1)
            
            # Look ahead to gather modifiers belonging to this content
            has_relative = False
            has_nocase = False
            legacy_buf = None
            
            for j in range(i + 1, len(options)):
                next_opt = options[j]
                if not is_content_modifier(next_opt):
                    break # Stop looking ahead when a new unrelated keyword is hit
                
                next_opt_lower = next_opt.lower()
                if next_opt_lower.startswith(('distance:', 'within:', 'offset:', 'depth:')):
                    has_relative = True
                if next_opt_lower == 'nocase':
                    has_nocase = True
                if next_opt_lower in HTTP1_TO_STICKY:
                    legacy_buf = HTTP1_TO_STICKY[next_opt_lower]
            
            # Determine the effective buffer context for this specific match
            eff_buffer = legacy_buf if legacy_buf else current_buffer
            
            # Create our unique signature key for this match
            key = (val, eff_buffer, has_nocase)
            
            # Apply our Removal Logic
            if key in seen_contents and not has_relative:
                removing_current_content = True
                if result:
                    result.actions_taken.append(f"Removed redundant content: '{val}' in {eff_buffer}")
                continue # Skip appending this content
            else:
                seen_contents.add(key)
                removing_current_content = False
                filtered_options.append(opt)
                continue

        # 3. Process modifiers and other rule keywords
        if removing_current_content:
            # If we flagged a content for removal, we must also drop its dependent modifiers
            if is_content_modifier(opt):
                continue # Skip appending the modifier
            else:
                # We reached the end of the modifiers, reset flag and keep option
                removing_current_content = False
                filtered_options.append(opt)
        else:
            filtered_options.append(opt)
            
    return "; ".join(filtered_options) + ";"

def evaluate_content(content_str: str) -> int:
    """
    Scores a content string based on length, entropy, and uniqueness.
    Higher score means it's a better candidate for fast_pattern.
    """
    match = re.search(r'^content:\s*"([^"]+)"', content_str, re.IGNORECASE)
    if not match:
        return -1
    
    val = match.group(1)
    val_lower = val.lower()
    
    # 1. Penalize common/"Must-Have" generic strings
    common_strings = {
        "get", "post", "put", "delete", "head", "options", "connect", "trace",
        "http/1.1", "http/1.0", "user-agent", "host", "accept", "content-length",
        "content-type", "keep-alive"
    }
    if val_lower in common_strings:
        return 0  # Very low score, avoid making this the fast pattern

    score = 0
    true_length = 0
    has_hex = False
    
    # 2. Calculate true length and check for hex (entropy)
    # Find all hex blocks like |3a 20| or |0a|
    hex_blocks = re.findall(r'\|([a-fA-F0-9\s]+)\|', val)
    if hex_blocks:
        has_hex = True
        for block in hex_blocks:
            # Count hex pairs (ignoring spaces) as single bytes
            hex_chars = block.replace(' ', '')
            true_length += len(hex_chars) // 2
    
    # Remove hex blocks to count remaining ASCII characters
    ascii_part = re.sub(r'\|[a-fA-F0-9\s]+\|', '', val)
    true_length += len(ascii_part)
    
    score += true_length
    
    # 3. Apply Bonuses
    if has_hex:
        score += 15  # Massive bonus for hex (high entropy)
        
    if true_length > 14:
        score += 5   # Bonus for long strings
        
    return score

def add_fast_pattern(options_str: str, result: FixResult = None) -> str:
    """If the rule has multiple contents, add 'fast_pattern;' to the best one."""
    # Split options safely by semicolon, respecting quotes
    options = [opt.strip() for opt in re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', options_str) if opt.strip()]
    
    # Check if fast_pattern already exists; if so, skip to avoid duplicates
    if any(re.match(r'^fast_pattern', opt, re.IGNORECASE) for opt in options):
        return options_str

    # Find all content indices
    content_indices = []
    for i, opt in enumerate(options):
        if opt.lower().startswith('content:'):
            content_indices.append(i)
    
    # Only add if there are multiple contents
    if len(content_indices) <= 1:
        return options_str
        
    # Evaluate contents to find the best candidate
    best_index = -1
    highest_score = -1
    
    for idx in content_indices:
        score = evaluate_content(options[idx])
        if score > highest_score:
            highest_score = score
            best_index = idx
            
    # Insert fast_pattern right after the best content
    if best_index != -1:
        options.insert(best_index + 1, "fast_pattern")
        if result:
            result.actions_taken.append(f"Added fast_pattern to content at index {best_index} (Score: {highest_score})")
            
    return "; ".join(options) + ";"

# ============================================================================
# MAIN FIX FUNCTION
# ============================================================================

def fix_rule(rule: str, sid_manager: Optional[SIDManager] = None) -> FixResult:
    """Main function to fix a Suricata rule"""
    result = FixResult(original_rule=rule.strip(), fixed_rule="", is_valid=False)
    
    # Skip empty/comments
    if not rule.strip() or rule.strip().startswith('#'):
        result.fixed_rule = rule.strip()
        result.is_valid = True
        return result
    
    # Parse rule
    components = parse_rule(rule)
    
    if not components:
        # Try stripping trailing semicolon variations
        stripped = rule.strip().rstrip()
        for suffix, action_desc in [(' ;', "Removed trailing ' ;'"), (';', "Removed trailing semicolon")]:
            if stripped.endswith(')' + suffix[0] if suffix == ';' else suffix):
                fixed_rule = stripped[:-len(suffix)]
                if components := parse_rule(fixed_rule):
                    result.actions_taken.append(action_desc)
                    break
        
        # Try reconstruction if still unparseable
        if not components:
            components = try_reconstruct_rule(rule, result)
            if not components:
                result.errors.append("Failed to parse rule")
                result.fixed_rule = rule.strip()
                return result
    
    # Apply fixes
    components.action = fix_action(components.action, result)
    if components.action == "reject" and components.proto.lower() == "udp":
        result.actions_taken.append("Changed 'reject' to 'drop' for UDP")
        components.action = "drop"
    
    components.proto = fix_protocol(components.proto, components.options, result)
    components.direction = fix_direction(components.direction, result)
    components.src = fix_address(components.src, "source", result)
    components.dst = fix_address(components.dst, "destination", result)
    components.src_port = fix_port(components.src_port, "source port", result)
    components.dst_port = fix_port(components.dst_port, "destination port", result)
    components.options = fix_options(components.options, components.proto, result)
    
    if sid_manager:
        components.options = fix_sid(components.options, sid_manager, result)
    
    # Reconstruct
    result.fixed_rule = (
        f"{components.action} {components.proto} {components.src} {components.src_port} "
        f"{components.direction} {components.dst} {components.dst_port} ({components.options})"
    )
    result.is_valid = not result.errors
    return result


# ============================================================================
# FILE PROCESSING & MAIN
# ============================================================================

def process_rules_file(input_path: str, output_path: str = None, verbose: bool = False) -> tuple:
    """Process a rules file, fixing all rules"""
    stats = {'total': 0, 'fixed': 0, 'unchanged': 0, 'failed': 0, 'skipped': 0}
    sid_manager = SIDManager()
    fixed_rules = []
    
    lines = sys.stdin.readlines() if input_path == '-' else open(input_path).readlines()
    
    for line in lines:
        line = line.rstrip('\n\r')
        
        if not line.strip() or line.strip().startswith('#'):
            fixed_rules.append(line)
            stats['skipped'] += 1
            continue
        
        stats['total'] += 1
        rule_result = fix_rule(line, sid_manager)
        
        if rule_result.errors:
            stats['failed'] += 1
            if verbose:
                print(f"ERROR: {rule_result.errors}", file=sys.stderr)
            fixed_rules.extend([f"# FIXME: {rule_result.errors[0]}", f"# {line}"])
        elif rule_result.actions_taken:
            stats['fixed'] += 1
            if verbose:
                print(f"FIXED: {', '.join(rule_result.actions_taken)}", file=sys.stderr)
            fixed_rules.append(rule_result.fixed_rule)
        else:
            stats['unchanged'] += 1
            fixed_rules.append(rule_result.fixed_rule)
    
    output = '\n'.join(fixed_rules)
    if output_path:
        with open(output_path, 'w') as f:
            f.write(output + '\n')
    else:
        print(output)
    
    return stats, fixed_rules


def main():
    parser = argparse.ArgumentParser(
        description='Fix invalid Suricata rules for Suricata 8.0.3 and AWS Network Firewall.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s input.rules -o output.rules
    %(prog)s input.rules --verbose
    echo "alert http2 ..." | %(prog)s -

Fixes applied: Protocol conversions, keyword fixes, duplicate removal,
SID management, address/port variable replacement, syntax corrections.
"""
    )
    parser.add_argument('input', help='Input rules file (use - for stdin)')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--stats', action='store_true', help='Print statistics')
    
    args = parser.parse_args()
    
    try:
        stats, _ = process_rules_file(args.input, args.output, args.verbose)
        if args.stats or args.verbose:
            print(f"\nStatistics: {stats['total']} rules, {stats['fixed']} fixed, "
                  f"{stats['unchanged']} unchanged, {stats['failed']} failed", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
