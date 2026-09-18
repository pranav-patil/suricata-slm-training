#!/usr/bin/env python3
"""Suricata Rule Randomizer - Randomizes rule headers and SIDs for training data generation.
   Protocol mutation enabled (default)
   $ python rule_randomizer.py input.rules

   Protocol mutation disabled
   $ python rule_randomizer.py input.rules --disable-random-protocol
"""

import re
import sys
import random
import argparse
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Tuple, List, Set

# --- Constants ---
SID_RANGE = (1_000_000, 9_999_999)
REV_RANGE = (1, 100)
PORT_RANGE = (1, 65535)
CIDR_MASK_RANGE = (16, 30)

# Precompiled patterns
RULE_PATTERN = re.compile(
    r'^(?P<action>[a-zA-Z]+)\s+'
    r'(?P<proto>[a-zA-Z0-9_-]+)\s+'
    r'(?P<src>[^\s]+)\s+'
    r'(?P<src_port>[^\s]+)\s+'
    r'(?P<dir>->|<>)\s+'
    r'(?P<dst>[^\s]+)\s+'
    r'(?P<dst_port>[^\s]+)\s+'
    r'\((?P<options>.*)\)\s*$'
)
OPTIONS_SPLIT = re.compile(r'(?P<pair>(?:[^;\\"]|\\.|"(?:\\.|[^"])*")+)')
SID_EXTRACT = re.compile(r'\bsid\s*:\s*(\d+)')
PORT_CHECK = re.compile(r'^[\d:]+$')

KEYWORD_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+\s*:')
WORD_PATTERN = re.compile(r'^([a-zA-Z0-9._-]+)')
STANDALONE_MODIFIERS = frozenset({
    # Case Sensitivity
    "nocase",
    # Content & Engine Logic
    "rawbytes", "fast_pattern", "prefilter", "noalert",
    # Sticky Buffers / Data Focus
    "file_data", "pkt_data",
    # HTTP Protocol Buffers
    "http_uri", "http_raw_uri", "http_method", "http_request_line",
    "http_header", "http_raw_header", "http_cookie", "http_user_agent",
    "http_client_body", "http_stat_code", "http_stat_msg", "http_host",
    "http_server_body", "http_response_line",
    # Protocol Specific
    "ftpbounce", "tls_cert_notbefore", "tls_cert_notafter",
    "tls_cert_expired", "tls_cert_valid",
    # DNS
    "dns_query",
})

# Meta keywords are safe to shuffle. 
# Everything else (Payload, Modifiers, Sticky Buffers) is "Logic".
META_KEYWORDS = {
    'msg', 'sid', 'rev', 'gid', 'classtype', 'reference', 
    'priority', 'metadata', 'target', 'requires', 'threshold', 
    'detection_filter', 'tag'
}

# Protocol compatibility groups
PROTOCOL_GROUPS = [
    # Layer 7: Web & Application Data
    ["http", "http2"],
    # Layer 7: Encryption & Handshakes
    ["tls", "ssl", "quic"],
    # Layer 7: File Transfer
    ["ftp", "ftp-data", "nfs", "tftp"],
    # Layer 7: Mail & Messaging
    ["smtp", "imap", "mqtt"],   # pop3 is unsupported
    # Layer 7: Windows / RPC Services
    ["smb", "dcerpc", "krb5"],
    # Layer 7: Infrastructure Services (UDP heavy)
    ["dns", "ntp", "dhcp"],
    # Layer 7: Remote Access & Console
    ["ssh", "rdp", "rfb"],
    # Layer 7: Industrial Control Systems (Existing)
    ["modbus", "dnp3", "enip"],
    # Layer 7: VPN & Key Exchange
    ["ike"],
    # Layer 4: Transport Layer (Generic)
    ["tcp", "udp", "sctp"],
    # Layer 3/4: Network & Special Handling
    ["ip", "ipv6", "icmp"],
    # Suricata Internal / Packet pseudo-protocols
    ["pkthdr", "tcp-pkt", "tcp-stream"]
]

UNIDIRECTIONAL_REQUIRED_KEYWORDS = [
    "http_", "tls.", "dns.", "smtp.", "ftp.", "ssh.", "content", "flow:to_"
]

PROTOCOL_MAP = {
    # Web & Modern App Protocols
    "http.": "http",
    "http_": "http",
    "file_data": "http",
    "uricontent": "http",
    "http2.": "http2",
    "quic.": "quic",
    "ip_": "ip",

    # Encryption & Handshakes
    "tls.": "tls",
    "tls_": "tls",
    "ssl.": "tls",

    # File Transfer
    "ftp.": "ftp",
    "ftp_": "ftp",
    "nfs.": "nfs",
    "tftp.": "tftp",

    # Mail & Messaging
    "smtp.": "smtp",
    "imap.": "imap",
    "pop3.": "tcp", # Unsupported protocol - fallback to TCP
    "mqtt.": "mqtt",

    # Remote Access
    "ssh.": "ssh",
    "ssh_": "ssh",
    "rdp.": "rdp",
    "rfb.": "rfb",

    # Windows / RPC / Auth
    "smb.": "smb",
    "dcerpc": "dcerpc",
    "krb5.": "krb5",

    # Infrastructure Services
    "dns.": "dns",
    "dns_query": "dns",
    "ntp.": "ntp",
    "dhcp.": "dhcp",
    "snmp.": "snmp",

    # VPN & Key Exchange
    "ike.": "ike",
    "ikev2.": "ikev2",

    # Industrial Control Systems
    "modbus.": "modbus",
    "dnp3.": "dnp3",
    "enip.": "enip",

    # Suricata Internal / Packet pseudo-protocols
    "pkthdr": "pkthdr",
    "tcp-pkt": "tcp-pkt",
    "tcp-stream": "tcp-stream"
}

CONTENT_MODIFIERS = frozenset({
    "nocase", "distance", "within", "depth", "offset", 
    "fast_pattern", "endswith", "startswith", "rawbytes"
})

FILE_DATA_PROTOS = frozenset({"http", "smtp", "smb", "nfs"})
DNS_KEYWORDS = frozenset({"dns.query", "dns.opcode"})

CLIENT_KEYWORDS = frozenset({
    "tls.sni", "http.uri", "http.host", "http.method", "http.request_header", 
    "http.request_body", "dns.query", "ssh.software", "quic.sni"
})

SERVER_KEYWORDS = frozenset({
    "tls.certs", "tls.cert_subject", "http.stat_code", "http.response_header", 
    "http.response_body", "tls.version"
})

DIRECTIONAL_MAP = {
    "to_server": ["http.uri", "dns.query", "ssh.hassh", "smtp.mail_from", "quic.sni", "tls.sni", "http.method"],
    "from_server": ["http.stat_code", "tls.certs", "tls.cert_subject", "tls.version"]
}

META_KEYWORDS = frozenset({
    'msg', 'sid', 'rev', 'gid', 'classtype', 'reference', 
    'priority', 'metadata', 'target', 'requires', 'threshold', 
    'detection_filter', 'tag'
})

DIVERSITY_GROUPS = frozenset(["http", "tls", "dns", "smtp", "ftp", "quic", "ssh"])

VALID_HEADER_PROTOCOLS = [
    "http", "ftp", "tls", "smb", "dns", "dcerpc", "dhcp", "ssh", 
    "smtp", "imap", "nfs", "ike", "krb5", "ntp", "rfb", 
    "rdp", "snmp", "tftp", "quic", "mqtt"
]

# PCRE flags that are strictly tied to HTTP buffers
HTTP_PCRE_FLAGS = re.compile(r'([R|U|P|W|H|M|C|S|B])(?=[a-z]*"|")')

# Keywords that should never appear more than once
UNIQUE_KEYWORDS = {"threshold", "detection_filter", "target", "priority", "classtype"}

TRANSPOSITION_MATRIX = {
    "IDENTIFIER": {
        "http": ["http.uri", "http.host"],
        "dns": ["dns.query"],
        "tls": ["tls.sni"],
        "quic": ["quic.sni"],
        "ssh": ["ssh.software"],
    },
    "META": {
        "http": ["http.stat_code"],
        "tls": ["tls.version:1.2", "tls.version:1.3"],
        "ssh": ["ssh.proto"],
    },
    "BODY": {
        "http": ["http.request_body", "file_data"],
        "tls": ["tls.certs"],
        "smtp": ["smtp.mail_from"]
    }
}

# --- Core Logic ---

class ProtocolSwapper:
    def __init__(self):
        self.keyword_to_class = {}
        for cls_name, proto_map in TRANSPOSITION_MATRIX.items():
            for proto_group, keywords in proto_map.items():
                for kw in keywords:
                    self.keyword_to_class[kw.lower()] = cls_name

    def _get_protocol_group(self, proto: str) -> str:
        proto = proto.lower()
        if proto.startswith("http"): return "http"
        if proto in {"tls", "ssl"}: return "tls"
        if proto in {"dns", "mdns"}: return "dns"
        return proto

    def _is_forbidden_buffer(self, keyword: str, target_proto: str) -> bool:
        if keyword == "bsize": return True
        if keyword in DNS_KEYWORDS and target_proto != "dns": return True

        # Prefix Protection
        prefixes = ("http.", "http_", "dns.", "dns_", "tls.", "tls_", "ssl.", "ssl_", "ssh.", "ssh_", "smtp.", "smtp_", "quic.", "quic_", "mdns.", "mdns_")
        if keyword.startswith(prefixes):
            clean_prefix = keyword.split('.')[0].split('_')[0]
            if clean_prefix != target_proto: 
                return True

        # Specific Suricata Engine Restrictions
        if keyword in {"file_data", "file.data"} and target_proto not in FILE_DATA_PROTOS: return True
        if keyword in {"urilen", "uricontent"} and target_proto != "http": return True
        if (keyword.startswith("ja3") or keyword.startswith("ja4")) and target_proto not in {"tls", "ssl"}: return True
        if "dotprefix" in keyword and target_proto not in {"dns", "tls"}: return True
        if keyword.startswith("app-layer-event"): return True
        if keyword in {"quic.uaid", "dns.opcode"}: return True
        if target_proto == "mdns" and keyword.startswith("dns."): return True

        return False

    def _sanitize_pcre(self, pcre_string: str, is_http: bool) -> str:
        """Removes HTTP-specific PCRE flags if the protocol is not HTTP."""
        if is_http:
            return pcre_string
        # Strip flags: R (URI), U (URI), P (Body), W (Host), H (Header), etc.
        return HTTP_PCRE_FLAGS.sub('', pcre_string)

    def swap(self, old_proto: str, logic_sequence: List[str], flows: Set[str]) -> Tuple[str, List[str], Set[str]]:
        target_proto = random.choice([p for p in VALID_HEADER_PROTOCOLS if p != old_proto])
        target_group = self._get_protocol_group(target_proto)
        
        new_logic = []

        for opt in logic_sequence:
            parts = opt.split(':', 1)
            keyword = parts[0].strip().lower()
            kw_class = self.keyword_to_class.get(keyword)
            
            if keyword == "pcre":
                opt = self._sanitize_pcre(opt, target_proto.startswith("http"))
            
            if kw_class and target_group in TRANSPOSITION_MATRIX[kw_class]:
                new_keyword = random.choice(TRANSPOSITION_MATRIX[kw_class][target_group])
                new_logic.append(f"{new_keyword}:{parts[1]}" if len(parts) > 1 else new_keyword)
                
                # Automatically fix flow conflict if introduced directional keyword
                for direction, keywords in DIRECTIONAL_MAP.items():
                    if new_keyword in keywords:
                        flows.add(direction)
                        if direction == "to_server":
                            flows.discard("to_client")
                            flows.discard("from_server")
                        elif direction in {"from_server", "to_client"}:
                            flows.discard("to_server")
            else:
                if not self._is_forbidden_buffer(keyword, target_proto):
                    if keyword == "pcre" and target_proto != "http":
                        opt = re.sub(r'/U(["\']?)$', r'/\1', opt)
                    new_logic.append(opt)

        if target_proto == "smtp" and any(k.split(':', 1)[0].strip().lower() in {"file_data", "file.data"} for k in new_logic):
            flows.discard("from_server")
            flows.discard("to_client")
            flows.add("to_server")
                
        return target_proto, new_logic, flows

class SIDManager:
    """Manages unique SID generation and persistence."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.used: set[int] = set()
        self.new: list[int] = []  # Track new SIDs for batch write
        self._load()
    
    def _load(self):
        if os.path.exists(self.filepath):
            with open(self.filepath) as f:
                self.used = {int(line) for line in f if line.strip().isdigit()}
    
    def generate(self) -> int:
        while True:
            sid = random.randint(*SID_RANGE)
            if sid not in self.used:
                self.used.add(sid)
                self.new.append(sid)
                return sid
    
    def register(self, rule_line: str) -> int | None:
        if match := SID_EXTRACT.search(rule_line):
            sid = int(match.group(1))
            if sid not in self.used:
                self.used.add(sid)
                self.new.append(sid)
            return sid
        return None
    
    def save(self):
        """Write all new SIDs to file at once."""
        if self.new:
            with open(self.filepath, 'a') as f:
                f.writelines(f"{sid}\n" for sid in self.new)
            print(f"Saved {len(self.new)} new SIDs to {self.filepath}")

@dataclass
class ParsedOptions:
    meta_options: list = field(default_factory=list)
    logic_sequence: list = field(default_factory=list)
    flows: Set[str] = field(default_factory=set)
    has_sid: bool = False
    has_rev: bool = False

class RuleRandomizer:
    """Randomizes Suricata rules while preserving detection logic."""
    
    def __init__(self, sid_manager: SIDManager, mutate_proto: bool = True):
        self.sid = sid_manager
        self.swapper = ProtocolSwapper()
        self.mutate_proto = mutate_proto

    """Return True if text starts with a recognisable Suricata keyword."""
    @staticmethod
    def _is_suricata_keyword(text: str) -> bool:
        text = text.strip()
        if not text: return True
        if KEYWORD_PATTERN.match(text): return True
        m = WORD_PATTERN.match(text)
        if m and m.group(1) in STANDALONE_MODIFIERS: return True
        return False

    """
    Split options by semicolon with keyword lookahead.
    Recovers from unbalanced/malformed quotes (e.g. bare quotes inside
    msg: values or extra quotes in PCRE) by forcing a split when the
    remaining text starts with a recognisable Suricata keyword.
    """
    def _robust_split(self, options_block: str) -> list[str]:
        parts, current, in_quotes, escaped = [], [], False, False

        for i, char in enumerate(options_block):
            if escaped:
                current.append(char); escaped = False
            elif char == '\\':
                current.append(char); escaped = True
            elif char == '"':
                in_quotes = not in_quotes; current.append(char)
            elif char == ';':
                remaining = options_block[i + 1:].lstrip()
                if not in_quotes or self._is_suricata_keyword(remaining):
                    if current:
                        parts.append("".join(current).strip())
                    current = []; in_quotes = False
                else:
                    current.append(char)
            else:
                current.append(char)

        if current: parts.append("".join(current).strip())
        return [p for p in parts if p]

    @staticmethod
    def _random_ip() -> str:
        return str(ipaddress.IPv4Address(random.getrandbits(32)))

    @staticmethod
    def _random_cidr() -> str:
        ip = ipaddress.IPv4Address(random.getrandbits(32))
        return str(ipaddress.IPv4Interface(f"{ip}/{random.randint(*CIDR_MASK_RANGE)}").network)

    def _gen_address(self) -> str:
        choice = random.choices(["var", "any", "ip", "cidr", "list"], weights=[30, 20, 30, 15, 5])[0]
        generators = {
            "var": lambda: random.choice(["$HOME_NET", "$EXTERNAL_NET"]),
            "any": lambda: "any",
            "ip": self._random_ip,
            "cidr": self._random_cidr,
            "list": lambda: f"[{self._random_ip()},{self._random_ip()}]",
        }
        return generators.get(choice, lambda: "any")()

    @staticmethod
    def _gen_port() -> str:
        choice = random.choices(["any", "single", "range", "not"], weights=[25, 40, 30, 5])[0]
        if choice == "any":
            return "any"
        if choice == "single":
            return str(random.randint(*PORT_RANGE))
        if choice == "not":
            return f"!{random.randint(*PORT_RANGE)}"
        p1, p2 = random.randint(1024, 30000), random.randint(30001, 65535)
        return random.choice([f":{p1}", f"{p1}:", f"{p1}:{p2}"])

    @staticmethod
    def _gen_protocol(original: str) -> str:
        orig = original.lower().strip()
        for group in PROTOCOL_GROUPS:
            if orig in group:
                return random.choice(group)
        return orig

    def _randomize_value(self, value: str, vtype: str, options: str = "") -> str:
        val = value.strip()
        if val.startswith('$') and random.random() <= 0.8:
            return value
        if val.lower() == 'any' or val.startswith('$') or val.startswith('['):
            return value
        if val.startswith('!') and not val[1:].startswith('$'):
            new_val = self._randomize_value(val[1:], vtype, options)
            if vtype == 'port' and (new_val == 'any' or new_val.startswith('!')):
                return new_val
            return "!" + new_val
        if vtype == 'action':
            return random.choice(["alert", "pass", "drop"])
        if vtype == 'ip':
            return self._gen_address()
        if vtype == 'port' and PORT_CHECK.match(val):
            return self._gen_port()
        if vtype == 'protocol':
            return self._gen_protocol(value)
        if vtype == 'direction':
            if any(kw in options for kw in UNIDIRECTIONAL_REQUIRED_KEYWORDS):
                return "->"
            return random.choice(["->", "<>"])
        return value

    def _parse_options(self, options_str: str) -> ParsedOptions:
        opts = ParsedOptions()

        for opt in self._robust_split(options_str):
            # A keyword is the part before the first ':'
            parts = opt.split(':', 1)
            keyword = parts[0].strip().lower()
            
            if keyword == 'flow':
                if len(parts) > 1:
                    opts.flows.update(f.strip() for f in parts[1].split(','))
                continue
            
            if keyword in META_KEYWORDS:
                if keyword == 'sid':
                    opts.meta_options.append(f"sid:{self.sid.generate()}")
                    opts.has_sid = True
                elif keyword == 'rev':
                    opts.meta_options.append(f"rev:{random.randint(*REV_RANGE)}")
                    opts.has_rev = True
                else:
                    opts.meta_options.append(opt)
            else:
                # This is Logic (content, pcre, sticky buffers, modifiers)
                # We keep them in their original relative order.
                opts.logic_sequence.append(opt)
        
        if not opts.has_sid:
            opts.meta_options.append(f"sid:{self.sid.generate()}")
        if not opts.has_rev:
            opts.meta_options.append(f"rev:1")

        return opts

    def _sanitize_modifiers(self, logic_sequence: List[str]) -> Tuple[List[str], bool, bool]:
        """Cleans up orphaned modifiers and flags client/server keywords."""
        sanitized = []
        has_client, has_server = False, False

        for opt in logic_sequence:
            kw = opt.split(':')[0].lower()
            if kw in CONTENT_MODIFIERS:
                # Skip modifier if no content/pcre precedes it
                if not sanitized or not any(x in sanitized[-1].lower() for x in ["content", "pcre"]):
                    continue 
            
            if kw in CLIENT_KEYWORDS: has_client = True
            if kw in SERVER_KEYWORDS: has_server = True
            sanitized.append(opt)
            
        # Prevent fast_pattern:only conflicts if relative math is present
        has_relative = any(k.split(':')[0].strip().lower() in {'within', 'distance', 'depth', 'offset'} for k in sanitized)
        if has_relative:
            sanitized = ["fast_pattern" if opt.strip().lower() == "fast_pattern:only" else opt for opt in sanitized]

        return sanitized, has_client, has_server

    def _harmonize_flow_and_direction(self, parsed: ParsedOptions, headers: dict, has_client: bool, has_server: bool):
        """Aligns the flow state and network direction based on present keywords."""
        if has_client and has_server: parsed.flows = {"established"}
        elif has_client: parsed.flows = {"established", "to_server"}
        elif has_server: parsed.flows = {"established", "from_server"}
        else: parsed.flows = parsed.flows if parsed.flows else {"established"}

        if "from_server" in parsed.flows and headers['src'] == "$HOME_NET" and headers['dst'] == "$EXTERNAL_NET":
            headers['src'], headers['dst'] = "$EXTERNAL_NET", "$HOME_NET"
        elif "to_server" in parsed.flows and headers['src'] == "$EXTERNAL_NET" and headers['dst'] == "$HOME_NET":
            headers['src'], headers['dst'] = "$HOME_NET", "$EXTERNAL_NET"

    def _clean_semantics(self, parsed_rule, proto):
        """Final pass to fix Sticky Buffer and Flow issues."""
        
        # 1. Deduplicate Unique Keywords (Keep the last one)
        seen_unique = set()
        final_logic = []
        for opt in reversed(parsed_rule.logic_sequence):
            kw = opt.split(':')[0].lower()
            if kw in UNIQUE_KEYWORDS:
                if kw in seen_unique: continue
                seen_unique.add(kw)
            final_logic.append(opt)
        parsed_rule.logic_sequence = list(reversed(final_logic))

        # 2. Fix Flow Redundancy (from_client/to_server conflict)
        if "to_server" in parsed_rule.flows and "from_client" in parsed_rule.flows:
            parsed_rule.flows.discard("from_client")
        if "from_server" in parsed_rule.flows and "to_client" in parsed_rule.flows:
            parsed_rule.flows.discard("to_client")

        # 3. Strip HTTP PCRE flags if not HTTP
        if not proto.startswith("http"):
            parsed_rule.logic_sequence = [
                HTTP_PCRE_FLAGS.sub('', opt) if opt.startswith("pcre") else opt 
                for opt in parsed_rule.logic_sequence
            ]

    def _assemble_options(self, opts: ParsedOptions) -> str:
        # Start with the logic sequence as the base (order is preserved)
        final_list = list(opts.logic_sequence)
        
        # Shuffle the meta options first so their relative order is also random
        random.shuffle(opts.meta_options)
        
        # Interleave: For every meta keyword, pick a random slot in the current list
        # Slots available = len(final_list) + 1 (includes start and end)
        for meta in opts.meta_options:
            insert_idx = random.randint(0, len(final_list))
            final_list.insert(insert_idx, meta)
            
        return "; ".join(final_list) + ";"
    
    # --- Main Randomization ---
    def randomize(self, rule_line: str) -> str | None:
        match = RULE_PATTERN.match(rule_line.strip())
        if not match: return None
        
        p = match.groupdict()
        options_block = p['options']
        current_proto = p['proto']
        
        # 2. Randomize Header Values
        p['action'] = self._randomize_value(p['action'], 'action')            
        p['src'] = self._randomize_value(p['src'], 'ip')
        p['dst'] = self._randomize_value(p['dst'], 'ip')
        p['src_port'] = self._randomize_value(p['src_port'], 'port')
        p['dst_port'] = self._randomize_value(p['dst_port'], 'port')
        
        # Updated: Direction now considers the protocol and options
        p['dir'] = self._randomize_value(p['dir'], 'direction', options_block)
        
        # Process options
        opts = self._parse_options(options_block)
        
        # Randomize protocol but enforce compatibility if certain keywords are present
        if self.mutate_proto:
            if current_proto in DIVERSITY_GROUPS:
                current_proto, opts.logic_sequence, opts.flows = self.swapper.swap(
                    current_proto, opts.logic_sequence, opts.flows
                )

            # Apply semantics rules natively
            opts.logic_sequence, has_client, has_server = self._sanitize_modifiers(opts.logic_sequence)
            self._harmonize_flow_and_direction(opts, p, has_client, has_server)
            self._clean_semantics(opts, current_proto)
            
            # Assemble the final options
            if opts.flows:
                opts.meta_options.append(f"flow:{','.join(sorted(opts.flows))}")
        
        opts_str = self._assemble_options(opts)
        
        # Random spacing before parenthesis
        space = random.choice([" (", " ( "])
        
        return f"{p['action']} {current_proto} {p['src']} {p['src_port']} {p['dir']} {p['dst']} {p['dst_port']}{space}{opts_str})"


def process_file(input_path: str, output_path: str, randomizer: RuleRandomizer) -> tuple[int, int]:
    """Process rules file and return (processed_count, error_count)."""
    processed = errors = 0
    
    with open(input_path) as infile, open(output_path, 'w') as outfile:
        for line in infile:
            line = line.strip()
            
            if not line or line.startswith('#'):
                outfile.write(line + "\n")
                continue
            
            try:
                if result := randomizer.randomize(line):
                    outfile.write(result + "\n")
                    processed += 1
                else:
                    sys.stderr.write(f"Warning: Parse error: {line[:40]}...\n")
                    randomizer.sid.register(line)
                    outfile.write(line + "\n")
                    errors += 1
            except Exception as e:
                sys.stderr.write(f"Error: {line[:40]}... -> {e}\n")
                randomizer.sid.register(line)
                outfile.write(line + "\n")
                errors += 1
    
    return processed, errors


def main():
    parser = argparse.ArgumentParser(description="Suricata Rule Randomizer")
    parser.add_argument("file", help="Input rules file")
    parser.add_argument("--disable-random-protocol", action="store_true",
                        help="Disable protocol mutation (keep original protocols)")
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        sys.exit(f"Error: File {args.file} not found.")
    
    # Setup paths
    dir_name = os.path.dirname(args.file) or '.'
    base, ext = os.path.splitext(os.path.basename(args.file))
    output_name = f"{base}{ext}" if base.endswith("_random") else f"{base}_random{ext}"
    output_path = os.path.join(dir_name, output_name)
    sids_path = os.path.join(dir_name, 'sids.txt')
    
    # Initialize and process
    sid_manager = SIDManager(sids_path)
    randomizer = RuleRandomizer(sid_manager, mutate_proto=not args.disable_random_protocol)
    
    print(f"Loaded {len(sid_manager.used)} existing SIDs")
    print(f"Processing: {args.file}")
    
    processed, errors = process_file(args.file, output_path, randomizer)
    
    # Save all new SIDs at once
    sid_manager.save()
    
    print("-" * 40)
    print(f"Output: {output_path}")
    print(f"Processed: {processed} | Errors: {errors}")


if __name__ == "__main__":
    main()