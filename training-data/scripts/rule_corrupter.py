#!/usr/bin/env python3
"""
Suricata Rule Corrupter for Training Data Generation

Intentionally introduces common errors into valid Suricata rules to create
training pairs for machine learning models that fix Suricata rule errors.

Error Categories:
1. Syntax breakage - semicolons, parentheses, PCRE, misspellings
2. Version mismatch - legacy modifiers, deprecated keywords
3. Protocol/hook errors - wrong hooks, mismatched app-layer keywords
4. Logic errors - flowbits, double negation, packet/stream mixing

Usage:
    python rule_corrupter.py input.rules -o output.rules
    python rule_corrupter.py input.rules --errors 2
    
Programmatic usage:
    corruptor = SuricataCorruptor()
    bad_rule = corruptor.corrupt_rule(rule, num_errors=2)
"""

import re
import random
import string
import sys
import argparse
from typing import Callable, Optional

# ============================================================================
# CONFIGURATION & MAPPINGS
# ============================================================================

# Sticky buffer -> Legacy modifier mapping (for version downgrade)
STICKY_TO_LEGACY = {
    "http.uri": "http_uri",
    "http.uri.raw": "http_raw_uri", 
    "http.method": "http_method",
    "http.user_agent": "http_user_agent",
    "http.host": "http_host",
    "http.host.raw": "http_raw_host",
    "http.cookie": "http_cookie",
    "http.header": "http_header",
    "http.header.raw": "http_raw_header",
    "http.request_body": "http_client_body",
    "http.stat_code": "http_stat_code",
    "http.stat_msg": "http_stat_msg",
    "dns.query": "dns_query",
    "tls.sni": "tls_sni",
    "tls.cert_subject": "tls_cert_subject",
    "tls.cert_issuer": "tls_cert_issuer",
    "ssh.proto": "ssh_proto",
    "ssh.software": "ssh_software",
}

# Modern keywords -> deprecated versions
DEPRECATED_KEYWORDS = {
    "tls.sni": "ssl_sni",
    "tls.version": "ssl_version",
    "tls.cert_subject": "ssl_cert_subject",
}

# Valid actions that can be corrupted
VALID_ACTIONS = ["alert", "drop", "pass", "reject"]

# Packet-level keywords (incompatible with tcp-stream/flow:only_stream)
PACKET_KEYWORDS = ["dsize", "pkt_len", "ttl", "tos", "id", "fragbits", "fragoffset", "seq", "ack", "window"]

# Expanded keyword list for Suricata 8 logic
TARGET_KEYWORDS = [
    "content", "reference", "metadata", "classtype", "flowbits", 
    "threshold", "detection_filter", "pcre", "byte_test", 
    "distance", "within", "depth", "offset", "nocase", 
    "fast_pattern", "rev", "sid", "http.uri", "http.method"
]

# Protocol -> incompatible keywords mapping  
PROTOCOL_KEYWORD_MISMATCH = {
    "dns": ["http.uri", "http.method", "http.header", "http_uri", "http_method"],
    "http": ["dns.query", "dns.opcode", "tls.sni", "tls.cert_subject"],
    "tls": ["http.uri", "http.method", "dns.query"],
    "tcp": [],  # TCP is generic, harder to mismatch
    "udp": ["flow:established"],  # UDP doesn't have established
}

# Classtypes to inject (unsupported by AWS)
CLASSTYPES = [
    "trojan-activity", "policy-violation", "attempted-admin",
    "attempted-user", "bad-unknown", "web-application-attack",
]


# ============================================================================
# SURICATA CORRUPTOR CLASS
# ============================================================================

class SuricataCorruptor:
    """
    Intentionally corrupts valid Suricata rules for ML training data generation.
    
    Usage:
        corruptor = SuricataCorruptor()
        bad_rule = corruptor.corrupt_rule(rule, num_errors=2)
    """
    
    # Category weights for corruption selection
    CATEGORY_WEIGHTS = {
        'syntax': [
            ('corrupt_remove_semicolon', 1.5),
            ('corrupt_add_semicolon', 1.0),
            ('corrupt_add_pipe', 1.0),
            ('corrupt_remove_parenthesis', 0.8),
            ('corrupt_misplace_parenthesis', 0.5),
            ('corrupt_pcre_syntax', 1.0),
            ('corrupt_double_negation', 1.0),
            ('corrupt_misspelling', 1.5),
            ('corrupt_duplicate_keywords', 0.8),
            ('corrupt_heavy_rule', 0.2),
            ('corrupt_unescaped_quote', 1.2),
            ('corrupt_malformed_hex_code', 1.2),
            ('corrupt_unclosed_address_block', 1.0),
            ('corrupt_unknown_keyword', 0.1),
            ('corrupt_unopened_address_block', 1.0),
            ('corrupt_unsupported_quotes', 1.0),
        ],
        'version': [
            ('corrupt_sticky_to_legacy', 2.0),
            ('corrupt_mix_sticky_and_legacy', 1.5),
            ('corrupt_mixed_buffer_styles', 1.0),
            ('corrupt_use_deprecated', 1.0),
            ('corrupt_underscore_to_dash', 0.8),
            ('corrupt_rawbytes_sticky_conflict', 1.0),
        ],
        'protocol': [
            ('corrupt_protocol_mismatch', 1.5),
            ('corrupt_explicit_hooks', 1.5),
            ('corrupt_wrong_explicit_hook', 1.0),
            ('corrupt_invalid_proto', 0.5),
            ('corrupt_protocol_keyword_mismatch', 1.0),
            ('corrupt_invalid_action', 1.0),
            ('corrupt_negated_any_address', 1.0),
            ('corrupt_negate_port', 1.0),
            ('corrupt_transactional_firewall', 1.0),
            ('corrupt_frame_proto_mismatch', 1.0),
            ('corrupt_shorthand_frame_error', 1.0),
            ('corrupt_mixed_directions', 1.2),
            ('corrupt_port_negation_nil', 1.0),
            ('corrupt_addr_negation_nil', 1.0),
            ('corrupt_mix_pkt_frame', 1.0),
        ],
        'logic': [
            ('corrupt_flowbits_logic', 1.2),
            ('corrupt_packet_stream_mix', 1.0),
            ('corrupt_add_classtype', 1.5),
            ('corrupt_add_gid', 0.8),
            ('corrupt_invalid_variable', 1.0),
            ('corrupt_ja3_flow_direction', 0.8),
            ('corrupt_content_pipes', 1.0),
            ('corrupt_flowbit_spaces', 1.0),
            ('corrupt_flowbit_isset_isnotset', 1.0),
            ('corrupt_conflicting_flow_flags', 1.2),
            ('corrupt_multiple_dsizes', 1.0),
            ('corrupt_negative_range_order', 0.8),
            ('corrupt_byte_jump_conflict', 0.8),
            ('corrupt_byte_extract_limit', 0.8),
            ('corrupt_count_out_of_range', 1.0),
            ('corrupt_absent_misplaced', 1.0),
            ('corrupt_dataset_non_sticky', 1.0),
            ('corrupt_conflicting_target', 1.0),
            ('corrupt_invalid_action_scope', 1.0),
            ('corrupt_flowbits_no_name', 1.0),
            ('corrupt_ipproto_conflict', 1.0),
        ],
        'content': [
            ('corrupt_nocase_with_value', 1.0),
            ('corrupt_depth_smaller_than_content', 1.2),
            ('corrupt_startswith_no_content', 1.0),
            ('corrupt_pcre_relative_no_match', 1.0),
            ('corrupt_pcre_uppercase_hostname', 0.8),
            ('corrupt_prefilter_multi', 1.0),
            ('corrupt_prefilter_negated', 1.0),
            ('corrupt_transform_misplaced', 1.0),
            ('corrupt_transform_unconsumed', 1.0),
            ('corrupt_dsize_content_contradiction', 1.2),
            ('corrupt_fast_pattern_math', 1.0),
        ],
        'sid': [
            ('corrupt_duplicated_key_fields', 1.5),
            ('corrupt_sid_zero', 1.2),
            ('corrupt_missing_key_fields', 1.5),
            ('corrupt_invalid_numeric_value', 1.0),
        ],
        'content': [
            ('corrupt_nocase_with_value', 1.0),
            ('corrupt_depth_smaller_than_content', 1.2),
            ('corrupt_startswith_no_content', 1.0),
            ('corrupt_pcre_relative_no_match', 1.0),
            ('corrupt_pcre_uppercase_hostname', 0.8),
            ('corrupt_prefilter_multi', 1.0),
            ('corrupt_prefilter_negated', 1.0),
            ('corrupt_transform_misplaced', 1.0),
            ('corrupt_transform_unconsumed', 1.0),
            ('corrupt_dsize_content_contradiction', 1.2),
            ('corrupt_fast_pattern_math', 1.0),
            ('corrupt_fast_pattern_only_relative', 1.0),
            ('corrupt_mix_absolute_relative_modifiers', 1.0),
            ('corrupt_remove_sticky_buffer', 1.0),
            ('corrupt_urilen_with_http_uri', 1.0),
        ],
    }
    
    def __init__(self):
        """Initialize the corruptor with weighted corruption methods."""
        self._corruptors = self._build_corruptors()
    
    def _build_corruptors(self) -> list[tuple[Callable, float]]:
        """Build list of corruption methods with their weights."""
        corruptors = []
        for category, methods in self.CATEGORY_WEIGHTS.items():
            for method_name, weight in methods:
                method = getattr(self, method_name)
                corruptors.append((method, weight))
        return corruptors
    
    def corrupt_rule(self, rule: str, num_errors: Optional[int] = None) -> str:
        """
        Apply random corruptions to a single rule.
        
        Args:
            rule: Valid Suricata rule string
            num_errors: Number of errors to inject (default: random 1-3)
            
        Returns:
            Corrupted rule string
        """
        if not rule.strip() or rule.strip().startswith('#'):
            return rule
        
        # Determine number of errors (1-3 by default)
        if num_errors is None:
            num_errors = random.choices([1, 2, 3], weights=[0.4, 0.4, 0.2])[0]
        
        # Select corruptors based on weights
        funcs, weights = zip(*self._corruptors)
        chosen = random.choices(funcs, weights=weights, k=min(num_errors, len(funcs)))
        
        corrupted = rule
        applied = []
        
        for func in chosen:
            try:
                new_rule = func(corrupted)
                if new_rule != corrupted:
                    corrupted = new_rule
                    applied.append(func.__name__)
            except Exception:
                continue
        
        # Fallback if no corruption applied
        if corrupted == rule:
            corrupted = self.corrupt_remove_semicolon(rule)
            if corrupted == rule:
                corrupted = self.corrupt_misspelling(rule)
        
        return corrupted
    
    def get_categories(self) -> dict:
        """Return the corruption categories and their methods with weights."""
        return self.CATEGORY_WEIGHTS.copy()
    
    # ========================================================================
    # SYNTAX BREAKAGE CORRUPTIONS
    # ========================================================================
    
    def corrupt_remove_semicolon(self, rule: str) -> str:
        """Remove a random mandatory semicolon from the options section."""
        match = re.search(r'\(([^)]+)\)', rule)
        if not match:
            return rule
        
        options = match.group(1)
        parts = options.split(';')
        
        if len(parts) > 2:
            idx = random.randint(0, len(parts) - 2)
            parts[idx] = parts[idx] + parts[idx + 1]
            del parts[idx + 1]
            new_options = ';'.join(parts)
            return rule[:match.start(1)] + new_options + rule[match.end(1):]
        
        return rule

    def corrupt_add_semicolon(self, rule: str) -> str:
        """Insert unescaped semicolon inside msg, content, or pcre field."""
        patterns = [
            (r'(content\s*:\s*")([^"]+)(")', 3),
            (r'(msg\s*:\s*")([^"]+)(")', 5),
            (r'(pcre\s*:\s*")([^"]+)(")', 5),
        ]
        random.shuffle(patterns)
        for pattern, min_len in patterns:
            match = re.search(pattern, rule)
            if match and len(match.group(2)) > min_len:
                value = match.group(2)
                pos = random.randint(1, len(value) - 1)
                corrupted = value[:pos] + ';' + value[pos:]
                return rule[:match.start(2)] + corrupted + rule[match.end(2):]
        return rule

    def corrupt_remove_parenthesis(self, rule: str) -> str:
        """Remove opening or closing parenthesis."""
        choice = random.choice(['open', 'close', 'both'])
        if choice == 'open':
            return rule.replace('(', '', 1)
        elif choice == 'close':
            idx = rule.rfind(')')
            if idx > 0:
                return rule[:idx] + rule[idx+1:]
        else:
            return rule.replace('(', '', 1).replace(')', '', 1)
        return rule

    def corrupt_misplace_parenthesis(self, rule: str) -> str:
        """Move parenthesis to wrong location."""
        match = re.search(r'\)\s*;?\s*$', rule)
        if match:
            options_match = re.search(r'\(([^)]+)\)', rule)
            if options_match and len(options_match.group(1)) > 20:
                options = options_match.group(1)
                cut_point = len(options) - random.randint(5, 15)
                return rule[:options_match.start(1)] + options[:cut_point] + ')' + options[cut_point:] + ';'
        return rule

    def corrupt_pcre_syntax(self, rule: str) -> str:
        """Corrupt PCRE to use PCRE1 or invalid syntax."""
        corruptions = [
            (r'\bpcre\s*:', 'pcre1:'),
            (r'pcre\s*:\s*"/', 'pcre:"#'),
            (r'/([imsxAEGRUBPQHMCOIDKYS]*)"', r'\1"'),
            (r'/(i?)"', r'/iG"'),
        ]
        
        if 'pcre:' in rule or 'pcre :' in rule:
            old, new = random.choice(corruptions)
            return re.sub(old, new, rule, count=1)
        return rule

    def corrupt_double_negation(self, rule: str) -> str:
        """Add double negation (!!) or !any to ports/addresses."""
        corruptions = [
            (r'\bany\b', '!any'),
            (r'!\[', '!!['),
            (r'!(\d+)', r'!!\1'),
            (r'!\$', '!!$'),
        ]
        
        old, new = random.choice(corruptions)
        return re.sub(old, new, rule, count=1)

    @staticmethod
    def _mutate_word(word: str) -> str:
        """Mutates a word with a dynamic number of changes based on length."""
        length = len(word)
        
        if length < 3:
            max_changes = 1
        elif 3 <= length < 6:
            max_changes = 2
        elif 6 <= length < 10:
            max_changes = 3
        else:
            max_changes = 3

        word_list = list(word)
        num_actual_changes = random.randint(1, max_changes)
        
        for _ in range(num_actual_changes):
            if not word_list:
                break
            
            error_type = random.choice(['delete', 'swap', 'replace', 'insert'])
            idx = random.randint(0, len(word_list) - 1)
            
            if error_type == 'delete' and len(word_list) > 1:
                word_list.pop(idx)
            elif error_type == 'swap' and idx < len(word_list) - 1:
                word_list[idx], word_list[idx+1] = word_list[idx+1], word_list[idx]
            elif error_type == 'replace':
                word_list[idx] = random.choice(string.ascii_lowercase)
            elif error_type == 'insert':
                word_list.insert(idx, random.choice(string.ascii_lowercase))
                
        return "".join(word_list)

    def corrupt_misspelling(self, rule: str) -> str:
        """Introduce dynamic typos in Suricata keywords with length-based scaling."""
        found_keywords = list(set(k for k in TARGET_KEYWORDS if k.lower() in rule.lower()))
        
        if not found_keywords:
            return rule

        target = random.choice(found_keywords)
        typo = self._mutate_word(target)
        
        pattern = re.compile(re.escape(target), re.IGNORECASE)
        return pattern.sub(typo, rule, count=1)

    def corrupt_duplicate_keywords(self, rule: str) -> str:
        """Duplicate a keyword creating invalid rule."""
        keywords = ['sid:', 'rev:', 'msg:', 'flow:', 'metadata:']
        for kw in keywords:
            if kw in rule:
                match = re.search(rf'({kw}\s*[^;]+;)', rule)
                if match:
                    return rule[:match.end()] + ' ' + match.group(1) + rule[match.end():]
        return rule

    def corrupt_heavy_rule(self, rule: str) -> str:
        """Make rule overly broad (any any -> any any)."""
        rule = re.sub(r'\$HOME_NET', 'any', rule)
        rule = re.sub(r'\$EXTERNAL_NET', 'any', rule)
        rule = re.sub(r'\b\d+\b(?=\s+[-<>])', 'any', rule)
        rule = re.sub(r'(?<=[-<>]\s)\b\d+\b', 'any', rule)
        return rule

    # ========================================================================
    # VERSION MISMATCH CORRUPTIONS
    # ========================================================================

    def corrupt_sticky_to_legacy(self, rule: str) -> str:
        """
        Convert Suricata 8 sticky buffer syntax to legacy modifier style.
        Suricata 8: http.uri; content:"/admin";
        Legacy: content:"/admin"; http_uri;
        """
        for sticky, legacy in STICKY_TO_LEGACY.items():
            pattern = re.compile(
                re.escape(sticky) + r'\s*;\s*(content\s*:\s*"[^"]+")\s*;',
                re.IGNORECASE
            )
            match = pattern.search(rule)
            if match:
                content_part = match.group(1)
                replacement = f'{content_part}; {legacy};'
                return rule[:match.start()] + replacement + rule[match.end():]
        return rule

    def corrupt_mix_sticky_and_legacy(self, rule: str) -> str:
        """Mix sticky buffers with legacy modifiers in same rule."""
        if 'http.uri;' in rule:
            return rule.replace('http.uri;', 'http.uri; http_header;', 1)
        elif 'http.header;' in rule:
            return rule.replace('http.header;', 'http.header; http_uri;', 1)
        
        if 'content:' in rule and 'http' not in rule.lower():
            match = re.search(r'(content\s*:\s*"[^"]+")\s*;', rule)
            if match:
                return rule[:match.end()] + ' http.uri; http_method;' + rule[match.end():]
        return rule

    def corrupt_use_deprecated(self, rule: str) -> str:
        """Replace modern keywords with deprecated versions."""
        for modern, deprecated in DEPRECATED_KEYWORDS.items():
            if modern in rule:
                return rule.replace(modern, deprecated, 1)
        
        deprecated_injections = [
            'ssl_version:tls1.2;',
            'ssl_state:client_hello;',
            'http_uri;',
        ]
        
        if 'sid:' in rule:
            injection = random.choice(deprecated_injections)
            return re.sub(r'(sid\s*:\s*\d+\s*;)', injection + r' \1', rule, count=1)
        return rule

    def corrupt_underscore_to_dash(self, rule: str) -> str:
        """Convert underscore logging format to dash (deprecated)."""
        replacements = [
            ('app_layer_event', 'app-layer-event'),
            ('security_result', 'security-result'),
        ]
        for new, old in replacements:
            if new in rule:
                return rule.replace(new, old, 1)
        return rule

    # ========================================================================
    # PROTOCOL/HOOK ERRORS
    # ========================================================================

    def corrupt_protocol_mismatch(self, rule: str) -> str:
        """Create protocol and keyword mismatches."""
        proto_match = re.match(r'^(alert|drop|pass|reject)\s+(\w+)', rule)
        if not proto_match:
            return rule
        
        proto = proto_match.group(2).lower()
        
        if proto in PROTOCOL_KEYWORD_MISMATCH:
            bad_keywords = PROTOCOL_KEYWORD_MISMATCH.get(proto, [])
            if bad_keywords:
                bad_kw = random.choice(bad_keywords)
                return re.sub(r'(sid\s*:\s*)', f'{bad_kw}; \\1', rule, count=1)
        
        if 'http.uri' in rule or 'http_uri' in rule:
            return re.sub(r'^(alert|drop|pass|reject)\s+\w+', r'\1 dns', rule)
        elif 'dns.query' in rule:
            return re.sub(r'^(alert|drop|pass|reject)\s+\w+', r'\1 http', rule)
        
        return rule

    def corrupt_explicit_hooks(self, rule: str) -> str:
        """
        Corrupt Suricata 8 explicit protocol hooks.
        Suricata 8: alert http:request ...  
        Corrupt to: alert tcp ... (creates mismatch with http keywords)
        """
        rule = re.sub(r'^(alert|drop|pass|reject)\s+\w+:\w+', r'\1 tcp', rule)
        
        if random.choice([True, False]):
            rule = re.sub(r'^(alert|drop|pass|reject)\s+http\b', r'\1 http:response', rule)
            rule = re.sub(r'^(alert|drop|pass|reject)\s+dns\b', r'\1 dns:response', rule)
        
        return rule

    def corrupt_wrong_explicit_hook(self, rule: str) -> str:
        """Use incorrect explicit hooks for the keywords present."""
        if 'http.uri' in rule or 'http.method' in rule or 'to_server' in rule:
            return re.sub(r'^(alert|drop|pass|reject)\s+http\b', r'\1 http:response', rule)
        elif 'http.stat_code' in rule or 'to_client' in rule:
            return re.sub(r'^(alert|drop|pass|reject)\s+http\b', r'\1 http:request', rule)
        return rule

    # ========================================================================
    # LOGIC/SEMANTIC ERRORS
    # ========================================================================

    def corrupt_flowbits_logic(self, rule: str) -> str:
        """Break flowbits logic in various ways."""
        corruptions = [
            (r'flowbits\s*:\s*set\s*,', 'flowbits:isset,'),
            (r'flowbits\s*:\s*set\s*,', 'flowbits:unset,'),
            (r'flowbits\s*:\s*(set|isset|unset)\s*,\s*[^;]+', r'flowbits:\1'),
            (r'flowbits\s*:\s*set', 'flowbits:toggle'),
        ]
        
        if 'flowbits' in rule:
            old, new = random.choice(corruptions)
            return re.sub(old, new, rule, count=1)
        else:
            return re.sub(r'(sid\s*:\s*)', 'flowbits:isset,undefined_bit; \\1', rule, count=1)

    def corrupt_packet_stream_mix(self, rule: str) -> str:
        """Mix packet-level keywords with stream-only rules."""
        if 'tcp-stream' in rule or 'flow:only_stream' in rule:
            bad_kw = random.choice(PACKET_KEYWORDS)
            return re.sub(r'(sid\s*:\s*)', f'{bad_kw}:100; \\1', rule, count=1)
        
        for kw in PACKET_KEYWORDS:
            if kw in rule:
                return re.sub(r'^(alert|drop|pass|reject)\s+tcp\b', r'\1 tcp-stream', rule)
        
        return rule

    def corrupt_add_classtype(self, rule: str) -> str:
        """Add classtype (unsupported by AWS Network Firewall)."""
        if 'classtype' not in rule:
            classtype = random.choice(CLASSTYPES)
            return re.sub(r'(sid\s*:\s*)', f'classtype:{classtype}; \\1', rule, count=1)
        return rule

    def corrupt_add_gid(self, rule: str) -> str:
        """Add gid (often needs removal for AWS)."""
        if 'gid:' not in rule:
            gid = random.randint(1, 100)
            return re.sub(r'(sid\s*:\s*)', f'gid:{gid}; \\1', rule, count=1)
        return rule

    def corrupt_invalid_variable(self, rule: str) -> str:
        """Use unsupported network variables."""
        invalid_vars = ['$DNS_SERVERS', '$SMTP_SERVERS', '$SQL_SERVERS', '$TELNET_SERVERS', '$HTTP_SERVERS']
        var = random.choice(invalid_vars)
        
        if '$HOME_NET' in rule:
            return rule.replace('$HOME_NET', var, 1)
        elif '$EXTERNAL_NET' in rule:
            return rule.replace('$EXTERNAL_NET', var, 1)
        return rule

    def corrupt_ja3_flow_direction(self, rule: str) -> str:
        """Create JA3/JA3S flow direction mismatches."""
        if 'ja3.hash' in rule and 'ja3s' not in rule:
            return rule.replace('to_server', 'to_client')
        elif 'ja3s.hash' in rule:
            return rule.replace('to_client', 'to_server')
        return rule

    def corrupt_content_pipes(self, rule: str) -> str:
        """Add backslash before pipes in hex notation (common error)."""
        pattern = r'(content\s*:\s*")([^"]*\|[0-9a-fA-F]{2}[^"]*)'
        match = re.search(pattern, rule)
        if match:
            value = match.group(2)
            corrupted = value.replace('|', '\\|', 1)
            return rule[:match.start(2)] + corrupted + rule[match.end(2):]
        return rule

    # ========================================================================
    # NEW SYNTAX ERRORS (from rule_corrupter2.py)
    # ========================================================================

    def corrupt_unescaped_quote(self, rule: str) -> str:
        """Triggers: 'Invalid unescaped double quote within content section.'"""
        pattern = r'(content\s*:\s*")([^"]+)(")'
        match = re.search(pattern, rule)
        if match and len(match.group(2)) > 4:
            value = match.group(2)
            pos = len(value) // 2
            corrupted = value[:pos] + '"' + value[pos:]  # Insert unescaped quote
            return rule[:match.start(2)] + corrupted + rule[match.end(2):]
        return rule

    def corrupt_malformed_hex_code(self, rule: str) -> str:
        """Triggers: 'Incomplete hex code in content' or 'Invalid hex code'."""
        # Generate random invalid hex (1-4 bytes)
        num_bytes = random.randint(1, 4)
        hex_parts = []
        
        for _ in range(num_bytes):
            error_type = random.choice(['invalid_char', 'incomplete'])
            if error_type == 'invalid_char':
                # Use invalid hex character (G-Z)
                invalid_char = random.choice('GHIJKLMNOPQRSTUVWXYZ')
                valid_char = random.choice('0123456789ABCDEF')
                hex_parts.append(f'{valid_char}{invalid_char}')
            else:
                # Incomplete/odd digits (single character)
                hex_parts.append(random.choice('0123456789ABCDEF'))
        
        invalid_hex = ' '.join(hex_parts)
        return re.sub(r'(sid\s*:\s*)', f'content:"|{invalid_hex}|"; \\1', rule, count=1)

    def corrupt_unclosed_address_block(self, rule: str) -> str:
        """Triggers: 'not every address block was properly closed'."""
        # Remove closing bracket from address group
        if '[$' in rule:
            return rule.replace('[$', '[', 1)
        # Or add unclosed bracket
        return re.sub(r'\$HOME_NET', '[192.168.1.0/24', rule, count=1)

    def corrupt_unknown_keyword(self, rule: str) -> str:
        """Inject a truly random unknown/invalid keyword."""
        # Generate random length between 3 and 12
        length = random.randint(3, 12)
        # Build random keyword with alphabetic chars and underscores
        chars = string.ascii_lowercase + '_'
        # Ensure first char is alphabetic (not underscore)
        kw = random.choice(string.ascii_lowercase)
        kw += ''.join(random.choice(chars) for _ in range(length - 1))
        return re.sub(r'(sid\s*:\s*)', f'{kw}; \\1', rule, count=1)

    # ========================================================================
    # NEW PROTOCOL ERRORS
    # ========================================================================

    def corrupt_invalid_proto(self, rule: str) -> str:
        """Inject protocol variants that may cause issues (http_any, http1)."""
        invalid_protos = ['http_any', 'http1', 'http2', 'ssl', 'tcp-pkt', 'ftp2']
        proto = random.choice(invalid_protos)
        return re.sub(r'^(alert|drop|pass|reject)\s+\w+', f'\\1 {proto}', rule)

    def corrupt_invalid_action(self, rule: str) -> str:
        """Triggers: 'accept' action only supported for firewall rules."""
        return re.sub(r'^(alert|drop|pass|reject)', 'accept', rule)

    def corrupt_negated_any_address(self, rule: str) -> str:
        """Triggers: negated 'any' address is invalid."""
        return re.sub(r'\bany\b(?=\s+any\s+->)', '!any', rule, count=1)

    # ========================================================================
    # NEW VERSION/MODIFIER ERRORS
    # ========================================================================

    def corrupt_rawbytes_sticky_conflict(self, rule: str) -> str:
        """Triggers: 'rawbytes cannot be combined with sticky buffer'."""
        # Get random sticky buffer from STICKY_TO_LEGACY
        sticky_buffers = list(STICKY_TO_LEGACY.keys())
        sticky_buffer = random.choice(sticky_buffers)
        
        # Check if any sticky buffer exists in rule
        has_sticky = any(sb in rule or STICKY_TO_LEGACY[sb] in rule for sb in sticky_buffers)
        
        # Find existing content in the rule
        content_match = re.search(r'(content\s*:\s*"[^"]+"\s*;)', rule)
        if not content_match:
            return rule
        
        if has_sticky:
            # Add rawbytes after existing content
            return re.sub(r'(content\s*:\s*"[^"]+"\s*;)', '\\1 rawbytes;', rule, count=1)
        else:
            # Insert sticky buffer before content and add rawbytes after
            return re.sub(r'(content\s*:\s*"[^"]+"\s*;)', f'{sticky_buffer}; \\1 rawbytes;', rule, count=1)

    # ========================================================================
    # NEW FLOWBITS/FLOW ERRORS
    # ========================================================================

    def corrupt_flowbit_spaces(self, rule: str) -> str:
        """Triggers: 'Spaces are not allowed in flowbit names.'"""
        return re.sub(r'(sid\s*:\s*)', 'flowbits:set, invalid name; \\1', rule, count=1)

    def corrupt_flowbit_isset_isnotset(self, rule: str) -> str:
        """Triggers: 'invalid flowbit command combination... isset and isnotset'."""
        return re.sub(r'(sid\s*:\s*)', 'flowbits:isset,testbit; flowbits:isnotset,testbit; \\1', rule, count=1)

    def corrupt_conflicting_flow_flags(self, rule: str) -> str:
        """Triggers: 'cannot set ESTABLISHED, NOT_ESTABLISHED already set'."""
        if 'flow:' in rule:
            return re.sub(r'flow\s*:\s*[^;]+', 'flow:established,not_established', rule, count=1)
        return re.sub(r'(sid\s*:\s*)', 'flow:established,not_established; \\1', rule, count=1)

    # ========================================================================
    # NEW BYTE/DSIZE ERRORS
    # ========================================================================

    def corrupt_multiple_dsizes(self, rule: str) -> str:
        """Triggers: 'Can't use 2 or more dsizes in the same sig.'"""
        if 'dsize:' in rule:
            return re.sub(r'(dsize\s*:\s*[^;]+;)', '\\1 dsize:200;', rule, count=1)
        return re.sub(r'(sid\s*:\s*)', 'dsize:100; dsize:200; \\1', rule, count=1)

    def corrupt_negative_range_order(self, rule: str) -> str:
        """Triggers: 'Second value in range must not be smaller than the first'."""
        return re.sub(r'(sid\s*:\s*)', 'dsize:500<>100; \\1', rule, count=1)

    def corrupt_byte_jump_conflict(self, rule: str) -> str:
        """Triggers: 'from_end and from_beginning cannot be used in same statement'."""
        return re.sub(r'(sid\s*:\s*)', 'byte_jump:4,0,from_end,from_beginning; \\1', rule, count=1)

    def corrupt_byte_extract_limit(self, rule: str) -> str:
        """Triggers: byte_extract exceeds 8 bytes without string modifier."""
        return re.sub(r'(sid\s*:\s*)', 'byte_extract:10,0,my_var; \\1', rule, count=1)

    # ========================================================================
    # NEW CONTENT/MODIFIER ERRORS
    # ========================================================================

    def corrupt_nocase_with_value(self, rule: str) -> str:
        """Triggers: 'nocase has value' error."""
        if 'content:' in rule:
            return re.sub(r'(content\s*:\s*"[^"]+"\s*;)', '\\1 nocase:1;', rule, count=1)
        return re.sub(r'(sid\s*:\s*)', 'content:"test"; nocase:1; \\1', rule, count=1)

    def corrupt_depth_smaller_than_content(self, rule: str) -> str:
        """Triggers: 'depth:%u smaller than content of len %u.'"""
        return re.sub(r'(sid\s*:\s*)', 'content:"verylongcontent"; depth:3; \\1', rule, count=1)

    def corrupt_startswith_no_content(self, rule: str) -> str:
        """Triggers: startswith needs preceding content."""
        return re.sub(r'(sid\s*:\s*)', 'startswith; \\1', rule, count=1)

    def corrupt_pcre_relative_no_match(self, rule: str) -> str:
        """Triggers: 'pcre with /R (relative) needs preceding match'."""
        # Place PCRE with /R at start of options
        match = re.search(r'\(\s*', rule)
        if match:
            return rule[:match.end()] + 'pcre:"/test/R"; ' + rule[match.end():]
        return rule

    def corrupt_pcre_uppercase_hostname(self, rule: str) -> str:
        """Triggers: 'pcre host("W") specified has an uppercase char.'"""
        return re.sub(r'(sid\s*:\s*)', 'http_host; pcre:"/[A-Z]/W"; \\1', rule, count=1)

    # ========================================================================
    # NEW SID ERRORS
    # ========================================================================

    def corrupt_duplicated_key_fields(self, rule: str) -> str:
        """Triggers: duplicate key fields (sid, rev, msg) error."""
        # Define patterns for each key field
        patterns = [
            (r'(sid\s*:\s*\d+\s*;)', 'sid'),
            (r'(rev\s*:\s*\d+\s*;)', 'rev'),
            (r'(msg\s*:\s*"[^"]+"\s*;)', 'msg'),
        ]
        
        # Shuffle to randomize which field we try to duplicate
        random.shuffle(patterns)
        
        for pattern, _ in patterns:
            match = re.search(pattern, rule)
            if match:
                return rule[:match.end()] + ' ' + match.group(1) + rule[match.end():]
        
        return rule

    def corrupt_sid_zero(self, rule: str) -> str:
        """Triggers: sid:0 is invalid."""
        return re.sub(r'sid\s*:\s*\d+', 'sid:0', rule, count=1)

    def corrupt_missing_key_fields(self, rule: str) -> str:
        """Remove one of sid, rev, or msg entirely."""
        patterns = [
            r'\s*sid\s*:\s*\d+\s*;?',
            r'\s*rev\s*:\s*\d+\s*;?',
            r'\s*msg\s*:\s*"[^"]+"\s*;?',
        ]
        random.shuffle(patterns)
        for pattern in patterns:
            if re.search(pattern, rule):
                return re.sub(pattern, '', rule, count=1)
        return rule

    def corrupt_invalid_numeric_value(self, rule: str) -> str:
        """Inject non-numeric value into priority, sid, or rev field."""
        # Generate dynamic 3-4 character lowercase alphabetic words
        def random_alpha():
            length = random.randint(3, 4)
            return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
        
        sid_val = random_alpha()
        rev_val = random_alpha()
        priority_val = random_alpha()
        
        corruptions = [
            (r'sid\s*:\s*\d+', f'sid:{sid_val}'),
            (r'rev\s*:\s*\d+', f'rev:{rev_val}'),
            (r'(sid\s*:\s*)', f'priority:{priority_val}; \\1'),
        ]
        random.shuffle(corruptions)
        for pattern, replacement in corruptions:
            if re.search(pattern, rule):
                return re.sub(pattern, replacement, rule, count=1)
        return rule

    # ========================================================================
    # ADVANCED MUTATORS (from corrupter.py)
    # ========================================================================

    def corrupt_count_out_of_range(self, rule: str) -> str:
        """Triggers: 'Invalid argument for count...'"""
        return re.sub(r'(sid\s*:\s*)', 'threshold: type limit, track by_src, count -1, seconds 60; \\1', rule, count=1)

    def corrupt_absent_misplaced(self, rule: str) -> str:
        """Triggers: 'absent must come first right after buffer'"""
        if 'http.uri' in rule or 'http_uri' in rule:
            return re.sub(r'(content\s*:\s*"[^"]+"\s*;)', '\\1 absent;', rule, count=1)
        return re.sub(r'(sid\s*:\s*)', 'http.uri; content:"abc"; absent; \\1', rule, count=1)

    def corrupt_dataset_non_sticky(self, rule: str) -> str:
        """Triggers: 'datasets are only supported for sticky buffers'"""
        match = re.search(r'\(\s*', rule)
        if match:
            return rule[:match.end()] + 'dataset:isset, name; ' + rule[match.end():]
        return rule

    def corrupt_unsupported_quotes(self, rule: str) -> str:
        """Triggers: 'quotes on %s keyword that doesn't support them'"""
        return re.sub(r'sid\s*:\s*(\d+)', r'sid:"\1"', rule, count=1)

    def corrupt_conflicting_target(self, rule: str) -> str:
        """Triggers: 'Conflicting values of target keyword'"""
        return re.sub(r'(sid\s*:\s*)', 'target:src_ip; target:dest_ip; \\1', rule, count=1)

    def corrupt_invalid_action_scope(self, rule: str) -> str:
        """Triggers: 'invalid action scope... only packet, flow, tx and hook allowed'"""
        return re.sub(r'(sid\s*:\s*)', 'scope:invalid_val; \\1', rule, count=1)

    def corrupt_transactional_firewall(self, rule: str) -> str:
        """Triggers: 'transactional bidirectional rules not supported for firewall rules'"""
        rule = re.sub(r'^alert\b', 'drop', rule)
        return re.sub(r'\s+->\s+', ' <> ', rule, count=1)

    def corrupt_frame_proto_mismatch(self, rule: str) -> str:
        """Triggers: 'frame %s protocol %s mismatch with rule protocol %s'"""
        if re.match(r'^(alert|drop|pass|reject)\s+tcp\b', rule):
            return re.sub(r'(sid\s*:\s*)', 'frame:icmp; \\1', rule, count=1)
        return re.sub(r'^(alert|drop|pass|reject)\s+\w+', r'\1 tcp', rule) + ' frame:icmp;'

    def corrupt_shorthand_frame_error(self, rule: str) -> str:
        """Triggers: 'rule protocol unknown, can't use shorthand notation for frame'"""
        rule = re.sub(r'^(alert|drop|pass|reject)\s+\w+', r'\1 ip', rule)
        return re.sub(r'(sid\s*:\s*)', 'frame:http; \\1', rule, count=1)

    def corrupt_mixed_directions(self, rule: str) -> str:
        """Triggers: 'rule %u mixes keywords with conflicting directions'"""
        return re.sub(r'(sid\s*:\s*)', 'flow:to_server; http_response_line; content:"200"; \\1', rule, count=1)

    def corrupt_port_negation_nil(self, rule: str) -> str:
        """Triggers: 'no ports left after merging ports with negated ports'"""
        return re.sub(r'\bany\b(?=\s+->)', '[80,!80]', rule, count=1)

    def corrupt_addr_negation_nil(self, rule: str) -> str:
        """Triggers: 'no addresses left after merging addresses...'"""
        return re.sub(r'\$HOME_NET|\$EXTERNAL_NET|\bany\b', '[1.1.1.1,!1.1.1.1]', rule, count=1)

    def corrupt_unopened_address_block(self, rule: str) -> str:
        """Triggers: 'not every address block was properly opened'"""
        return re.sub(r'\$HOME_NET', '192.168.1.0/24]', rule, count=1)

    def corrupt_mix_pkt_frame(self, rule: str) -> str:
        """Triggers: 'can't mix pkt buffer and frame inspection'"""
        return re.sub(r'(sid\s*:\s*)', 'frame:tcp; http.uri; content:"abc"; \\1', rule, count=1)

    def corrupt_prefilter_multi(self, rule: str) -> str:
        """Triggers: 'prefilter already set'"""
        return re.sub(r'(sid\s*:\s*)', 'content:"a"; prefilter; content:"b"; prefilter; \\1', rule, count=1)

    def corrupt_prefilter_negated(self, rule: str) -> str:
        """Triggers: 'prefilter; cannot be used with negated content'"""
        return re.sub(r'(sid\s*:\s*)', 'content:!"abc"; prefilter; \\1', rule, count=1)

    def corrupt_transform_misplaced(self, rule: str) -> str:
        """Triggers: 'transforms must directly follow stickybuffers'"""
        if 'http.uri' in rule:
            return re.sub(r'(http\.uri\s*;\s*content\s*:\s*"[^"]+"\s*;)', '\\1 compress_whitespace;', rule, count=1)
        return re.sub(r'(sid\s*:\s*)', 'http.uri; content:"a"; compress_whitespace; \\1', rule, count=1)

    def corrupt_transform_unconsumed(self, rule: str) -> str:
        """Triggers: 'previous transforms not consumed before pkt_data'"""
        return re.sub(r'(sid\s*:\s*)', 'http.uri; compress_whitespace; pkt_data; \\1', rule, count=1)

    def corrupt_ipproto_conflict(self, rule: str) -> str:
        """Triggers: 'can't use a eq ipproto along with a not ipproto'"""
        return re.sub(r'(sid\s*:\s*)', 'ip_proto:6; ip_proto:!6; \\1', rule, count=1)

    def corrupt_dsize_content_contradiction(self, rule: str) -> str:
        """Triggers: 'content length %d exceeds dsize value %d'"""
        return re.sub(r'(sid\s*:\s*)', 'content:"verylongcontent"; dsize:2; \\1', rule, count=1)

    def corrupt_fast_pattern_math(self, rule: str) -> str:
        """Triggers: 'Fast pattern (length + offset) exceeds pattern length'"""
        return re.sub(r'(sid\s*:\s*)', 'content:"abc"; fast_pattern:1,10; \\1', rule, count=1)

    def corrupt_flowbits_no_name(self, rule: str) -> str:
        """Triggers: 'No valid flowbits specified'"""
        return re.sub(r'(sid\s*:\s*)', 'flowbits:isset; \\1', rule, count=1)

    # ========================================================================
    # NEW CORRUPTION METHODS
    # ========================================================================

    def corrupt_add_pipe(self, rule: str) -> str:
        """Insert pipe character inside content or pcre value string."""
        patterns = [
            (r'(content\s*:\s*")([^"|]+)(")', 3),
            (r'(pcre\s*:\s*")([^"]+)(")', 5),
        ]
        random.shuffle(patterns)
        for pattern, min_len in patterns:
            match = re.search(pattern, rule)
            if match and len(match.group(2)) > min_len:
                value = match.group(2)
                pos = random.randint(1, len(value) - 1)
                corrupted = value[:pos] + '|' + value[pos:]
                return rule[:match.start(2)] + corrupted + rule[match.end(2):]
        return rule

    def corrupt_mixed_buffer_styles(self, rule: str) -> str:
        """Mix sticky buffer and legacy modifier in rule with multiple contents."""
        # Find all content matches
        content_pattern = r'(content\s*:\s*"[^"]+"\s*;)'
        contents = list(re.finditer(content_pattern, rule))
        
        if len(contents) < 2:
            return rule
        
        # Check for existing sticky buffers after first content
        sticky_buffers = ['http.uri', 'http.method', 'http.header', 'http.host', 'http.cookie']
        legacy_modifiers = ['http_uri', 'http_method', 'http_header', 'http_host', 'http_cookie']
        
        # Add a legacy modifier after first content
        first_content = contents[0]
        rule = rule[:first_content.end()] + ' http_uri;' + rule[first_content.end():]
        
        # Add a sticky buffer before second content (re-find due to modification)
        content_pattern = r'(content\s*:\s*"[^"]+"\s*;)'
        contents = list(re.finditer(content_pattern, rule))
        if len(contents) >= 2:
            second_content = contents[1]
            rule = rule[:second_content.start()] + 'http.header; ' + rule[second_content.start():]
        
        return rule

    def corrupt_negate_port(self, rule: str) -> str:
        """Negate port 'any' to '!any' or double-negate a port number."""
        if random.choice([True, False]):
            # Negate 'any' port
            proto_match = re.search(r'^(alert|drop|pass|reject\s+\w+\s+\S+\s+)any(\s+)', rule)
            if proto_match:
                return rule[:proto_match.start()] + proto_match.group(1) + '!any' + proto_match.group(2) + rule[proto_match.end():]
            return re.sub(r'(\s)any(\s+->)', r'\1!any\2', rule, count=1)
        else:
            # Double-negate an existing port
            port_match = re.search(r'!(\d+)', rule)
            if port_match:
                return rule[:port_match.start()] + '!!' + port_match.group(1) + rule[port_match.end():]
            # Or negate a port number
            port_match = re.search(r'\s(\d+)(\s+->|\s*;)', rule)
            if port_match:
                return rule[:port_match.start(1)] + '!' + port_match.group(1) + rule[port_match.end(1):]
        return rule

    def corrupt_protocol_keyword_mismatch(self, rule: str) -> str:
        """Randomly change protocol to mismatch with protocol-specific keywords."""
        # Protocol to keyword mapping
        proto_keywords = {
            'http': ['http.uri', 'http.method', 'http.header', 'http_uri', 'http_method'],
            'dns': ['dns.query', 'dns.opcode', 'dns_query'],
            'tls': ['tls.sni', 'tls.cert_subject', 'ssl_sni'],
            'ssh': ['ssh.proto', 'ssh.software'],
            'smtp': ['smtp.', 'file.data'],
            'ftp': ['ftp.command', 'ftp_command'],
        }
        
        # Detect current protocol
        proto_match = re.match(r'^(alert|drop|pass|reject)\s+(\w+)', rule)
        if not proto_match:
            return rule
        
        current_proto = proto_match.group(2).lower()
        
        # Detect which protocol's keywords are present
        detected_proto = None
        for proto, keywords in proto_keywords.items():
            for kw in keywords:
                if kw in rule.lower():
                    detected_proto = proto
                    break
            if detected_proto:
                break
        
        if not detected_proto:
            return rule
        
        # Choose a different protocol that mismatches
        all_protos = ['tcp', 'udp', 'icmp', 'http', 'dns', 'tls', 'ssh', 'ftp', 'smtp']
        mismatched = [p for p in all_protos if p != detected_proto]
        new_proto = random.choice(mismatched)
        
        return re.sub(r'^(alert|drop|pass|reject)\s+\w+', f'\\1 {new_proto}', rule)

    def corrupt_fast_pattern_only_relative(self, rule: str) -> str:
        """Add fast_pattern:only when rule contains relative keywords."""
        # Find existing content in the rule
        content_match = re.search(r'(content\s*:\s*"[^"]+"\s*;)', rule)
        if not content_match:
            return rule
        
        relative_keywords = ['distance:', 'within:']
        if any(kw in rule for kw in relative_keywords):
            # Add fast_pattern:only after existing content
            return rule[:content_match.end()] + ' fast_pattern:only;' + rule[content_match.end():]
        
        # Add relative keyword and fast_pattern:only after content
        rel_modifier = random.choice(['distance', 'within'])
        rel_value = random.randint(0, 30)
        return rule[:content_match.end()] + f' {rel_modifier}:{rel_value}; fast_pattern:only;' + rule[content_match.end():]

    def corrupt_mix_absolute_relative_modifiers(self, rule: str) -> str:
        """Mix absolute modifiers (offset, depth) with relative modifiers (distance, within) for same content."""
        # Find content in the rule
        content_match = re.search(r'(content\s*:\s*"[^"]+"\s*;)(\s*[^;]*;)*', rule)
        if not content_match:
            return rule
        
        content_section = content_match.group(0)
        
        # Check for existing absolute modifiers (offset, depth)
        has_absolute = bool(re.search(r'\b(offset|depth)\s*:', content_section))
        # Check for existing relative modifiers (distance, within)
        has_relative = bool(re.search(r'\b(distance|within)\s*:', content_section))
        
        # Generate random values
        abs_modifier = random.choice(['offset', 'depth'])
        rel_modifier = random.choice(['distance', 'within'])
        abs_value = random.randint(0, 100)
        rel_value = random.randint(0, 100)
        
        # Determine what to add based on existing modifiers
        if has_absolute and not has_relative:
            # Has absolute, add relative
            new_modifier = f' {rel_modifier}:{rel_value};'
        elif has_relative and not has_absolute:
            # Has relative, add absolute
            new_modifier = f' {abs_modifier}:{abs_value};'
        else:
            # No modifiers or has both - add one of each
            new_modifier = f' {abs_modifier}:{abs_value}; {rel_modifier}:{rel_value};'
        
        # Insert the new modifier after the content
        content_only = re.search(r'(content\s*:\s*"[^"]+"\s*;)', rule)
        if content_only:
            insert_pos = content_only.end()
            return rule[:insert_pos] + new_modifier + rule[insert_pos:]
        
        return rule

    def corrupt_remove_sticky_buffer(self, rule: str) -> str:
        """Randomly remove a sticky buffer from the rule."""
        sticky_buffers = [
            'http.uri;', 'http.method;', 'http.header;', 'http.host;', 'http.cookie;',
            'http.request_body;', 'http.response_body;', 'http.stat_code;', 'http.stat_msg;',
            'dns.query;', 'tls.sni;', 'tls.cert_subject;', 'ssh.proto;', 'file.data;'
        ]
        random.shuffle(sticky_buffers)
        for sb in sticky_buffers:
            if sb in rule:
                return rule.replace(sb, '', 1)
        # Also try without semicolon for sticky buffers before content
        for sb in sticky_buffers:
            sb_no_semi = sb.rstrip(';')
            pattern = rf'{re.escape(sb_no_semi)}\s*;'
            if re.search(pattern, rule):
                return re.sub(pattern, '', rule, count=1)
        return rule

    def corrupt_urilen_with_http_uri(self, rule: str) -> str:
        """Add urilen with minimal value when rule has http.uri sticky buffer."""
        # Find existing content in the rule
        content_match = re.search(r'(content\s*:\s*"[^"]+"\s*;)', rule)
        if not content_match:
            return rule
        
        urilen_val = random.randint(0, 30)
        
        if 'http.uri' in rule or 'http_uri' in rule:
            return re.sub(r'(sid\s*:\s*)', f'urilen:{urilen_val}; \\1', rule, count=1)
        
        # Add http.uri before existing content and urilen after
        return re.sub(r'(content\s*:\s*"[^"]+"\s*;)', f'http.uri; \\1 urilen:{urilen_val};', rule, count=1)


# ============================================================================
# FILE PROCESSING FUNCTIONS
# ============================================================================

def process_rules(input_path: str, output_path: str = None, 
                  num_errors: int = None, verbose: bool = False) -> dict:
    """Process rules file and generate corrupted versions."""
    stats = {'total': 0, 'corrupted': 0, 'skipped': 0}
    corrupted_rules = []
    
    corruptor = SuricataCorruptor()
    
    with open(input_path, 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        line = line.rstrip('\n\r')
        
        if not line.strip() or line.strip().startswith('#'):
            corrupted_rules.append(line)
            stats['skipped'] += 1
            continue
        
        stats['total'] += 1
        corrupted = corruptor.corrupt_rule(line, num_errors)
        
        if corrupted != line:
            stats['corrupted'] += 1
            if verbose:
                print(f"Original:  {line[:80]}...")
                print(f"Corrupted: {corrupted[:80]}...")
                print()
        
        corrupted_rules.append(corrupted)
    
    output = '\n'.join(corrupted_rules)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write("# SYNTHETIC CORRUPTED RULES - DO NOT USE IN PRODUCTION\n")
            f.write("# Line N corresponds to Line N in the original file\n")
            f.write(output + '\n')
    else:
        print(output)
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Corrupt valid Suricata rules for training data generation.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Error categories applied:
  - Syntax: semicolons, parentheses, PCRE, misspellings, duplicates
  - Version: sticky->legacy buffer conversion, deprecated keywords
  - Protocol: mismatched keywords, wrong explicit hooks
  - Logic: flowbits, packet/stream mixing, classtype, variables

Examples:
    %(prog)s good.rules -o bad.rules
    %(prog)s good.rules --errors 2 -v
    
Programmatic usage:
    corruptor = SuricataCorruptor()
    bad_rule = corruptor.corrupt_rule(rule, num_errors=2)
"""
    )
    parser.add_argument('input', help='Input rules file with valid rules')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-e', '--errors', type=int, default=None,
                        help='Number of errors per rule (default: random 1-3)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show before/after for each rule')
    parser.add_argument('--stats', action='store_true',
                        help='Print statistics')
    
    args = parser.parse_args()
    
    try:
        stats = process_rules(args.input, args.output, args.errors, args.verbose)
        
        if args.stats or args.verbose:
            print(f"\nStatistics: {stats['total']} rules, "
                  f"{stats['corrupted']} corrupted, "
                  f"{stats['skipped']} skipped", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
