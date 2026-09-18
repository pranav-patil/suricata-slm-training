#!/usr/bin/env python3
"""
Suricata Rule Compressor

Compresses Suricata rule fields (tls_fingerprint, content, reference, metadata, pcre)
and addresses to reduce rule length while maintaining validity.
"""

import argparse
import os
import random
import re
import sys
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────────────────────────
# Configuration Constants
# ─────────────────────────────────────────────────────────────────────────────

MAX_RULE_LENGTH_THRESHOLD = 350
TARGET_RULE_LENGTH = 400
MIN_FIELD_LENGTH = 5
SID_RANGE = (1_000_000, 9_999_999)

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

STICKY_BUFFERS = frozenset({
    "tls.random", "tls.random_time", "tls.random_bytes", "tls.fingerprint",
    "dns.query.type", "bsize", "urilen",
    "ja3s.hash", "ja3.hash", "ja3.string", "ja3s.string",
    # Legacy
    "tls_cert_notbefore", "tls_cert_notafter",
    "ja3_hash", "ja3s_hash", "ja3_string", "ja3s_string",
})

CONTEXT_RESETTERS = frozenset({
    "content", "msg", "sid", "reference", "metadata", "pcre", "uricontent"
})

# ─────────────────────────────────────────────────────────────────────────────
# Compiled Regex Patterns
# ─────────────────────────────────────────────────────────────────────────────

RULE_PATTERN = re.compile(
    r'^(?P<action>[a-zA-Z]+)\s+'
    r'(?P<proto>[a-zA-Z0-9_-]+)\s+'
    r'(?P<src>[^\s]+)\s+'
    r'(?P<src_port>[^\s]+)\s+'
    r'(?P<dir>->|<>)\s+'
    r'(?P<dst>[^\s]+)\s+'
    r'(?P<dst_port>[^\s]+)\s+'
    r'\((?P<options>.*)\)\s*$',
    re.DOTALL
)

KEYWORD_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+\s*:')
WORD_PATTERN = re.compile(r'^([a-zA-Z0-9._-]+)')
PCRE_PATTERN = re.compile(r'^/(.*)/([a-zA-Z]*)$')
HEX_BLOCK_PATTERN = re.compile(r'(\|[0-9a-fA-F\s]+\|)')
SID_PATTERN = re.compile(r'\bsid\s*:\s*(\d+)')

MSG_PREFIX_PATTERNS = [
    (re.compile(r'^\[(FIREEYE|ET|GPL)[^\]]*\]\s*', re.IGNORECASE),
     lambda m: f"[{m.group(1)[:8]}-] "),
    (re.compile(r'^(ET|GPL)\s+(MALWARE|POLICY|INFO|TROJAN)\s+', re.IGNORECASE),
     lambda m: f"{m.group(1)} {m.group(2)[0]}: "),
]


# ─────────────────────────────────────────────────────────────────────────────
# SID Manager
# ─────────────────────────────────────────────────────────────────────────────

class SIDManager:
    """Ensures unique SIDs within a safe range for training data."""
    
    def __init__(self):
        self.used: set[int] = set()

    def register(self, sid_str: str) -> str:
        """Register a SID and return a unique one if already used."""
        try:
            sid = int(sid_str)
            if sid not in self.used:
                self.used.add(sid)
                return str(sid)
        except ValueError:
            pass
        return self._generate_unique()

    def _generate_unique(self) -> str:
        """Generate a unique SID within the configured range."""
        new_sid = random.randint(*SID_RANGE)
        while new_sid in self.used:
            new_sid = random.randint(*SID_RANGE)
        self.used.add(new_sid)
        return str(new_sid)

    def register_from_rule(self, rule_line: str) -> str:
        """Extract SID from rule and register it, returning updated rule."""
        if not (match := SID_PATTERN.search(rule_line)):
            return rule_line

        original_sid = match.group(1)
        new_sid = self.register(original_sid)
        
        if new_sid != original_sid:
            return rule_line[:match.start(1)] + new_sid + rule_line[match.end(1):]
        return rule_line


# ─────────────────────────────────────────────────────────────────────────────
# Rule Compressor
# ─────────────────────────────────────────────────────────────────────────────

class RuleCompressor:
    """Compresses Suricata rules while preserving validity."""

    def __init__(self, sid_manager: SIDManager):
        self.sid = sid_manager

    # ─────────────────────────────────────────────────────────────────────────
    # Parsing Helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_suricata_keyword(text: str) -> bool:
        """Check if text looks like a Suricata keyword (keyword: or modifier;)."""
        text = text.strip()
        if not text:
            return True  # End of string is valid split point
        
        if KEYWORD_PATTERN.match(text):
            return True
        
        if (match := WORD_PATTERN.match(text)) and match.group(1) in STANDALONE_MODIFIERS:
            return True
            
        return False

    def _robust_split(self, options_block: str) -> list[str]:
        """Split options by semicolon, respecting quoted strings and keyword boundaries."""
        parts, current = [], []
        in_quotes, escaped = False, False

        for i, char in enumerate(options_block):
            if escaped:
                current.append(char)
                escaped = False
            elif char == '\\':
                current.append(char)
                escaped = True
            elif char == '"':
                in_quotes = not in_quotes
                current.append(char)
            elif char == ';':
                remaining = options_block[i + 1:]
                if not in_quotes or self._is_suricata_keyword(remaining):
                    if current:
                        parts.append("".join(current).strip())
                    current = []
                    in_quotes = False
                else:
                    current.append(char)
            else:
                current.append(char)

        if current:
            parts.append("".join(current).strip())
        
        return [p for p in parts if p]

    @staticmethod
    def _clean_value(val: str) -> str:
        """Remove outer quotes and trailing semicolons from a value."""
        val = val.strip().rstrip(';')
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        return val.strip()

    # ─────────────────────────────────────────────────────────────────────────
    # Field Compressors
    # ─────────────────────────────────────────────────────────────────────────

    def _compress_msg(self, msg: str, max_len: int = 60) -> str:
        """Compress msg field with acronym compression and truncation."""
        text = self._clean_value(msg)
        if len(text) <= MIN_FIELD_LENGTH:
            return text

        # Apply prefix compression
        for pattern, replacement in MSG_PREFIX_PATTERNS:
            if pattern.match(text):
                text = pattern.sub(replacement, text, count=1)
                break

        # Truncate at word boundary
        if len(text) > max_len:
            text = text[:max_len].rsplit(' ', 1)[0]

        return f'"{text}"'

    def _compress_content(self, content_str: str, max_text_len: int = 8, 
                          max_hex_pairs: int = 2) -> str:
        """Compress content string, handling hex blocks and text separately."""
        is_negated = content_str.strip().startswith('!')
        inner = self._clean_value(content_str.strip().lstrip('!'))

        parts = HEX_BLOCK_PATTERN.split(inner)
        compressed = []

        for part in parts:
            if not part:
                continue
            if part.startswith('|') and part.endswith('|'):
                # Hex block: keep first N pairs
                hex_content = part.strip('|').replace(" ", "")
                truncated = hex_content[:max_hex_pairs * 2]
                if len(truncated) % 2:
                    truncated = truncated[:-1]
                compressed.append(f"|{truncated}|")
            else:
                # Plain text: truncate, avoiding trailing backslash
                truncated = part[:max_text_len]
                if truncated.endswith('\\'):
                    truncated = truncated[:-1]
                compressed.append(truncated)

        prefix = '!' if is_negated else ''
        return f'{prefix}"{"".join(compressed).strip()}"'

    def _compress_pcre(self, pcre: str, max_len: int = 180) -> str:
        """Compress PCRE using atomic tokenization to prevent syntax errors."""
        pcre = self._clean_value(pcre)
        
        if len(pcre) <= MIN_FIELD_LENGTH:
            return pcre
        
        match = re.match(r"^/(.*)/([a-zA-Z]*)$", pcre)
        if not match:
            return f'"{pcre[:max_len]}"'

        core, flags = match.groups()
        limit = max_len - len(flags) - 10

        if len(core) <= limit:
            return f'"/{core}/{flags}"'

        truncated = ""
        stack = []
        i = 0
        
        while i < len(core):
            char = core[i]
            token = char
            is_opener = False
            is_closer = False

            # --- ATOMIC TOKENIZATION ---
            if char == '\\':
                # Escapes: \x{FFF}, \xFF, \p{L}, \c., \u.... or standard \.
                m = re.match(r'^\\(?:x\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|[pP]\{.*?\}|[cu].|.)', core[i:])
                token = m.group(0) if m else core[i:i+2]
                
            elif char == '[':
                # Character Classes: [a-zA-Z_], [^abc]
                m = re.match(r'^\[\^?\]?(?:[^\]\\]|\\.)*\]', core[i:])
                token = m.group(0) if m else '['
                
            elif char == '(':
                # Match all group headers: Named Groups, Lookarounds, Options, Comments, Verbs
                # Includes: (?P<name>, (?P=name), (?!, (?<=, (?:, (?i:, (?i), (?>), (?|), (?#...), (*ACCEPT)
                group_regex = r'^\(\?(?:P<[^>]+>|P=[^)]+\)|P>[^)]+\)|<[=!]|<[^>]+>|[=!\>\|]|#[^)]+\)|[a-zA-Z0-9-]*:|[a-zA-Z0-9-]+\))|^\(\*[^)]+\)'
                m = re.match(group_regex, core[i:])
                if m:
                    token = m.group(0)
                    # Skip stack logic for leaf nodes: backreferences, subroutine calls, comments, verbs, and bodyless modifiers like (?i)
                    if (token.startswith('(?P=') or token.startswith('(?P>') or 
                        token.startswith('(?#') or token.startswith('(*') or 
                        (token.endswith(')') and ':' not in token)):
                        pass
                    else:
                        is_opener = True
                else:
                    token = '('
                    is_opener = True
                    
            elif char == ')':
                token = ')'
                is_closer = True
                
            elif char == '{':
                # Quantifiers: {1,3}, {5}
                m = re.match(r'^\{\d+(?:,\d*)?\}', core[i:])
                token = m.group(0) if m else '{'

            # --- LIMIT CHECK & TRUNCATION ---
            # Predict space needed for closing brackets
            expected_closing = len(stack) + (1 if is_opener else (-1 if is_closer and stack else 0))
            
            # If adding this complete token and its closing structures exceeds the limit, stop early.
            if len(truncated) + len(token) + expected_closing + 3 > limit:
                break

            truncated += token
            i += len(token)

            # --- STACK MANAGEMENT ---
            if is_opener:
                stack.append(')')
            elif is_closer and stack:
                stack.pop()

        closing = "".join(reversed(stack))
        return f'"/{truncated}...{closing}/{flags}"'

    def _compress_reference(self, ref_block: str, max_refs: int = 2, 
                            max_val_len: int = 20) -> str:
        """Compress reference field, preserving type and shortening values."""
        ref_block = self._clean_value(ref_block)
        if len(ref_block) <= MIN_FIELD_LENGTH:
            return ref_block

        compressed = []
        for ref in ref_block.split('|')[:max_refs]:
            parts = ref.split(',', 1)
            if len(parts) < 2:
                continue

            ref_type, ref_val = parts[0].strip(), parts[1].strip()

            if ref_type == 'url':
                parsed = urlparse(ref_val if ref_val.startswith('http') else f'http://{ref_val}')
                domain = parsed.netloc or ref_val.split('/')[0]
                path_snippet = parsed.path[:5] if parsed.path else ""
                compressed_val = f"{domain}{path_snippet}"
            elif ref_type in ('md5', 'sha256'):
                compressed_val = ref_val[:8]
            else:
                compressed_val = ref_val[:max_val_len]

            compressed.append(f"{ref_type},{compressed_val}")

        return "|".join(compressed)

    def _compress_metadata(self, metadata_str: str, max_pairs: int = 3, 
                           max_val_len: int = 12) -> str:
        """Compress metadata to structural minimum."""
        metadata_str = self._clean_value(metadata_str)
        if len(metadata_str) <= MIN_FIELD_LENGTH:
            return metadata_str

        compressed = []
        for pair in metadata_str.split(','):
            pair = pair.strip()
            if not pair:
                continue
            parts = pair.split(' ', 1)
            if len(parts) == 2 and '_name' not in parts[0]:
                compressed.append(f"{parts[0]} {parts[1][:10]}")

        return ", ".join(compressed[:2]) if compressed else "slm_trained true"

    # ─────────────────────────────────────────────────────────────────────────
    # Options Compression
    # ─────────────────────────────────────────────────────────────────────────

    def _compress_options(self, options_block: str) -> str:
        """Compress all options in a rule's options block."""
        raw_options = self._robust_split(options_block)
        compressed = []
        last_content_existed = False
        i = 0

        while i < len(raw_options):
            opt = raw_options[i]

            # Handle standalone modifiers
            if ':' not in opt:
                compressed.append(opt)
                i += 1
                continue

            keyword, value = opt.split(':', 1)
            keyword = keyword.strip()

            # Skip relative modifiers without preceding content
            if keyword in ('distance', 'within', 'offset', 'depth') and not last_content_existed:
                i += 1
                continue

            # Field-specific compression
            result = self._compress_keyword(keyword, value, raw_options, i)
            if result:
                compressed.append(result)
                # Only mark content as existing if it passed the length check
                if keyword == 'content' and len(self._clean_value(value)) > MIN_FIELD_LENGTH:
                    last_content_existed = True

            i += 1

        return "; ".join(compressed) + ";"

    def _compress_keyword(self, keyword: str, value: str, 
                          raw_options: list[str], index: int) -> str | None:
        """Compress a specific keyword based on its type."""
        
        if keyword == 'content' and len(self._clean_value(value)) > MIN_FIELD_LENGTH:
            return self._handle_content_compression(value, raw_options, index)
        
        if keyword == 'pcre':
            return f"pcre:{self._compress_pcre(value)}"
        
        if keyword == 'uricontent':
            is_negated = value.strip().startswith('!')
            inner = self._clean_value(value.strip().lstrip('!'))
            prefix = '!' if is_negated else ''
            return f'uricontent:{prefix}"{inner}"'
        
        if keyword == 'reference':
            return f"reference:{self._compress_reference(value)}"
        
        if keyword == 'metadata':
            return f"metadata:{self._compress_metadata(value)}"
        
        if keyword == 'msg':
            return f"msg:{self._compress_msg(value)}"
        
        if keyword == 'sid':
            return f"sid:{self.sid.register(self._clean_value(value))}"
        
        return f"{keyword}:{value}"

    def _handle_content_compression(self, value: str, raw_options: list[str], 
                                    index: int) -> str:
        """Handle content compression with sticky buffer context awareness."""
        has_sticky_context = False

        # Backward scan for sticky buffer context
        for k in range(index - 1, -1, -1):
            prev_opt = raw_options[k]
            prev_kw = prev_opt.split(':', 1)[0].strip() if ':' in prev_opt else prev_opt.strip()
            if prev_kw in CONTEXT_RESETTERS:
                break
            if prev_kw in STICKY_BUFFERS:
                has_sticky_context = True
                break

        # Forward scan for modifiers
        following_modifiers = []
        for j in range(index + 1, len(raw_options)):
            next_opt = raw_options[j]
            next_kw = next_opt.split(':', 1)[0].strip() if ':' in next_opt else next_opt.strip()
            if next_kw in CONTEXT_RESETTERS:
                break
            following_modifiers.append((j, next_opt, next_kw))

        if not has_sticky_context:
            has_sticky_context = any(kw in STICKY_BUFFERS for _, _, kw in following_modifiers)

        if has_sticky_context:
            return f"content:{value}"

        original_clean = self._clean_value(value)
        compressed_val = self._compress_content(value)
        
        # Fix fast_pattern if content was truncated
        if len(self._clean_value(compressed_val)) < len(original_clean):
            for idx, m_opt, m_kw in following_modifiers:
                if m_kw == 'fast_pattern' and ':' in m_opt:
                    raw_options[idx] = 'fast_pattern'

        return f"content:{compressed_val}"

    # ─────────────────────────────────────────────────────────────────────────
    # IP Compression
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _compress_ip_list(addr: str, current_length: int) -> str:
        """Compress IP address list by randomly sampling to reduce length."""
        if not (addr.startswith('[') and addr.endswith(']')):
            return addr

        ips = [ip.strip() for ip in addr[1:-1].split(',') if ip.strip()]
        if len(ips) <= 3:
            return addr

        excess = current_length - TARGET_RULE_LENGTH
        if excess <= 0:
            return addr

        avg_ip_len = len(addr[1:-1]) / len(ips) if ips else 10
        target_count = max(3, len(ips) - int(excess / avg_ip_len) - 1)

        if target_count >= len(ips):
            return addr

        indices = sorted(random.sample(range(len(ips)), target_count))
        return f"[{','.join(ips[i] for i in indices)}]"

    # ─────────────────────────────────────────────────────────────────────────
    # Main Compression Entry Point
    # ─────────────────────────────────────────────────────────────────────────

    def compress(self, rule_line: str) -> str | None:
        """Compress a Suricata rule if it exceeds threshold."""
        rule_line = rule_line.strip()

        if len(rule_line) <= MAX_RULE_LENGTH_THRESHOLD:
            return rule_line

        if not (match := RULE_PATTERN.match(rule_line)):
            return None

        p = match.groupdict()
        compressed_options = self._compress_options(p['options'])

        # Build rule
        def build_rule(src: str, dst: str) -> str:
            header = f"{p['action']} {p['proto']} {src} {p['src_port']} {p['dir']} {dst} {p['dst_port']}"
            return f"{header} ({compressed_options})"

        rule = build_rule(p['src'], p['dst'])

        # Compress IPs if still too long
        if len(rule) > TARGET_RULE_LENGTH:
            compressed_src = self._compress_ip_list(p['src'], len(rule))
            rule = build_rule(compressed_src, p['dst'])
            
            if len(rule) > TARGET_RULE_LENGTH:
                compressed_dst = self._compress_ip_list(p['dst'], len(rule))
                rule = build_rule(p['src'], compressed_dst)

        return rule


# ─────────────────────────────────────────────────────────────────────────────
# File Processing
# ─────────────────────────────────────────────────────────────────────────────

def process_file(input_path: str, output_path: str, 
                 compressor: RuleCompressor) -> tuple[int, int]:
    """Process rules file and return (processed_count, error_count)."""
    processed = errors = 0

    with open(input_path) as infile, open(output_path, 'w') as outfile:
        for line in infile:
            line = line.strip()

            # Pass through empty lines and comments
            if not line or line.startswith('#'):
                outfile.write(line + "\n")
                continue

            try:
                if len(line) <= MAX_RULE_LENGTH_THRESHOLD:
                    line = compressor.sid.register_from_rule(line)
                    outfile.write(line + "\n")
                elif result := compressor.compress(line):
                    outfile.write(result + "\n")
                else:
                    sys.stderr.write(f"Warning: Parse error: {line}...\n")
                    outfile.write(line + "\n")
                    errors += 1
                    continue
                processed += 1
            except Exception as e:
                sys.stderr.write(f"Error: {line} -> {e}\n")
                outfile.write(line + "\n")
                errors += 1

    return processed, errors


def main():
    parser = argparse.ArgumentParser(description="Suricata Rule Compressor")
    parser.add_argument("file", help="Input rules file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        sys.exit(f"Error: File {args.file} not found.")

    # Setup paths
    dir_name = os.path.dirname(args.file) or '.'
    base, ext = os.path.splitext(os.path.basename(args.file))
    output_name = f"{base}{ext}" if base.endswith("_compressed") else f"{base}_compressed{ext}"
    output_path = os.path.join(dir_name, output_name)

    # Process
    sid_manager = SIDManager()
    compressor = RuleCompressor(sid_manager)

    print(f"Processing: {args.file}")
    processed, errors = process_file(args.file, output_path, compressor)

    print("-" * 40)
    print(f"Output: {output_path}")
    print(f"Processed: {processed} | Errors: {errors}")


if __name__ == "__main__":
    main()
