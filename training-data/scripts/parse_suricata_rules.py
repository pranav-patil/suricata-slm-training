#!/usr/bin/env python3
"""
Parses rules and outputs CSV with bnf_category for each non-terminal symbol.
"""

import argparse
import csv
import re
import sys


class SuricataParser:
    """Parser for Suricata rules based on BNF grammar."""

    def __init__(self, enable_legacy_support=False):
        self.pos = 0
        self.text = ""
        self.enable_legacy_support = enable_legacy_support
        """When True, recognise legacy underscore-form aliases such as
        ``dns_query``, ``file_data``, ``tls_sni``, ``tls_cert_issuer``,
        ``tls_cert_subject``, ``tls_sni``, ``ja3_hash``, ``ssh_proto``,
        ``http_content_type``, ``http_header_names``, ``http_referer``,
        ``http_server_body``, ``base64_data``, and ``dotprefix``.
        Legacy aliases are mapped to the same keyword categories as their
        modern dot-notation counterparts.
        """

    def parse_rule(self, rule_text):
        """Parse a complete Suricata rule."""
        self.text = rule_text.strip()
        self.pos = 0

        if not self.text:
            return None

        try:
            result = self._parse_rule()
            return result
        except Exception as e:
            return {"bnf_category": "rule", "error": str(e), "raw": rule_text[:200]}

    def _skip_whitespace(self):
        while self.pos < len(self.text) and self.text[self.pos] in ' \t':
            self.pos += 1

    def _parse_rule(self):
        """<rule> ::= <action> <whitespace> <header> <whitespace> "(" <rule-options> ")" """
        result = {"bnf_category": "rule"}

        # Parse action
        result["action"] = self._parse_action()
        self._skip_whitespace()

        # Parse header
        result["header"] = self._parse_header()
        self._skip_whitespace()

        # Expect "("
        if self.pos < len(self.text) and self.text[self.pos] == '(':
            self.pos += 1
        else:
            raise ValueError(f"Expected '(' at position {self.pos}")

        self._skip_whitespace()

        # Parse rule-options
        result["rule_options"] = self._parse_rule_options()

        self._skip_whitespace()

        # Expect ")"
        if self.pos < len(self.text) and self.text[self.pos] == ')':
            self.pos += 1

        return result

    def _parse_action(self):
        """<action> ::= "alert" | "pass" | "drop" | "reject" | "rejectsrc" | "rejectdst" | "rejectboth" """
        actions = ["alert", "pass", "drop", "rejectboth", "rejectsrc", "rejectdst", "reject"]
        for action in actions:
            if self.text[self.pos:].startswith(action):
                self.pos += len(action)
                return {"bnf_category": "action", "value": action}
        raise ValueError(f"Unknown action at position {self.pos}")

    def _parse_header(self):
        """<header> ::= <protocol> <whitespace> <source-address> <whitespace> <source-port> <whitespace> <direction> <whitespace> <dest-address> <whitespace> <dest-port>"""
        result = {"bnf_category": "header"}

        result["protocol"] = self._parse_protocol()
        self._skip_whitespace()

        result["source_address"] = self._parse_address_spec("source-address")
        self._skip_whitespace()

        result["source_port"] = self._parse_port_spec("source-port")
        self._skip_whitespace()

        result["direction"] = self._parse_direction()
        self._skip_whitespace()

        result["dest_address"] = self._parse_address_spec("dest-address")
        self._skip_whitespace()

        result["dest_port"] = self._parse_port_spec("dest-port")

        return result

    def _parse_protocol(self):
        """<protocol> ::= <network-protocol> | <application-protocol> | <explicit-hook>"""
        network_protocols = ["tcp-pkt", "tcp-stream", "pkthdr", "tcp", "udp", "icmp", "ipv6", "ip"]
        app_protocols = ["http_any", "http1", "http2", "http", "ftp-data", "ftp", "tls", "ssl",
                        "smb", "dns", "dcerpc", "dhcp", "ssh", "smtp", "imap", "pop3", "modbus",
                        "dnp3", "enip", "nfs", "ike", "krb5", "bittorrent-dht", "ntp", "rfb",
                        "rdp", "snmp", "tftp", "sip", "websocket", "quic", "mqtt", "pgsql",
                        "ja4", "mdns", "sctp"]

        all_protocols = network_protocols + app_protocols
        for proto in sorted(all_protocols, key=len, reverse=True):
            if self.text[self.pos:].lower().startswith(proto):
                self.pos += len(proto)
                if proto in network_protocols:
                    return {
                        "bnf_category": "protocol",
                        "network_protocol": {"bnf_category": "network-protocol", "value": proto}
                    }
                else:
                    return {
                        "bnf_category": "protocol",
                        "application_protocol": {"bnf_category": "application-protocol", "value": proto}
                    }

        # Try explicit hook (protocol:hook)
        match = re.match(r'([a-zA-Z_][a-zA-Z0-9_-]*):([a-zA-Z_][a-zA-Z0-9_-]*)', self.text[self.pos:])
        if match:
            self.pos += len(match.group(0))
            return {
                "bnf_category": "protocol",
                "explicit_hook": {
                    "bnf_category": "explicit-hook",
                    "protocol_name": {"bnf_category": "protocol-name", "value": match.group(1)},
                    "hook_name": {"bnf_category": "hook-name", "value": match.group(2)}
                }
            }

        raise ValueError(f"Unknown protocol at position {self.pos}")

    def _parse_direction(self):
        """<direction> ::= "->" | "=>" | "<>" """
        for direction in ["->", "=>", "<>"]:
            if self.text[self.pos:].startswith(direction):
                self.pos += len(direction)
                return {"bnf_category": "direction", "value": direction}
        raise ValueError(f"Unknown direction at position {self.pos}")

    def _parse_address_spec(self, wrapper_category):
        """<address-spec> ::= <address> | <address-group> | <negated-address> | <variable>"""
        result = {"bnf_category": wrapper_category}
        inner = {"bnf_category": "address-spec"}

        # Check for negation
        negated = False
        if self.pos < len(self.text) and self.text[self.pos] == '!':
            negated = True
            self.pos += 1
            self._skip_whitespace()

        # Check for variable
        if self.pos < len(self.text) and self.text[self.pos] == '$':
            self.pos += 1
            var_name = self._parse_identifier()
            var_obj = {"bnf_category": "variable", "identifier": {"bnf_category": "identifier", "value": var_name}}
            if negated:
                inner["negated_address"] = {"bnf_category": "negated-address", "address_spec": {"bnf_category": "address-spec", "variable": var_obj}}
            else:
                inner["variable"] = var_obj
            result["address_spec"] = inner
            return result

        # Check for address group
        if self.pos < len(self.text) and self.text[self.pos] == '[':
            self.pos += 1
            address_list = self._parse_address_list()
            if self.pos < len(self.text) and self.text[self.pos] == ']':
                self.pos += 1
            group = {"bnf_category": "address-group", "address_list": address_list}
            if negated:
                inner["negated_address"] = {"bnf_category": "negated-address", "address_spec": {"bnf_category": "address-spec", "address_group": group}}
            else:
                inner["address_group"] = group
            result["address_spec"] = inner
            return result

        # Parse address (any, IPv4, IPv6)
        address = self._parse_address()
        if negated:
            inner["negated_address"] = {"bnf_category": "negated-address", "address_spec": {"bnf_category": "address-spec", "address": address}}
        else:
            inner["address"] = address
        result["address_spec"] = inner
        return result

    def _parse_address_list(self):
        """<address-list> ::= <address-spec> | <address-spec> "," <address-list>"""
        result = {"bnf_category": "address-list", "items": []}

        while True:
            self._skip_whitespace()
            item = self._parse_address_spec_inner()
            result["items"].append(item)
            self._skip_whitespace()
            if self.pos < len(self.text) and self.text[self.pos] == ',':
                self.pos += 1
            else:
                break

        return result

    def _parse_address_spec_inner(self):
        """Parse address-spec without wrapper."""
        inner = {"bnf_category": "address-spec"}

        # Check for negation
        negated = False
        if self.pos < len(self.text) and self.text[self.pos] == '!':
            negated = True
            self.pos += 1
            self._skip_whitespace()

        # Check for variable
        if self.pos < len(self.text) and self.text[self.pos] == '$':
            self.pos += 1
            var_name = self._parse_identifier()
            var_obj = {"bnf_category": "variable", "identifier": {"bnf_category": "identifier", "value": var_name}}
            if negated:
                inner["negated_address"] = {"bnf_category": "negated-address", "address_spec": {"bnf_category": "address-spec", "variable": var_obj}}
            else:
                inner["variable"] = var_obj
            return inner

        # Check for address group (nested)
        if self.pos < len(self.text) and self.text[self.pos] == '[':
            self.pos += 1
            address_list = self._parse_address_list()
            if self.pos < len(self.text) and self.text[self.pos] == ']':
                self.pos += 1
            group = {"bnf_category": "address-group", "address_list": address_list}
            if negated:
                inner["negated_address"] = {"bnf_category": "negated-address", "address_spec": {"bnf_category": "address-spec", "address_group": group}}
            else:
                inner["address_group"] = group
            return inner

        # Parse address
        address = self._parse_address()
        if negated:
            inner["negated_address"] = {"bnf_category": "negated-address", "address_spec": {"bnf_category": "address-spec", "address": address}}
        else:
            inner["address"] = address
        return inner

    def _parse_address(self):
        """<address> ::= <ipv4-address> | <ipv4-cidr> | <ipv6-address> | <ipv6-cidr> | "any" """
        self._skip_whitespace()

        # Check for "any"
        if self.text[self.pos:].lower().startswith("any"):
            self.pos += 3
            return {"bnf_category": "address", "value": "any"}

        # Try to match IPv4 with optional CIDR
        ipv4_cidr_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/(\d{1,2}))?'
        match = re.match(ipv4_cidr_pattern, self.text[self.pos:])
        if match:
            self.pos += len(match.group(0))
            if match.group(2):
                return {
                    "bnf_category": "address",
                    "ipv4_cidr": {
                        "bnf_category": "ipv4-cidr",
                        "ipv4_address": {
                            "bnf_category": "ipv4-address",
                            "octets": self._parse_octets(match.group(1))
                        },
                        "cidr_prefix": {"bnf_category": "cidr-prefix", "value": match.group(3)}
                    }
                }
            else:
                return {
                    "bnf_category": "address",
                    "ipv4_address": {
                        "bnf_category": "ipv4-address",
                        "octets": self._parse_octets(match.group(1))
                    }
                }

        # Try to match IPv6 (simplified)
        ipv6_pattern = r'([0-9a-fA-F:]+(?:::)?[0-9a-fA-F:]*)(/(\d{1,3}))?'
        match = re.match(ipv6_pattern, self.text[self.pos:])
        if match and ':' in match.group(1):
            self.pos += len(match.group(0))
            if match.group(2):
                return {
                    "bnf_category": "address",
                    "ipv6_cidr": {
                        "bnf_category": "ipv6-cidr",
                        "ipv6_address": {"bnf_category": "ipv6-address", "value": match.group(1)},
                        "cidr_prefix": {"bnf_category": "cidr-prefix", "value": match.group(3)}
                    }
                }
            else:
                return {
                    "bnf_category": "address",
                    "ipv6_address": {"bnf_category": "ipv6-address", "value": match.group(1)}
                }

        raise ValueError(f"Invalid address at position {self.pos}")

    def _parse_octets(self, ip_str):
        """Parse IPv4 octets."""
        parts = ip_str.split('.')
        return [{"bnf_category": "octet", "value": p} for p in parts]

    def _parse_port_spec(self, wrapper_category):
        """<port-spec> ::= <port> | <port-group> | <negated-port> | <port-range> | <variable> | "any" """
        result = {"bnf_category": wrapper_category}
        inner = {"bnf_category": "port-spec"}

        self._skip_whitespace()

        # Check for negation
        negated = False
        if self.pos < len(self.text) and self.text[self.pos] == '!':
            negated = True
            self.pos += 1
            self._skip_whitespace()

        # Check for variable
        if self.pos < len(self.text) and self.text[self.pos] == '$':
            self.pos += 1
            var_name = self._parse_identifier()
            var_obj = {"bnf_category": "variable", "identifier": {"bnf_category": "identifier", "value": var_name}}
            if negated:
                inner["negated_port"] = {"bnf_category": "negated-port", "port_spec": {"bnf_category": "port-spec", "variable": var_obj}}
            else:
                inner["variable"] = var_obj
            result["port_spec"] = inner
            return result

        # Check for "any"
        if self.text[self.pos:].lower().startswith("any"):
            self.pos += 3
            inner["value"] = "any"
            if negated:
                inner = {"bnf_category": "port-spec", "negated_port": {"bnf_category": "negated-port", "port_spec": inner}}
            result["port_spec"] = inner
            return result

        # Check for port group
        if self.pos < len(self.text) and self.text[self.pos] == '[':
            self.pos += 1
            port_list = self._parse_port_list()
            if self.pos < len(self.text) and self.text[self.pos] == ']':
                self.pos += 1
            group = {"bnf_category": "port-group", "port_list": port_list}
            if negated:
                inner["negated_port"] = {"bnf_category": "negated-port", "port_spec": {"bnf_category": "port-spec", "port_group": group}}
            else:
                inner["port_group"] = group
            result["port_spec"] = inner
            return result

        # Parse port or port range (may be followed by comma for unbracketed list)
        port_obj = self._parse_port_or_range()
        
        # Check for comma-separated port list without brackets (e.g., 80,443)
        if self.pos < len(self.text) and self.text[self.pos] == ',':
            # This is an unbracketed port list - collect all items
            port_list_items = []
            # Add the first port we already parsed
            first_item = {"bnf_category": "port-spec"}
            first_item.update(port_obj)
            port_list_items.append(first_item)
            
            while self.pos < len(self.text) and self.text[self.pos] == ',':
                self.pos += 1  # skip comma
                self._skip_whitespace()
                next_port = self._parse_port_or_range()
                next_item = {"bnf_category": "port-spec"}
                next_item.update(next_port)
                port_list_items.append(next_item)
            
            port_list = {"bnf_category": "port-list", "items": port_list_items}
            group = {"bnf_category": "port-group", "port_list": port_list}
            if negated:
                inner["negated_port"] = {"bnf_category": "negated-port", "port_spec": {"bnf_category": "port-spec", "port_group": group}}
            else:
                inner["port_group"] = group
            result["port_spec"] = inner
            return result
        
        if negated:
            inner["negated_port"] = {"bnf_category": "negated-port", "port_spec": {"bnf_category": "port-spec", **port_obj}}
        else:
            inner.update(port_obj)
        result["port_spec"] = inner
        return result

    def _parse_port_or_range(self):
        """Parse a port number or port range."""
        port_match = re.match(r'(\d+)?(:)?(\d+)?', self.text[self.pos:])
        if port_match and (port_match.group(1) or port_match.group(3)):
            self.pos += len(port_match.group(0))
            if port_match.group(2):  # Range
                result = {"bnf_category": "port-range"}
                if port_match.group(1):
                    result["start_port"] = {
                        "bnf_category": "port",
                        "port_number": {"bnf_category": "port-number", "value": port_match.group(1)}
                    }
                if port_match.group(3):
                    result["end_port"] = {
                        "bnf_category": "port",
                        "port_number": {"bnf_category": "port-number", "value": port_match.group(3)}
                    }
                return {"port_range": result}
            else:
                return {
                    "port": {
                        "bnf_category": "port",
                        "port_number": {"bnf_category": "port-number", "value": port_match.group(1)}
                    }
                }
        return {}

    def _parse_port_list(self):
        """<port-list> ::= <port-spec> | <port-spec> "," <port-list>"""
        result = {"bnf_category": "port-list", "items": []}

        while True:
            self._skip_whitespace()
            result["items"].append(self._parse_port_spec_inner())
            self._skip_whitespace()
            if self.pos < len(self.text) and self.text[self.pos] == ',':
                self.pos += 1
            else:
                break

        return result

    def _parse_port_spec_inner(self):
        """Parse port-spec without wrapper."""
        inner = {"bnf_category": "port-spec"}
        self._skip_whitespace()

        negated = False
        if self.pos < len(self.text) and self.text[self.pos] == '!':
            negated = True
            self.pos += 1
            self._skip_whitespace()

        if self.pos < len(self.text) and self.text[self.pos] == '$':
            self.pos += 1
            var_name = self._parse_identifier()
            var_obj = {"bnf_category": "variable", "identifier": {"bnf_category": "identifier", "value": var_name}}
            if negated:
                inner["negated_port"] = {"bnf_category": "negated-port", "port_spec": {"bnf_category": "port-spec", "variable": var_obj}}
            else:
                inner["variable"] = var_obj
            return inner

        if self.text[self.pos:].lower().startswith("any"):
            self.pos += 3
            inner["value"] = "any"
            return inner

        port_obj = self._parse_port_or_range()
        if negated and port_obj:
            inner["negated_port"] = {"bnf_category": "negated-port", "port_spec": {"bnf_category": "port-spec", **port_obj}}
        else:
            inner.update(port_obj)
        return inner

    def _parse_identifier(self):
        """Parse an identifier."""
        match = re.match(r'[a-zA-Z_][a-zA-Z0-9_-]*', self.text[self.pos:])
        if match:
            self.pos += len(match.group(0))
            return match.group(0)
        return ""

    def _parse_rule_options(self):
        """<rule-options> ::= <rule-option> | <rule-option> <whitespace>? ";" <whitespace>? <rule-options> | <whitespace>?"""
        result = {"bnf_category": "rule-options", "options": []}

        while self.pos < len(self.text):
            self._skip_whitespace()

            if self.pos >= len(self.text) or self.text[self.pos] == ')':
                break

            option = self._parse_rule_option()
            if option:
                result["options"].append(option)

            self._skip_whitespace()

            if self.pos < len(self.text) and self.text[self.pos] == ';':
                self.pos += 1
            else:
                break

        return result

    def _parse_rule_option(self):
        """Parse a single rule option."""
        self._skip_whitespace()

        if self.pos >= len(self.text) or self.text[self.pos] in ');':
            return None

        # Find the keyword
        keyword_match = re.match(r'([a-zA-Z][a-zA-Z0-9_.-]*)', self.text[self.pos:])
        if not keyword_match:
            return None

        keyword = keyword_match.group(1).lower()
        self.pos += len(keyword_match.group(1))

        result = {"bnf_category": "rule-option"}
        keyword_obj = self._categorize_keyword(keyword)
        result.update(keyword_obj)

        self._skip_whitespace()

        # Check for value
        if self.pos < len(self.text) and self.text[self.pos] == ':':
            self.pos += 1
            self._skip_whitespace()
            value_obj = self._parse_option_value(keyword)
            result["value"] = value_obj

        return result

    def _categorize_keyword(self, keyword):
        """Categorize keyword according to BNF."""
        kw = keyword.lower()

        # Meta keywords
        meta_keywords = {
            "msg": "msg-keyword", "sid": "sid-keyword", "rev": "rev-keyword",
            "gid": "gid-keyword", "classtype": "classtype-keyword",
            "reference": "reference-keyword", "priority": "priority-keyword",
            "metadata": "metadata-keyword", "target": "target-keyword",
            "requires": "requires-keyword"
        }
        if kw in meta_keywords:
            return {"keyword_category": "meta-keyword", "keyword_type": meta_keywords[kw], "keyword": keyword}

        # Payload keywords
        if kw == "content":
            return {"keyword_category": "payload-keyword", "keyword_type": "content-keyword", "keyword": keyword}

        content_modifiers = ["nocase", "depth", "offset", "distance", "within", "startswith", "endswith", "rawbytes"]
        if kw in content_modifiers:
            return {"keyword_category": "payload-keyword", "keyword_type": "content-modifier", "modifier_type": f"{kw}-keyword", "keyword": keyword}

        if kw == "pcre":
            return {"keyword_category": "payload-keyword", "keyword_type": "pcre-keyword", "keyword": keyword}

        byte_keywords = {"byte_test": "byte-test-keyword", "byte_jump": "byte-jump-keyword",
                        "byte_extract": "byte-extract-keyword", "byte_math": "byte-math-keyword"}
        if kw in byte_keywords:
            return {"keyword_category": "payload-keyword", "keyword_type": "byte-keyword", "byte_type": byte_keywords[kw], "keyword": keyword}

        if kw == "dsize":
            return {"keyword_category": "payload-keyword", "keyword_type": "dsize-keyword", "keyword": keyword}
        if kw == "bsize":
            return {"keyword_category": "payload-keyword", "keyword_type": "bsize-keyword", "keyword": keyword}
        if kw == "isdataat":
            return {"keyword_category": "payload-keyword", "keyword_type": "isdataat-keyword", "keyword": keyword}

        # Prefilter keywords
        if kw == "fast_pattern":
            return {"keyword_category": "prefilter-keyword", "keyword_type": "fast-pattern-keyword", "keyword": keyword}
        if kw == "prefilter":
            return {"keyword_category": "prefilter-keyword", "keyword_type": "prefilter-kw", "keyword": keyword}

        # Flow keywords
        if kw == "flow":
            return {"keyword_category": "flow-keyword", "keyword_type": "flow-kw", "keyword": keyword}
        if kw == "flowbits":
            return {"keyword_category": "flow-keyword", "keyword_type": "flowbits-keyword", "keyword": keyword}
        if kw == "flowint":
            return {"keyword_category": "flow-keyword", "keyword_type": "flowint-keyword", "keyword": keyword}
        if kw == "stream_size":
            return {"keyword_category": "flow-keyword", "keyword_type": "stream-size-keyword", "keyword": keyword}
        if kw == "noalert":
            return {"keyword_category": "flow-keyword", "keyword_type": "noalert-keyword", "keyword": keyword}

        # Header keywords - TCP
        tcp_keywords = {"tcp.flags": "tcp-flags-keyword", "flags": "tcp-flags-keyword",
                       "seq": "tcp-seq-keyword", "ack": "tcp-ack-keyword",
                       "window": "tcp-window-keyword", "tcp.mss": "tcp-mss-keyword",
                       "tcp.wscale": "tcp-wscale-keyword", "tcp.hdr": "tcp-hdr-keyword"}
        if kw in tcp_keywords:
            return {"keyword_category": "header-keyword", "keyword_type": "tcp-keyword", "tcp_type": tcp_keywords[kw], "keyword": keyword}

        # Header keywords - UDP
        if kw == "udp.hdr":
            return {"keyword_category": "header-keyword", "keyword_type": "udp-keyword", "udp_type": "udp-hdr-keyword", "keyword": keyword}

        # Header keywords - ICMP
        icmp_keywords = {"itype": "itype-keyword", "icode": "icode-keyword",
                        "icmp_id": "icmp-id-keyword", "icmp_seq": "icmp-seq-keyword",
                        "icmpv4.hdr": "icmpv4-hdr-keyword", "icmpv6.hdr": "icmpv6-hdr-keyword",
                        "icmpv6.mtu": "icmpv6-mtu-keyword"}
        if kw in icmp_keywords:
            return {"keyword_category": "header-keyword", "keyword_type": "icmp-keyword", "icmp_type": icmp_keywords[kw], "keyword": keyword}

        # Header keywords - IP
        ip_keywords = {"ttl": "ttl-keyword", "ipopts": "ipopts-keyword", "sameip": "sameip-keyword",
                      "ip_proto": "ip-proto-keyword", "id": "ipid-keyword", "geoip": "geoip-keyword",
                      "fragbits": "fragbits-keyword", "fragoffset": "fragoffset-keyword",
                      "tos": "tos-keyword", "ipv4.hdr": "ipv4-hdr-keyword", "ipv6.hdr": "ipv6-hdr-keyword"}
        if kw in ip_keywords:
            return {"keyword_category": "header-keyword", "keyword_type": "ip-keyword", "ip_type": ip_keywords[kw], "keyword": keyword}

        # Threshold keywords
        if kw == "threshold":
            return {"keyword_category": "threshold-keyword", "keyword_type": "threshold-kw", "keyword": keyword}
        if kw == "detection_filter":
            return {"keyword_category": "threshold-keyword", "keyword_type": "detection-filter-keyword", "keyword": keyword}

        # HTTP sticky buffers
        http_sticky = ["http.uri", "http.uri.raw", "http.host", "http.host.raw", "http.method",
                      "http.request_line", "http.request_body", "http.response_line", "http.response_body",
                      "http.header", "http.header.raw", "http.header_names", "http.cookie",
                      "http.user_agent", "http.accept", "http.accept_enc", "http.accept_lang",
                      "http.referer", "http.connection", "http.content_len", "http.content_type",
                      "http.location", "http.server", "http.protocol", "http.stat_code",
                      "http.stat_msg", "http.start", "http.request_header", "http.response_header",
                      "file.data", "file.name"]
        if kw in [s.lower() for s in http_sticky]:
            return {"keyword_category": "http-keyword", "keyword_type": "http-sticky-buffer", "keyword": keyword}

        # HTTP content modifiers
        http_modifiers = ["http_uri", "http_raw_uri", "http_method", "http_header", "http_raw_header",
                         "http_cookie", "http_client_body", "http_stat_code", "http_stat_msg",
                         "http_user_agent", "http_host", "http_raw_host"]
        if kw in http_modifiers:
            return {"keyword_category": "http-keyword", "keyword_type": "http-content-modifier", "keyword": keyword}

        if kw == "urilen":
            return {"keyword_category": "http-keyword", "keyword_type": "http-other", "other_type": "urilen-keyword", "keyword": keyword}

        # HTTP/2 keywords
        if kw.startswith("http2."):
            return {"keyword_category": "http2-keyword", "keyword": keyword}

        # File keywords
        file_keywords = ["filemagic", "filemd5", "filesha1", "filesha256", "filesize", "filestore", "filename", "fileext"]
        if kw in file_keywords:
            return {"keyword_category": "file-keyword", "keyword_type": f"{kw}-keyword", "keyword": keyword}

        # TLS keywords
        tls_sticky = ["tls.cert_subject", "tls.cert_issuer", "tls.cert_serial", "tls.cert_fingerprint",
                     "tls.sni", "tls.certs", "tls.version", "tls.subject", "tls.issuerdn",
                     "tls.cert_chain_len", "tls.cert_notbefore", "tls.cert_notafter", "tls.random",
                     "tls.alpn", "ja3.hash", "ja3.string", "ja3s.hash", "ja3s.string"]
        if kw in [t.lower() for t in tls_sticky]:
            return {"keyword_category": "tls-keyword", "keyword_type": "tls-sticky-buffer", "keyword": keyword}
        if kw in ["ssl_version", "ssl_state", "tls.fingerprint"]:
            return {"keyword_category": "tls-keyword", "keyword_type": "tls-other", "keyword": keyword}

        # DNS keywords
        dns_sticky = ["dns.query", "dns.answer", "dns.answer.name", "dns.authority", "dns.authority.name", "dns.opcode", "dns.rrtype"]
        if kw in [d.lower() for d in dns_sticky]:
            return {"keyword_category": "dns-keyword", "keyword_type": "dns-sticky-buffer", "keyword": keyword}

        # mDNS keywords
        if kw.startswith("mdns."):
            return {"keyword_category": "mdns-keyword", "keyword_type": "mdns-sticky-buffer", "keyword": keyword}

        # SSH keywords
        if kw.startswith("ssh."):
            return {"keyword_category": "ssh-keyword", "keyword_type": "ssh-sticky-buffer", "keyword": keyword}

        # Legacy keyword aliases (only when enable_legacy_support=True)
        if self.enable_legacy_support:
            # Payload
            if kw == "base64_data":
                return {"keyword_category": "payload-keyword", "keyword_type": "base64-data-keyword", "keyword": keyword}
            if kw == "dotprefix":
                return {"keyword_category": "payload-keyword", "keyword_type": "content-modifier", "modifier_type": "dotprefix-keyword", "keyword": keyword}
            # DNS legacy alias
            if kw == "dns_query":
                return {"keyword_category": "dns-keyword", "keyword_type": "dns-sticky-buffer", "keyword": keyword}
            # File legacy alias
            if kw == "file_data":
                return {"keyword_category": "http-keyword", "keyword_type": "http-sticky-buffer", "keyword": keyword}
            # HTTP content-modifier legacy aliases
            if kw in ["http_content_type", "http_header_names", "http_referer", "http_server_body"]:
                return {"keyword_category": "http-keyword", "keyword_type": "http-content-modifier", "keyword": keyword}
            # TLS / JA3 legacy aliases
            if kw in ["tls_cert_issuer", "tls_cert_subject", "tls_sni", "ja3_hash"]:
                return {"keyword_category": "tls-keyword", "keyword_type": "tls-sticky-buffer", "keyword": keyword}
            # SSH legacy alias
            if kw == "ssh_proto":
                return {"keyword_category": "ssh-keyword", "keyword_type": "ssh-sticky-buffer", "keyword": keyword}

        # FTP keywords
        if kw.startswith("ftp.") or kw in ["ftpdata_command", "ftpbounce"]:
            return {"keyword_category": "ftp-keyword", "keyword": keyword}

        # SMTP keywords
        if kw.startswith("smtp."):
            return {"keyword_category": "smtp-keyword", "keyword_type": "smtp-sticky-buffer", "keyword": keyword}

        # DHCP keywords
        if kw.startswith("dhcp."):
            return {"keyword_category": "dhcp-keyword", "keyword": keyword}

        # SNMP keywords
        if kw.startswith("snmp."):
            return {"keyword_category": "snmp-keyword", "keyword": keyword}

        # WebSocket keywords
        if kw.startswith("websocket."):
            return {"keyword_category": "websocket-keyword", "keyword": keyword}

        # IP reputation keywords
        if kw == "iprep":
            return {"keyword_category": "iprep-keyword", "keyword": keyword}

        # Frame keywords
        if kw == "frame":
            return {"keyword_category": "frame-keyword", "keyword": keyword}

        # Other keywords
        other_keywords = {
            "app-layer-protocol": "app-layer-protocol-keyword",
            "lua": "lua-keyword", "xbits": "xbits-keyword",
            "dataset": "dataset-keyword", "datarep": "datarep-keyword",
            "tag": "tag-keyword", "config": "config-keyword",
            "pkt_data": "pkt-data-keyword"
        }
        if kw in other_keywords:
            return {"keyword_category": "other-keyword", "keyword_type": other_keywords[kw], "keyword": keyword}

        return {"keyword_category": "rule-option", "keyword": keyword}

    def _parse_option_value(self, keyword):
        """Parse option value based on keyword type."""
        result = {"bnf_category": "option-value"}

        value_parts = []
        in_quotes = False
        escape_next = False
        depth = 0

        while self.pos < len(self.text):
            ch = self.text[self.pos]

            if escape_next:
                value_parts.append(ch)
                escape_next = False
                self.pos += 1
                continue

            if ch == '\\':
                escape_next = True
                value_parts.append(ch)
                self.pos += 1
                continue

            if ch == '"':
                in_quotes = not in_quotes
                value_parts.append(ch)
                self.pos += 1
                continue

            if not in_quotes:
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    if depth == 0:
                        break
                    depth -= 1
                elif ch == ';' and depth == 0:
                    break

            value_parts.append(ch)
            self.pos += 1

        value = ''.join(value_parts).strip()
        result["raw_value"] = value

        # Parse specific value types based on keyword
        kw = keyword.lower()

        if kw == "msg":
            result["quoted_string"] = {"bnf_category": "quoted-string", "string_content": {"bnf_category": "string-content", "value": value.strip('"')}}
        elif kw == "tls.fingerprint":
            result["quoted_string"] = {"bnf_category": "quoted-string", "string_content": {"bnf_category": "string-content", "value": value.strip('"')}}
        elif kw in ["sid", "rev", "gid", "priority"]:
            result["number"] = {"bnf_category": "number", "value": value}
        elif kw == "classtype":
            result["classtype_name"] = {"bnf_category": "classtype-name", "value": value}
        elif kw == "reference":
            if ',' in value:
                parts = value.split(',', 1)
                result["reference_type"] = {"bnf_category": "reference-type", "value": parts[0]}
                result["reference_value"] = {"bnf_category": "reference-value", "unquoted_string": {"bnf_category": "unquoted-string", "value": parts[1]}}
        elif kw == "content":
            result["content_value"] = self._parse_content_value(value)
        elif kw == "pcre":
            result["quoted_regex"] = {"bnf_category": "quoted-regex", "value": value}
        elif kw == "flow":
            result["flow_options"] = self._parse_flow_options(value)
        elif kw == "flowbits":
            result["flowbits_cmd"] = {"bnf_category": "flowbits-cmd", "value": value}
        elif kw in ["depth", "offset", "distance", "within"]:
            result["number"] = {"bnf_category": "number", "value": value}
        elif kw == "dsize":
            result["dsize_spec"] = {"bnf_category": "dsize-spec", "value": value}
        elif kw == "flags":
            result["tcp_flags_spec"] = {"bnf_category": "tcp-flags-spec", "value": value}
        elif kw == "fast_pattern":
            if value:
                result["fast_pattern_opts"] = {"bnf_category": "fast-pattern-opts", "value": value}
        elif kw == "threshold":
            result["threshold_spec"] = self._parse_threshold_spec(value)
        elif kw == "metadata":
            result["metadata_list"] = {"bnf_category": "metadata-list", "value": value}
        elif ',' in value:
            parts = self._split_value(value)
            result["value_list"] = {"bnf_category": "value-list", "items": [{"bnf_category": "value-item", "value": p.strip()} for p in parts]}

        return result

    def _parse_content_value(self, value):
        """Parse content value."""
        result = {"bnf_category": "content-value"}
        if value.startswith('!'):
            result["negated_content"] = {
                "bnf_category": "negated-content",
                "quoted_string": {"bnf_category": "quoted-string", "value": value[1:]}
            }
        else:
            result["quoted_string"] = {"bnf_category": "quoted-string", "value": value}
        return result

    def _parse_flow_options(self, value):
        """Parse flow options."""
        result = {"bnf_category": "flow-options", "options": []}
        parts = [p.strip() for p in value.split(',')]
        for part in parts:
            result["options"].append({"bnf_category": "flow-option", "value": part})
        return result

    def _parse_threshold_spec(self, value):
        """Parse threshold specification."""
        result = {"bnf_category": "threshold-spec", "raw": value}
        # Parse type, track, count, seconds
        type_match = re.search(r'type\s+(\w+)', value)
        track_match = re.search(r'track\s+(\w+)', value)
        count_match = re.search(r'count\s+(\d+)', value)
        seconds_match = re.search(r'seconds\s+(\d+)', value)

        if type_match:
            result["threshold_type"] = {"bnf_category": "threshold-type", "value": type_match.group(1)}
        if track_match:
            result["track_by"] = {"bnf_category": "track-by", "value": track_match.group(1)}
        if count_match:
            result["count"] = {"bnf_category": "number", "value": count_match.group(1)}
        if seconds_match:
            result["seconds"] = {"bnf_category": "number", "value": seconds_match.group(1)}

        return result

    def _split_value(self, value):
        """Split value by commas, respecting quotes."""
        parts = []
        current = []
        in_quotes = False
        escape_next = False

        for ch in value:
            if escape_next:
                current.append(ch)
                escape_next = False
                continue

            if ch == '\\':
                escape_next = True
                current.append(ch)
                continue

            if ch == '"':
                in_quotes = not in_quotes
                current.append(ch)
                continue

            if ch == ',' and not in_quotes:
                parts.append(''.join(current))
                current = []
                continue

            current.append(ch)

        if current:
            parts.append(''.join(current))

        return parts

    # ------------------------------------------------------------------
    # DataFrame helpers
    # ------------------------------------------------------------------

    def _extract_single_address(self, addr):
        """Return a string representation of a single address dict."""
        if not isinstance(addr, dict):
            return ''
        if addr.get('value') == 'any':
            return 'any'
        if 'ipv4_cidr' in addr:
            cidr = addr['ipv4_cidr']
            octets = cidr.get('ipv4_address', {}).get('octets', [])
            prefix = cidr.get('cidr_prefix', {}).get('value', '')
            return '.'.join(o.get('value', '') for o in octets) + '/' + prefix
        if 'ipv4_address' in addr:
            octets = addr['ipv4_address'].get('octets', [])
            return '.'.join(o.get('value', '') for o in octets)
        if 'ipv6_cidr' in addr:
            cidr = addr['ipv6_cidr']
            ip = cidr.get('ipv6_address', {}).get('value', '')
            prefix = cidr.get('cidr_prefix', {}).get('value', '')
            return f'{ip}/{prefix}'
        if 'ipv6_address' in addr:
            return addr['ipv6_address'].get('value', '')
        return ''

    def _extract_address_inner_str(self, inner):
        """Return a string representation of an address-spec dict (no wrapper)."""
        if not isinstance(inner, dict):
            return ''
        if 'variable' in inner:
            return '$' + inner['variable'].get('identifier', {}).get('value', '')
        if 'negated_address' in inner:
            neg = inner['negated_address'].get('address_spec', {})
            return '!' + self._extract_address_inner_str(neg)
        if 'address_group' in inner:
            items = inner['address_group'].get('address_list', {}).get('items', [])
            return '[' + ','.join(self._extract_address_inner_str(i) for i in items) + ']'
        if 'address' in inner:
            return self._extract_single_address(inner['address'])
        return ''

    def _extract_address_str(self, addr_spec):
        """Return a string representation of a wrapped address-spec dict."""
        if not isinstance(addr_spec, dict):
            return ''
        return self._extract_address_inner_str(addr_spec.get('address_spec', {}))

    def _extract_port_inner_str(self, inner):
        """Return a string representation of a port-spec dict (no wrapper)."""
        if not isinstance(inner, dict):
            return ''
        if inner.get('value') == 'any':
            return 'any'
        if 'variable' in inner:
            return '$' + inner['variable'].get('identifier', {}).get('value', '')
        if 'negated_port' in inner:
            neg = inner['negated_port'].get('port_spec', {})
            return '!' + self._extract_port_inner_str(neg)
        if 'port_group' in inner:
            items = inner['port_group'].get('port_list', {}).get('items', [])
            return '[' + ','.join(self._extract_port_inner_str(i) for i in items) + ']'
        if 'port_range' in inner:
            pr = inner['port_range']
            start = pr.get('start_port', {}).get('port_number', {}).get('value', '')
            end = pr.get('end_port', {}).get('port_number', {}).get('value', '')
            return f'{start}:{end}'
        if 'port' in inner:
            return inner['port'].get('port_number', {}).get('value', '')
        return ''

    def _extract_port_str(self, port_spec):
        """Return a string representation of a wrapped port-spec dict."""
        if not isinstance(port_spec, dict):
            return ''
        return self._extract_port_inner_str(port_spec.get('port_spec', {}))

    def _extract_value_str(self, value_obj):
        """Return the raw_value string from an option-value dict."""
        if not isinstance(value_obj, dict):
            return ''
        raw = value_obj.get('raw_value', '')
        return raw if raw is not None else ''

    def to_flat_dict(self, parsed):
        """
        Convert a parsed rule dict into a flat dict suitable for a DataFrame row.

        Fixed columns: action, protocol, src_address, src_port, direction,
                       dst_address, dst_port.
        Dynamic columns: one ``opt_<keyword>`` column per option keyword found
                         in the rule (dots and hyphens replaced with underscores).
                         When a keyword appears multiple times its values are
                         joined with a pipe ``|`` separator.
        """
        row = {}

        # --- action ---
        action = parsed.get('action', {})
        row['action'] = action.get('value', '') if isinstance(action, dict) else ''

        # --- header ---
        header = parsed.get('header', {})
        if isinstance(header, dict):
            proto = header.get('protocol', {})
            if isinstance(proto, dict):
                if 'network_protocol' in proto:
                    row['protocol'] = proto['network_protocol'].get('value', '')
                elif 'application_protocol' in proto:
                    row['protocol'] = proto['application_protocol'].get('value', '')
                elif 'explicit_hook' in proto:
                    hook = proto['explicit_hook']
                    pname = hook.get('protocol_name', {}).get('value', '')
                    hname = hook.get('hook_name', {}).get('value', '')
                    row['protocol'] = f'{pname}:{hname}'
                else:
                    row['protocol'] = ''
            else:
                row['protocol'] = ''

            row['src_address'] = self._extract_address_str(header.get('source_address', {}))
            row['src_port'] = self._extract_port_str(header.get('source_port', {}))
            direction = header.get('direction', {})
            row['direction'] = direction.get('value', '') if isinstance(direction, dict) else ''
            row['dst_address'] = self._extract_address_str(header.get('dest_address', {}))
            row['dst_port'] = self._extract_port_str(header.get('dest_port', {}))
        else:
            for col in ('protocol', 'src_address', 'src_port', 'direction', 'dst_address', 'dst_port'):
                row[col] = ''

        # --- rule options ---
        rule_options = parsed.get('rule_options', {})
        options = rule_options.get('options', []) if isinstance(rule_options, dict) else []

        for opt in options:
            if not isinstance(opt, dict):
                continue
            keyword = opt.get('keyword', '')
            if not keyword:
                continue
            col = 'opt_' + re.sub(r'[^a-zA-Z0-9]', '_', keyword)
            value_str = self._extract_value_str(opt.get('value', {}))
            if col in row:
                row[col] = row[col] + '|' + value_str
            else:
                row[col] = value_str

        return row


def parse_to_dataframe(rules_source, errors_only=False, enable_legacy_support=False):
    """
    Parse Suricata rules and return a flat pandas DataFrame.

    Parameters
    ----------
    rules_source : str or iterable of str
        Either a file path (str) to a ``.rules`` file, or any iterable that
        yields raw rule strings (e.g. a list, ``sys.stdin``, or an open file).
    errors_only : bool
        When ``True`` only rules that failed to parse are included.
        When ``False`` (default) only successfully parsed rules are included.

    Returns
    -------
    pandas.DataFrame
        One row per rule.  Fixed columns are ``action``, ``protocol``,
        ``src_address``, ``src_port``, ``direction``, ``dst_address``,
        ``dst_port``.
        Additional ``opt_<keyword>`` columns are created dynamically for every
        option keyword encountered across all rules.

    Examples
    --------
    >>> import parse_suricata_rules as psr
    >>> df = psr.parse_to_dataframe('my.rules')
    >>> df[['action', 'protocol', 'opt_msg', 'opt_sid']].head()
    """
    try:
        import pandas as pd
    except ImportError as exc:
        raise ImportError(
            "pandas is required for parse_to_dataframe(). "
            "Install it with: pip install pandas"
        ) from exc

    parser = SuricataParser(enable_legacy_support=enable_legacy_support)
    rows = []

    if isinstance(rules_source, str):
        stream = open(rules_source, 'r', encoding='utf-8', errors='replace')
        close_stream = True
    else:
        stream = rules_source
        close_stream = False

    try:
        for line_num, line in enumerate(stream, 1):
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='replace')
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parsed = parser.parse_rule(line)
            if not parsed:
                continue

            has_error = 'error' in parsed

            if errors_only and not has_error:
                continue
            if not errors_only and has_error:
                continue

            rows.append(parser.to_flat_dict(parsed))
    finally:
        if close_stream:
            stream.close()

    return pd.DataFrame(rows)


def _write_csv(rows, dest):
    """
    Write a list of flat rule dicts to *dest* as CSV.

    Parameters
    ----------
    rows : list[dict]
        Flat dicts produced by :meth:`SuricataParser.to_flat_dict`.
    dest : str or ``'-'``
        Output file path, or ``'-'`` to write to stdout.
    """
    if not rows:
        if dest != '-':
            # Write an empty file
            open(dest, 'w').close()
        return

    # Collect all column names preserving insertion order:
    # fixed columns first, then dynamic opt_* columns.
    fixed = ['action', 'protocol', 'src_address', 'src_port',
             'direction', 'dst_address', 'dst_port']
    opt_cols = []
    seen = set(fixed)
    for row in rows:
        for k in row:
            if k not in seen:
                opt_cols.append(k)
                seen.add(k)
    fieldnames = fixed + opt_cols

    if dest == '-':
        writer = csv.DictWriter(
            sys.stdout, fieldnames=fieldnames,
            extrasaction='ignore', lineterminator='\n'
        )
        writer.writeheader()
        writer.writerows(rows)
    else:
        with open(dest, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f, fieldnames=fieldnames,
                extrasaction='ignore', lineterminator='\n'
            )
            writer.writeheader()
            writer.writerows(rows)


def main():
    arg_parser = argparse.ArgumentParser(
        description="Suricata Rules Parser - Parse rules and output a flat CSV DataFrame.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Parse rules file to CSV
  python parse_suricata_rules.py -i rules.rules -c output.csv

  # Read from stdin, write to stdout
  echo 'alert tcp any any -> any any (msg:"test"; sid:1;)' | python parse_suricata_rules.py -c -

  # Pipe from generator to parser
  python generate_rules.py -n 5 | python parse_suricata_rules.py -c output.csv

  # Output only parsing errors
  python parse_suricata_rules.py -e -i rules.rules -c errors.csv

  # Output rules with annotations as comments
  python parse_suricata_rules.py -i rules.rules -c output.csv -r annotated.rules

  # Use as a library in Jupyter / Python scripts
  import parse_suricata_rules as psr
  df = psr.parse_to_dataframe('my.rules')
  print(df[['action', 'protocol', 'opt_msg', 'opt_sid']].head())
""")
    arg_parser.add_argument("-i", "--input-file", type=str, default="-",
                           help="Input rules file (default: stdin)")
    arg_parser.add_argument("-c", "--csv-output", type=str, default=None,
                           help="Output CSV file (use '-' for stdout)")
    arg_parser.add_argument("-e", "--errors-only", action="store_true",
                           help="Output only rules with parsing errors")
    arg_parser.add_argument("-r", "--rules-output", type=str, default=None,
                           help="Output rules file with duplicate/prefilter annotations as comments")
    arg_parser.add_argument("-l", "--legacy", action="store_true", default=False,
                           help="Enable legacy underscore-form keyword aliases (e.g. dns_query, file_data, tls_sni, tls_cert_issuer, tls_cert_subject, ja3_hash, ssh_proto, http_content_type, http_header_names, http_referer, http_server_body, base64_data, dotprefix)")

    args = arg_parser.parse_args()

    parser = SuricataParser(enable_legacy_support=args.legacy)
    parsed_rules = []   # raw parsed dicts (needed for --rules-output)
    flat_rows = []      # flat dicts for CSV output
    error_count = 0

    if args.input_file == '-':
        input_stream = sys.stdin
    else:
        input_stream = open(args.input_file, 'r', encoding='utf-8', errors='replace')

    try:
        for line_num, line in enumerate(input_stream, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parsed = parser.parse_rule(line)
            if parsed:
                parsed["line_number"] = line_num
                parsed["rule"] = line
                if "error" in parsed:
                    print(f"Error parsing line {line_num}: {parsed['error']}", file=sys.stderr)
                    error_count += 1
                    if args.errors_only:
                        parsed_rules.append(parsed)
                        flat_rows.append(parser.to_flat_dict(parsed))
                else:
                    if not args.errors_only:
                        parsed_rules.append(parsed)
                        flat_rows.append(parser.to_flat_dict(parsed))

            if line_num % 1000 == 0:
                print(f"Processed {line_num} lines...", file=sys.stderr)
    finally:
        if args.input_file != '-':
            input_stream.close()

    if args.csv_output:
        _write_csv(flat_rows, args.csv_output)
        if args.csv_output != '-':
            print(f"Parsed {len(flat_rows)} rules to {args.csv_output}", file=sys.stderr)

    # Write annotated rules file if requested
    if args.rules_output:
        with open(args.rules_output, 'w', encoding='utf-8') as f:
            for parsed in parsed_rules:
                comments = []
                if "duplicate" in parsed:
                    for dup in parsed["duplicate"]:
                        comments.append(f"# duplicate: content={dup['content_value']} count={dup['occurrence_count']} indices={dup['option_indices']}")
                if "prefilter" in parsed:
                    comments.append(f"# prefilter: {parsed['prefilter']}")
                if comments:
                    f.write('\n'.join(comments) + '\n')
                f.write(parsed.get("rule", "") + '\n')
        print(f"Wrote annotated rules to {args.rules_output}", file=sys.stderr)

    sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()