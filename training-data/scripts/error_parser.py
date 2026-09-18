#!/usr/bin/env python3
"""
Suricata error log parser.

Reads Suricata validation output (from a log file or stdin) and groups
failed rules by their detect-parse error message, using the canonical
error templates from suricata_errors.txt to merge errors that differ only
in embedded IDs, protocol names, or other variable values.

Usage:
    # From a saved log file:
    python error_parser.py errors.log

    # Custom templates file:
    python error_parser.py errors.log --templates /path/to/suricata_errors.txt

    # Directly from suricata (stderr must be redirected to stdout):
    suricata -T -c /opt/homebrew/etc/suricata/suricata.yaml -S bad.rules 2>&1 | python error_parser.py

    # Capture only errors (suppress suricata stdout):
    suricata -T -c /opt/homebrew/etc/suricata/suricata.yaml -S bad.rules 2>&1 >/dev/null | python error_parser.py
"""

import os
import sys
import re
import argparse
from collections import OrderedDict


# ---------------------------------------------------------------------------
# Log line regexes
# ---------------------------------------------------------------------------

# Matches:  E: detect-parse: <message>
DETECT_PARSE_RE = re.compile(r"^E: detect-parse: (.+)$")

# Matches:  E: detect: error parsing signature "<rule>" from file <f> at line <n>
# Uses a greedy inner group so that embedded quotes inside the rule (e.g. msg:"…")
# are captured correctly — the trailing anchor `" from file … at line \d+$` forces
# backtracking to the last quote before " from file".
SIGNATURE_RE = re.compile(
    r'^E: detect: error parsing signature "(.+)" from file .+ at line \d+$'
)

# ---------------------------------------------------------------------------
# Template loading and matching
# ---------------------------------------------------------------------------

# Matches C printf-style format specifiers, including:
#   %s  %S  %d  %i  %u  %o  %x  %X  %ld  %lu  %lx  %li  %zu  %c  %f  %g  %e
#   %'  (C99 thousands-separator prefix, e.g. %'d  %'PRIu64)
#   %   followed by digits/flags then a letter (e.g. %d, %5d, %02x …)
# Also handles a bare trailing `%` (truncated specifier in some error strings).
_FMT_SPEC_RE = re.compile(
    r"%(?:'[a-zA-Z]*|[0-9.*+\-#]*(?:l{0,2}|z|h|j|t)?[dDiuUoOxXeEfFgGaAcCsSpnqb]|[0-9.*+\-#]*(?:l{0,2}|z|h)?$)"
)


def _template_to_regex(template: str) -> re.Pattern:
    """
    Convert a Suricata printf-style error template to a compiled regex.

    Steps:
      1. Strip surrounding single-quotes added by the template file format.
      2. Unescape C-style \\\" → " and \\\\ → \\
      3. Replace printf format specifiers with appropriate regex atoms.
      4. Escape all remaining literal characters.
      5. Collapse runs of literal spaces into \\s+ to tolerate varying whitespace.
    """
    # Strip outer single-quotes (first and last character of each non-empty line)
    if len(template) >= 2 and template[0] == "'" and template[-1] == "'":
        template = template[1:-1]

    # Unescape C-style escape sequences used in the template file
    template = template.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")

    # Walk through the template, building a list of regex fragments
    fragments: list[str] = []
    last = 0
    for m in _FMT_SPEC_RE.finditer(template):
        # Escape the literal text before this format specifier
        literal = template[last : m.start()]
        if literal:
            fragments.append(re.escape(literal))
        spec = m.group()
        # Map the specifier to a regex atom
        last_char = spec[-1]
        if last_char in "dDiuUoOxXeEfFgGaApq" or spec.endswith("'"):
            # Numeric / pointer / thousands-sep → any non-whitespace token
            fragments.append(r"\S+")
        elif last_char == "c":
            fragments.append(r".")
        elif last_char in "sS":
            fragments.append(r"\S+")
        else:
            # Catch-all (bare %, etc.)
            fragments.append(r"\S*")
        last = m.end()

    # Append any remaining literal text after the last specifier
    tail = template[last:]
    if tail:
        fragments.append(re.escape(tail))

    pattern = "".join(fragments)

    # Normalise whitespace: one or more escaped spaces → \s+ so that
    # templates with a single space match error messages with two spaces, etc.
    pattern = re.sub(r"(?:\\ )+", r"\\s+", pattern)

    return re.compile("^" + pattern + "$")


def load_templates(path: str) -> list[tuple[str, re.Pattern]]:
    """
    Read suricata_errors.txt and return a list of (canonical_label, regex) pairs.

    The canonical label is the template text with outer quotes stripped (used as
    the display key in the output index and detail sections).
    """
    templates: list[tuple[str, re.Pattern]] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or not line.startswith("'"):
                continue
            # canonical label: strip outer quotes + unescape
            label = line[1:-1].replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
            try:
                pattern = _template_to_regex(line)
                templates.append((label, pattern))
            except re.error:
                # Skip any template that produces an invalid regex
                pass
    return templates


def _default_templates_path() -> str | None:
    """
    Try to locate suricata_errors.txt relative to this script's location.
    Looks in the parent directory (training-data/) of the scripts/ folder.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(script_dir, "..", "suricata_errors.txt")
    candidate = os.path.normpath(candidate)
    return candidate if os.path.isfile(candidate) else None


def canonicalize_error(raw_msg: str, templates: list[tuple[str, re.Pattern]]) -> str:
    """
    Match *raw_msg* (the text after 'E: detect-parse: ') against the loaded
    templates and return the canonical label for the first match.

    Falls back to the raw message itself if no template matches.
    """
    for label, pattern in templates:
        if pattern.fullmatch(raw_msg):
            return label
    return raw_msg


def parse_errors(lines: list[str], templates: list[tuple[str, re.Pattern]]) -> OrderedDict:
    """
    Parse log lines into an ordered mapping of canonical_error_label -> [rule, …].

    Each 'E: detect-parse: …' message is matched against the loaded templates
    so that errors differing only in embedded IDs/names land in the same group.
    Insertion order is preserved (first occurrence of each canonical error type).
    """
    grouped: OrderedDict[str, list[str]] = OrderedDict()
    pending_key: str | None = None  # canonical group key for the next rule line

    # Cache raw_msg → canonical_key to avoid re-running all regexes for repeated errors
    _cache: dict[str, str] = {}

    for raw_line in lines:
        line = raw_line.rstrip("\n")

        dp_match = DETECT_PARSE_RE.match(line)
        if dp_match:
            raw_msg = dp_match.group(1)
            if raw_msg not in _cache:
                _cache[raw_msg] = canonicalize_error(raw_msg, templates)
            pending_key = _cache[raw_msg]
            continue

        sig_match = SIGNATURE_RE.match(line)
        if sig_match:
            rule = sig_match.group(1)
            if pending_key is not None:
                grouped.setdefault(pending_key, []).append(rule)
                pending_key = None
            else:
                fallback = "(unknown error)"
                grouped.setdefault(fallback, []).append(rule)
            continue

        # Any other E: line that isn't E: detect: clears the pending key
        if line.startswith("E:") and not line.startswith("E: detect:"):
            pending_key = None

    return grouped


DIVIDER = "=" * 80


def format_output(grouped: OrderedDict) -> str:
    """
    Format output as:

        INDEX
        -----
        1. <canonical error label>
        2. <canonical error label>
        …

        ================================================================================

        E: detect-parse: <canonical error label>
        <rule 1>
        <rule 2>
        …

        E: detect-parse: <next canonical error label>
        <rule>
        …
    """
    # --- Index section ---
    index_lines = ["INDEX", "-" * 5]
    for i, label in enumerate(grouped.keys(), start=1):
        index_lines.append(f"{i}. {label}")

    # --- Detail sections ---
    blocks = []
    for label, rules in grouped.items():
        header = f"E: detect-parse: {label}"
        block_lines = [header] + rules
        blocks.append("\n".join(block_lines))

    detail_section = "\n\n".join(blocks)

    return "\n".join(index_lines) + "\n\n" + DIVIDER + "\n\n" + detail_section


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Suricata error logs and group failed rules by error type.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        help="Path to the Suricata error log file (reads from stdin if omitted).",
    )
    parser.add_argument(
        "--templates",
        metavar="FILE",
        default=None,
        help=(
            "Path to suricata_errors.txt containing canonical error templates. "
            "Defaults to ../suricata_errors.txt relative to this script."
        ),
    )
    args = parser.parse_args()

    # --- Load templates ---
    templates_path = args.templates or _default_templates_path()
    if templates_path:
        templates = load_templates(templates_path)
    else:
        templates = []
        print(
            "Warning: no suricata_errors.txt found; grouping by raw error strings.",
            file=sys.stderr,
        )

    # --- Read log input ---
    if args.logfile:
        with open(args.logfile, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    else:
        if sys.stdin.isatty():
            parser.print_help()
            sys.exit(0)
        lines = sys.stdin.readlines()

    grouped = parse_errors(lines, templates)

    if not grouped:
        print("No errors found.", file=sys.stderr)
        sys.exit(0)

    print(format_output(grouped))


if __name__ == "__main__":
    main()
