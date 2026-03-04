#!/usr/bin/env python3
"""
Line-by-line YAML parser that builds a Python dict strictly by scanning lines.
It avoids recursive block parsing and handles these malformations:
- multi-line quoted strings (opening quote on same or next line)
- space-separated quoted values treated as arrays

This parser favors robustness and best-effort recovery rather than strict YAML conformance.
"""

import sys
import re
import json
import argparse
from typing import Any, Dict, List, Tuple

try:
    import yaml
except ImportError:
    yaml = None


def get_indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def parse_scalar(value: str, lines: List[str], idx_ref: List[int]) -> Any:
    """Parse a scalar value. idx_ref is a single-item list holding current index
    so this function can advance it when consuming extra lines for multi-line strings."""
    v = value.strip()
    if not v:
        return None

    # Quoted array: "a" "b"
    if v.startswith('"') and '" "' in v:
        return re.findall(r'"([^\"]*)"', v)

    # Lone quote on the value (e.g. value == '"') - handle BEFORE complete quoted check
    # because a single quote char both starts and ends with itself
    if v == '"':
        # collect until closing quote line
        quote = '"'
        parts = []
        idx = idx_ref[0]
        while idx < len(lines):
            line = lines[idx]
            if quote in line:
                closing = line.index(quote)
                parts.append(line[:closing])
                idx_ref[0] = idx + 1
                return "\n".join(p.rstrip() for p in parts)
            parts.append(line.rstrip())
            idx += 1
        raise ValueError("UNCLOSED_QUOTE: reached EOF without closing quote")

    # Exact quoted (single-line)
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]

    # Opening quote without closing -> collect until closing quote
    if v.startswith('"') and not v.endswith('"'):
        quote = '"'
        parts = [v[1:]]
        idx = idx_ref[0]
        while idx < len(lines):
            line = lines[idx]
            if quote in line:
                closing = line.index(quote)
                parts.append(line[:closing])
                idx_ref[0] = idx + 1
                return "\n".join(p.rstrip() for p in parts)
            parts.append(line.rstrip())
            idx += 1
        raise ValueError("UNCLOSED_QUOTE: reached EOF without closing quote")

    # Null/booleans/numbers
    if v in ('null', 'Null', 'NULL', '~'):
        return None
    if v.lower() in ('true', 'yes', 'on'):
        return True
    if v.lower() in ('false', 'no', 'off'):
        return False
    if re.match(r'^-?\d+$', v):
        return int(v)
    if re.match(r'^-?\d+\.\d+$', v):
        return float(v)

    return v


class LineByLineParser:
    def __init__(self, filename: str):
        self.filename = filename
        self.lines: List[str] = []
        self.root: Dict[str, Any] = {}

    def load(self):
        with open(self.filename, 'r') as f:
            self.lines = f.readlines()

    def parse(self) -> Dict[str, Any]:
        i = 0
        n = len(self.lines)
        stack: List[Tuple[int, Any]] = [(-1, self.root)]  # (indent, container)

        while i < n:
            raw = self.lines[i]
            if not raw.strip() or raw.lstrip().startswith('#'):
                i += 1
                continue

            indent = get_indent(raw)
            content = raw.lstrip()

            # Pop stack until top has indent < current
            while stack and indent <= stack[-1][0]:
                stack.pop()
            if not stack:
                raise ValueError(f"Indentation error at line {i+1}")

            parent = stack[-1][1]

            # List item
            if content.startswith('- '):
                item_text = content[2:].strip()

                # Ensure parent is a list; if parent is dict, attach to last key
                if isinstance(parent, dict):
                    if len(parent) == 0:
                        raise ValueError(f"No key to attach list to at line {i+1}")
                    last_key = list(parent.keys())[-1]
                    if not isinstance(parent[last_key], list):
                        # convert empty dict or None to list, otherwise overwrite
                        if parent[last_key] == {} or parent[last_key] is None:
                            parent[last_key] = []
                        else:
                            parent[last_key] = []
                    lst = parent[last_key]
                elif isinstance(parent, list):
                    lst = parent
                else:
                    raise ValueError(f"Unexpected parent type for list at line {i+1}: {type(parent).__name__}")

                # item_text may be '135:' or 'key: value'
                if ':' in item_text:
                    k, _, v = item_text.partition(':')
                    k = k.strip()
                    v = v.strip()
                    item: Dict[str, Any] = {}
                    if v:
                        idx_ref = [i+1]
                        item[k] = parse_scalar(v, self.lines, idx_ref)
                        i = idx_ref[0]
                    else:
                        # value is a nested block -> create empty dict and push
                        item[k] = {}
                        lst.append(item)
                        # push this new dict onto stack with current indent
                        stack.append((indent, item[k]))
                        i += 1
                        continue
                    lst.append(item)
                    i += 1
                    continue

                # simple list element (scalar)
                idx_ref = [i+1]
                val = parse_scalar(item_text, self.lines, idx_ref)
                lst.append(val)
                i = idx_ref[0]
                continue

            # Key-value
            if ':' in content:
                key, _, rest = content.partition(':')
                key = key.strip()
                rest = rest.strip()

                # If parent is a list, attach this key to the last element dict
                target_parent = parent
                if isinstance(parent, list):
                    if len(parent) == 0:
                        raise ValueError(f"List parent has no element to attach mapping at line {i+1}")
                    last_elem = parent[-1]
                    if not isinstance(last_elem, dict):
                        # convert scalar last element into a dict container
                        newd: Dict[str, Any] = {}
                        parent[-1] = newd
                        last_elem = newd
                    target_parent = last_elem

                if rest == '':
                    # Peek next non-empty non-comment line to decide whether this key holds
                    # a list (next line starts with '-') or a nested dict
                    peek = i + 1
                    while peek < n and (not self.lines[peek].strip() or self.lines[peek].lstrip().startswith('#')):
                        peek += 1
                    if peek < n and self.lines[peek].lstrip().startswith('- '):
                        # If the key already exists and is a list, reuse it; otherwise create new
                        if key not in target_parent or not isinstance(target_parent[key], list):
                            target_parent[key] = []
                        stack.append((indent, target_parent[key]))
                        i += 1
                        continue
                    # otherwise nested dict - only create if it doesn't exist or isn't a dict
                    if key not in target_parent or not isinstance(target_parent[key], dict):
                        target_parent[key] = {}
                    stack.append((indent, target_parent[key]))
                    i += 1
                    continue

                # value present on same line
                idx_ref = [i+1]
                val = parse_scalar(rest, self.lines, idx_ref)
                target_parent[key] = val
                # advance i to the index returned by parse_scalar (it may have consumed lines)
                i = idx_ref[0]
                continue

            # If none of the above matched, treat as continuation of previous multi-line string
            # or unexpected content
            # If content is a single opening quote, attach to last key in parent
            stripped = content.strip()
            if stripped in ('"', "'"):
                quote_char = stripped
                # find target key
                if isinstance(parent, dict) and len(parent) > 0:
                    target_key = list(parent.keys())[-1]
                    idx_ref = [i+1]
                    val = parse_scalar(quote_char, self.lines, idx_ref)
                    parent[target_key] = val
                    i = idx_ref[0]
                    continue

            raise ValueError(f"Unexpected content at line {i+1}: {content[:60]!r}")

        return self.root


def main():
    parser = argparse.ArgumentParser(
        description='Parse a pseudo-YAML config file and output as JSON or YAML'
    )
    parser.add_argument('filename', help='Path to the pseudo-YAML file to parse')
    parser.add_argument(
        '-o', '--output',
        choices=['json', 'yaml'],
        default='json',
        help='Output format (default: json)'
    )
    args = parser.parse_args()

    filename = args.filename
    linep = LineByLineParser(filename)
    linep.load()

    print(f"Parsing {filename}...", file=sys.stderr)
    try:
        result = linep.parse()
    except Exception as e:
        print(f"\n❌ ERROR at: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"✓ Parsed into Python dict structure (root keys): {list(result.keys())}", file=sys.stderr)

    # Output in requested format
    if args.output == 'json':
        output = json.dumps(result, indent=2)
    elif args.output == 'yaml':
        if yaml is None:
            print("❌ ERROR: PyYAML is not installed. Install it with: pip install pyyaml", file=sys.stderr)
            sys.exit(1)
        output = yaml.dump(result, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    print(output)


if __name__ == '__main__':
    main()
