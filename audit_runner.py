#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Completely modular audit engine.

- Loads rule modules dynamically
- Groups them by SECTION key
- Executes rules in order
- Each rule returns findings
- Each section_* module decides how to render its Markdown output
"""

import argparse
import importlib
import json
import os
from collections import defaultdict


RULES_DIR = "rules"


def load_rules():
    """Load every Python file in rules/ except __init__."""
    rule_modules = []

    for filename in os.listdir(RULES_DIR):
        if not filename.endswith(".py"):
            continue
        if filename == "__init__.py":
            continue

        module_name = filename[:-3]
        module = importlib.import_module(f"{RULES_DIR}.{module_name}")

        if hasattr(module, "SECTION"):
            rule_modules.append(module)

    return rule_modules


def extract_vdom(config, name):
    """Extract and merge all instances of a VDOM from the config array."""
    vdom_list = config.get("vdom", [])
    merged_vdom = {}
    
    for vdom_dict in vdom_list:
        if name in vdom_dict:
            # Deep merge this VDOM's data into the accumulated result
            vdom_data = vdom_dict[name]
            merged_vdom.update(vdom_data)
    
    if not merged_vdom:
        raise ValueError(f"VDOM '{name}' not found.")
    
    return merged_vdom


def aggregate_vdom(vdom_data):
    """Aggregate flat VDOM config into nested structure.
    
    Converts keys like "firewall_address" into nested dict:
    {"firewall": {"address": ...}}
    """
    aggregated = {}
    
    for key, value in vdom_data.items():
        parts = key.split("_", 1)  # Split on first underscore only
        if len(parts) == 2:
            section, subsection = parts
            if section not in aggregated:
                aggregated[section] = {}
            aggregated[section][subsection] = value
        else:
            # Keys without underscore go at top level
            aggregated[key] = value
    
    return aggregated


def main():
    parser = argparse.ArgumentParser(description="Modular FortiGate JSON Auditor")
    parser.add_argument("--config", required=True, help="JSON config file")
    parser.add_argument("--vdom", required=True, help="VDOM to audit")
    parser.add_argument("--output", default="report.md")

    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # Extract and aggregate the requested VDOM
    vdom_raw = extract_vdom(cfg, args.vdom)
    vdom = aggregate_vdom(vdom_raw)
    
    rules = load_rules()

    # Group rules by SECTION key
    grouped = defaultdict(list)
    for rule in rules:
        grouped[rule.SECTION].append(rule)

    final_markdown = ["# **1. Anti-patterns detection**\n"]

    # Process sections in alphabetical order (1.1.*, 1.2.*, etc.)
    for section_name in sorted(grouped.keys()):
        section_rules = grouped[section_name]

        # Section aggregator rule is the one whose filename starts with "section_"
        section_aggregator = None
        audit_rules = []

        for r in section_rules:
            if r.__name__.split(".")[-1].startswith("section_"):
                section_aggregator = r
            else:
                audit_rules.append(r)

        if section_aggregator is None:
            raise RuntimeError(
                f"Section {section_name} has no section_* aggregator rule."
            )

        # Execute rules in order, passing aggregated VDOM
        findings = []
        for rule in audit_rules:
            result = rule.run(vdom)
            if result:
                findings.extend(result)

        # Instruct the aggregator to render markdown only if findings exist
        section_md = section_aggregator.render(findings)
        if section_md:
            final_markdown.append(section_md)

    # Output
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(final_markdown))

    print(f"[OK] Report generated: {args.output}")


if __name__ == "__main__":
    main()