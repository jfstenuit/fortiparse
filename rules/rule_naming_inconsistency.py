SECTION = "1_objects"
TITLE = "Naming patterns observed in object names"

import re

# pattern helpers
_CAMEL_RE = re.compile(r"[a-z]+[A-Z][a-zA-Z0-9]*")
_PASCAL_RE = re.compile(r"^[A-Z][a-z]+[A-Z][a-zA-Z0-9]*")
_SNAKE_RE = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)+$")
_KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)+$")
_UPPER_SNAKE_RE = re.compile(r"^[A-Z0-9]+(_[A-Z0-9]+)+$")


def _gather_names(vdom):
    """Collect object names from common firewall object lists."""
    names = []
    fw = vdom.get("firewall", {})

    # common lists to inspect
    lists = ["address", "addrgrp", "service", "service_group"]

    for key in lists:
        items = fw.get(key, []) or []
        for entry in items:
            if isinstance(entry, dict):
                for name in entry.keys():
                    names.append((key, name))
    return names


def run(vdom):
    """Analyze object names and report the main naming patterns observed.

    The rule does not flag each individual object as a problem. Instead it
    summarizes which naming conventions are present and provides a few
    representative examples for each pattern.
    """
    findings = []

    names = _gather_names(vdom)
    if not names:
        return []

    # buckets: pattern -> set of examples
    buckets = {
        "underscore": set(),
        "dash": set(),
        "camel": set(),
        "pascal": set(),
        "snake_case": set(),
        "kebab-case": set(),
        "UPPER_SNAKE": set(),
        "dots": set(),
        "spaces": set(),
        "lowercase": set(),
        "uppercase": set(),
        "other": set(),
    }

    for sect, name in names:
        # quick checks
        if " " in name:
            buckets["spaces"].add(name)
            continue
        if "." in name:
            buckets["dots"].add(name)
            continue
        if "_" in name and name.isupper():
            buckets["UPPER_SNAKE"].add(name)
            continue
        if "_" in name and name.islower():
            buckets["snake_case"].add(name)
            continue
        if "_" in name:
            buckets["underscore"].add(name)
            continue
        if "-" in name:
            if _KEBAB_RE.match(name):
                buckets["kebab-case"].add(name)
            else:
                buckets["dash"].add(name)
            continue
        if _CAMEL_RE.search(name):
            buckets["camel"].add(name)
            continue
        if _PASCAL_RE.search(name):
            buckets["pascal"].add(name)
            continue
        if name.islower():
            buckets["lowercase"].add(name)
            continue
        if name.isupper():
            buckets["uppercase"].add(name)
            continue
        buckets["other"].add(name)

    # prepare finding only if multiple distinct patterns observed
    observed = {k: v for k, v in buckets.items() if v}
    if len(observed) <= 1:
        # nothing interesting to report
        return []

    md = [
        "### Naming patterns observed across firewall objects\n\n",
        "The audit examines object names (addresses, groups, services) and summarizes "
        "the naming styles present. This rule does not mark objects as failures; it "
        "only lists patterns to help standardise naming across the estate.\n",
        "\n",
    ]

    # For each pattern show up to 3 examples and the total count
    for pattern in [
        "underscore",
        "dash",
        "snake_case",
        "kebab-case",
        "camel",
        "pascal",
        "UPPER_SNAKE",
        "dots",
        "spaces",
        "lowercase",
        "uppercase",
        "other",
    ]:
        examples = sorted(observed.get(pattern, []))[:3]
        if not examples:
            continue
        md.append(f"* **{pattern}**: {len(observed.get(pattern))} examples; e.g. {', '.join(examples)}\n")

    md.append("")
    findings.extend(md)
    return findings
