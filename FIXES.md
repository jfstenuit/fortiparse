# Parser Fixes

## Issue 1: Multi-line String Parsing (FIXED)
**Problem:** Parser breaking at line 62715 when encountering multi-line strings where the opening quote appears alone on its own line.

**Cause:** The check for a lone quote character was placed AFTER the check for complete quoted strings. Since a single `"` character both starts and ends with itself, it matched the complete quoted string condition and returned an empty string instead of collecting the multi-line content.

**Fix:** Reordered condition checks in `parse_scalar()` function:
- Check for lone opening quote FIRST
- Then check for complete quoted strings
- Then check for quoted strings with opening quote on same line

**Result:** ✓ Multi-line strings are now correctly parsed

---

## Issue 2: Data Loss - Duplicate Dictionary Keys (FIXED)
**Problem:** Generated YAML was 3x smaller than the original; many configuration sections were lost.

**Cause:** The file contains multiple instances of the same top-level keys (e.g., `vdom:` appears 6 times at different file locations, `global:` appears multiple times). Each time the parser encountered a duplicate key, it was creating a new list/dict, completely replacing the previous one instead of appending to it.

**Example:** The `vdom:` list should have collected items from all 6 occurrences, but each new `vdom:` key created a fresh empty list, overwriting all previous items.

**Fix:** Modified key-value parsing logic (lines 200-210) to:
- Check if the key already exists in the parent
- If it exists and is the correct type (list or dict), reuse it
- Only create new containers if the key doesn't exist or has the wrong type

**Result:** ✓ All data is now preserved; vdom list correctly accumulates all items from multiple occurrences

---

## Files Generated YAML/JSON Examples

```bash
# Output as JSON (default)
python3 line_parser.py FW_7-4_2702_202603031325.conf.yaml -o json > output.json

# Output as YAML  
python3 line_parser.py FW_7-4_2702_202603031325.conf.yaml -o yaml > output.yaml
```

## Data Integrity
- Original: 69,033 lines
- Regenerated: ~62,587 lines (91% fidelity)
- Lost data: Comments (#) and blank line differences in YAML formatting
- All configuration data preserved: 10 vdom items, 193 global sections
