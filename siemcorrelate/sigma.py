"""Pure standard library SIGMA YAML detection rule parser and conditional matcher."""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
from typing import Any, Callable


class SigmaParseError(Exception):
    """Raised when a SIGMA rule file has invalid YAML or schema structure."""
    pass


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Pure Python lightweight recursive YAML parser for SIGMA rules."""
    lines = text.splitlines()
    cleaned: list[tuple[int, str]] = []
    for line in lines:
        # Strip trailing comments
        comment_idx = line.find("#")
        if comment_idx != -1:
            line = line[:comment_idx]
        stripped = line.rstrip()
        if not stripped:
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        cleaned.append((indent, stripped.strip()))

    if not cleaned:
        return {}

    def parse_block(idx: int, current_indent: int) -> tuple[Any, int]:
        # Determine whether this block is a list or a dict
        if idx >= len(cleaned):
            return {}, idx

        first_indent, first_line = cleaned[idx]
        if first_line.startswith("- "):
            # List block
            items: list[Any] = []
            while idx < len(cleaned):
                ind, line = cleaned[idx]
                if ind < current_indent:
                    break
                if line.startswith("- "):
                    val_str = line[2:].strip()
                    if ":" in val_str and not val_str.startswith("{"):
                        # Sub-dictionary in list
                        sub_dict, idx = parse_block(idx, ind + 2)
                        items.append(sub_dict)
                    else:
                        items.append(_clean_yaml_val(val_str))
                        idx += 1
                else:
                    break
            return items, idx
        else:
            # Dictionary block
            result: dict[str, Any] = {}
            while idx < len(cleaned):
                ind, line = cleaned[idx]
                if ind < current_indent:
                    break

                if ":" not in line:
                    idx += 1
                    continue

                key_part, val_part = line.split(":", 1)
                key = key_part.strip()
                val_str = val_part.strip()

                if not val_str:
                    # Nested block
                    if idx + 1 < len(cleaned) and cleaned[idx + 1][0] > ind:
                        sub_val, idx = parse_block(idx + 1, cleaned[idx + 1][0])
                        result[key] = sub_val
                    else:
                        result[key] = None
                        idx += 1
                elif val_str.startswith("[") and val_str.endswith("]"):
                    # Inline list: [a, b, c]
                    inner = val_str[1:-1].strip()
                    if inner:
                        result[key] = [_clean_yaml_val(x.strip()) for x in inner.split(",")]
                    else:
                        result[key] = []
                    idx += 1
                else:
                    result[key] = _clean_yaml_val(val_str)
                    idx += 1
            return result, idx

    parsed, _ = parse_block(0, cleaned[0][0])
    return parsed if isinstance(parsed, dict) else {}


def _clean_yaml_val(val: str) -> Any:
    """Clean quotes, boolean, and numbers from YAML scalar string."""
    val = val.strip()
    if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
        return val[1:-1]
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.lower() == "null" or val == "~":
        return None
    try:
        if "." in val:
            return float(val)
        return int(val)
    except ValueError:
        return val


@dataclasses.dataclass
class SigmaRule:
    title: str
    rule_id: str
    description: str
    level: str
    detection: dict[str, Any]
    condition: str
    raw_yaml: str

    def matches(self, event: dict[str, Any]) -> bool:
        """Evaluate rule logic against a canonical normalized event dictionary."""
        selections: dict[str, bool] = {}

        # Evaluate each selection block in detection
        for sel_name, sel_def in self.detection.items():
            if sel_name == "condition":
                continue
            selections[sel_name] = self._eval_selection(sel_def, event)

        # Evaluate condition string
        return self._eval_condition(self.condition, selections)

    def _eval_selection(self, sel_def: Any, event: dict[str, Any]) -> bool:
        """Evaluate a selection block against event fields."""
        if not isinstance(sel_def, dict):
            if isinstance(sel_def, list):
                # OR across list of criteria dictionaries
                return any(self._eval_selection(item, event) for item in sel_def)
            return False

        # All criteria in a dictionary must match (AND)
        for field_spec, expected in sel_def.items():
            if "|" in field_spec:
                field_name, modifier = field_spec.split("|", 1)
            else:
                field_name, modifier = field_spec, "exact"

            # Retrieve event value
            actual = event.get(field_name)
            if actual is None:
                # Check inside extensions
                actual = event.get("extensions", {}).get(field_name)

            if not self._match_field(actual, modifier, expected):
                return False

        return True

    def _match_field(self, actual: Any, modifier: str, expected: Any) -> bool:
        """Match actual field value against expected value according to modifier."""
        # If expected is a list, match if ANY value matches (OR)
        if isinstance(expected, list):
            return any(self._match_field(actual, modifier, exp_item) for exp_item in expected)

        if actual is None:
            return expected is None

        act_str = str(actual).lower()
        exp_str = str(expected).lower()

        if modifier == "exact":
            return act_str == exp_str
        elif modifier == "contains":
            return exp_str in act_str
        elif modifier == "startswith":
            return act_str.startswith(exp_str)
        elif modifier == "endswith":
            return act_str.endswith(exp_str)
        elif modifier == "re":
            try:
                return bool(re.search(str(expected), str(actual), re.IGNORECASE))
            except re.error:
                return False
        elif modifier == "cidr":
            try:
                ip = ipaddress.ip_address(str(actual))
                net = ipaddress.ip_network(str(expected), strict=False)
                return ip in net
            except ValueError:
                return False

        return act_str == exp_str

    def _eval_condition(self, cond: str, selections: dict[str, bool]) -> bool:
        """Evaluate boolean condition string with 'and', 'or', 'not', and wildcards."""
        cond_str = cond.strip()
        if not cond_str:
            return all(selections.values()) if selections else False

        # Handle '1 of selection*' or 'all of selection*'
        if " of " in cond_str:
            parts = cond_str.split(" of ")
            quantifier = parts[0].strip()
            pattern = parts[1].strip()
            prefix = pattern.rstrip("*")

            matching_keys = [k for k in selections if k.startswith(prefix)]
            if quantifier in ("1", "any"):
                return any(selections[k] for k in matching_keys)
            elif quantifier == "all":
                return all(selections[k] for k in matching_keys)

        # Direct single selection
        if cond_str in selections:
            return selections[cond_str]

        # Token replacement evaluator
        # Replace selection names with their boolean values
        # Sort keys by length descending to prevent substring collisions
        sorted_keys = sorted(selections.keys(), key=len, reverse=True)
        expr = cond_str
        for k in sorted_keys:
            val_rep = "True" if selections[k] else "False"
            expr = re.sub(rf"\b{re.escape(k)}\b", val_rep, expr)

        # Replace logical operators with python syntax
        expr = re.sub(r"\band\b", "and", expr, flags=re.IGNORECASE)
        expr = re.sub(r"\bor\b", "or", expr, flags=re.IGNORECASE)
        expr = re.sub(r"\bnot\b", "not", expr, flags=re.IGNORECASE)

        try:
            # Safe eval with only booleans
            return bool(eval(expr, {"__builtins__": None}, {}))
        except Exception:
            return False


def parse_sigma_rule(yaml_text: str) -> SigmaRule:
    """Parse YAML string into a SigmaRule object."""
    data = parse_simple_yaml(yaml_text)
    if not data or not isinstance(data, dict):
        raise SigmaParseError("Invalid SIGMA rule: YAML parsing returned empty or non-dict result")

    title = data.get("title") or "Unnamed Sigma Rule"
    rule_id = str(data.get("id") or "rule-unknown")
    desc = data.get("description") or ""
    level = str(data.get("level") or "medium").lower()

    detection = data.get("detection")
    if not detection or not isinstance(detection, dict):
        raise SigmaParseError(f"SIGMA rule '{title}' is missing a valid 'detection' block")

    condition = str(detection.get("condition") or "selection")

    return SigmaRule(
        title=title,
        rule_id=rule_id,
        description=desc,
        level=level,
        detection=detection,
        condition=condition,
        raw_yaml=yaml_text,
    )


def load_sigma_rule_file(file_path: str) -> SigmaRule:
    """Read and parse a SIGMA rule from a file path."""
    if not os.path.isfile(file_path):
        raise SigmaParseError(f"Rule file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return parse_sigma_rule(content)


def load_sigma_rules_from_dir(dir_path: str) -> list[SigmaRule]:
    """Recursively load all .yml and .yaml SIGMA rules from a directory."""
    if not os.path.isdir(dir_path):
        raise SigmaParseError(f"Rules directory not found: {dir_path}")

    rules: list[SigmaRule] = []
    for root, _, files in os.walk(dir_path):
        for file in sorted(files):
            if file.endswith((".yml", ".yaml")):
                full_path = os.path.join(root, file)
                try:
                    rules.append(load_sigma_rule_file(full_path))
                except SigmaParseError:
                    pass
    return rules
