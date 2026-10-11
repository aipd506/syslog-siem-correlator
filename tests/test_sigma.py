"""Tests for pure stdlib SIGMA YAML detection rule parser and matcher."""

import pytest

from siemcorrelate.sigma import (
    SigmaParseError,
    load_sigma_rule_file,
    parse_sigma_rule,
    parse_simple_yaml,
)


def test_yaml_parser():
    yaml_text = """
title: Test YAML
level: high
detection:
  selection:
    app_name: sshd
    tags: [auth, security]
  condition: selection
"""
    data = parse_simple_yaml(yaml_text)
    assert data["title"] == "Test YAML"
    assert data["level"] == "high"
    assert data["detection"]["selection"]["app_name"] == "sshd"
    assert data["detection"]["selection"]["tags"] == ["auth", "security"]


def test_sigma_contains_and_exact_match():
    rule_yaml = """
title: SSH Failed Login
id: 1111-2222
level: medium
detection:
  selection:
    app_name: sshd
    message|contains: 'Failed password'
  condition: selection
"""
    rule = parse_sigma_rule(rule_yaml)
    assert rule.title == "SSH Failed Login"

    event_match = {"app_name": "sshd", "message": "Failed password for root from 192.168.1.1"}
    assert rule.matches(event_match) is True

    event_no_match = {"app_name": "sshd", "message": "Accepted publickey for ubuntu"}
    assert rule.matches(event_no_match) is False


def test_sigma_modifiers_cidr_and_regex():
    rule_yaml = """
title: Private Network SSH Scan
level: high
detection:
  selection:
    src_ip|cidr: '10.0.0.0/8'
    message|re: 'invalid user\\s+\\w+'
  condition: selection
"""
    rule = parse_sigma_rule(rule_yaml)

    # In 10.0.0.0/8 and matches regex
    ev1 = {"src_ip": "10.5.20.1", "message": "Failed password for invalid user admin"}
    assert rule.matches(ev1) is True

    # Outside 10.0.0.0/8
    ev2 = {"src_ip": "192.168.1.5", "message": "Failed password for invalid user admin"}
    assert rule.matches(ev2) is False


def test_sigma_boolean_condition_logic():
    rule_yaml = """
title: Sudo Abuse Detection
level: critical
detection:
  selection_sudo:
    app_name: sudo
  selection_root:
    user: root
  filter_clean:
    message|contains: 'normal operation'
  condition: selection_sudo and selection_root and not filter_clean
"""
    rule = parse_sigma_rule(rule_yaml)

    # Matches sudo + root, without filter
    ev1 = {"app_name": "sudo", "user": "root", "message": "COMMAND=/bin/bash"}
    assert rule.matches(ev1) is True

    # Filter is present -> should NOT match
    ev2 = {"app_name": "sudo", "user": "root", "message": "normal operation performed"}
    assert rule.matches(ev2) is False


def test_sigma_invalid_schema():
    bad_yaml = "title: Incomplete Rule"
    with pytest.raises(SigmaParseError):
        parse_sigma_rule(bad_yaml)
