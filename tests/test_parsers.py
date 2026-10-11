"""Tests for syslog-siem-correlator parsers (RFC 3164, RFC 5424, CEF, LEEF)."""

import pytest

from siemcorrelate.parsers import (
    LogParseError,
    parse_cef,
    parse_leef,
    parse_log_line,
    parse_rfc3164,
    parse_rfc5424,
)


def test_parse_rfc3164():
    raw = "<34>Oct 11 22:14:15 gateway-01 sshd[4210]: Failed password for root from 192.168.1.105 port 54210"
    ev = parse_rfc3164(raw)
    assert ev["format"] == "RFC3164"
    assert ev["facility"] == 4  # 34 >> 3
    assert ev["severity"] == 2  # 34 & 7
    assert ev["hostname"] == "gateway-01"
    assert ev["app_name"] == "sshd"
    assert ev["procid"] == "4210"
    assert ev["src_ip"] == "192.168.1.105"
    assert ev["user"] == "root"
    assert "Failed password" in ev["message"]


def test_parse_rfc5424():
    raw = '<165>1 2026-10-11T22:14:15.003Z myhost sshd 4210 ID_AUTH [exampleSDID@32473 iut="3" src="10.0.0.5"] Failed authentication'
    ev = parse_rfc5424(raw)
    assert ev["format"] == "RFC5424"
    assert ev["facility"] == 20  # 165 >> 3
    assert ev["severity"] == 5  # 165 & 7
    assert ev["hostname"] == "myhost"
    assert ev["app_name"] == "sshd"
    assert ev["procid"] == "4210"
    assert ev["msgid"] == "ID_AUTH"
    assert ev["src_ip"] == "10.0.0.5"
    assert ev["extensions"]["iut"] == "3"


def test_parse_cef():
    raw = "CEF:0|SecurityVendor|FirewallApp|1.2.3|100|Connection Blocked|8|src=192.168.10.50 dst=10.0.0.1 spt=45231 dpt=443 msg=Denied by rule"
    ev = parse_cef(raw)
    assert ev["format"] == "CEF"
    assert ev["severity"] == 8
    assert ev["app_name"] == "FirewallApp"
    assert ev["procid"] == "100"
    assert ev["msgid"] == "Connection Blocked"
    assert ev["src_ip"] == "192.168.10.50"
    assert ev["dst_ip"] == "10.0.0.1"
    assert ev["src_port"] == 45231
    assert ev["dst_port"] == 443
    assert ev["message"] == "Denied by rule"


def test_parse_leef():
    raw = "LEEF:2.0|Microsoft|AD|10.0|4625|^|src=172.16.0.4^dst=10.0.0.2^usrName=administrator^msg=Logon Failure"
    ev = parse_leef(raw)
    assert ev["format"] == "LEEF"
    assert ev["app_name"] == "AD"
    assert ev["procid"] == "4625"
    assert ev["src_ip"] == "172.16.0.4"
    assert ev["dst_ip"] == "10.0.0.2"
    assert ev["user"] == "administrator"
    assert ev["message"] == "Logon Failure"


def test_auto_detection():
    # Automatically detect format
    cef_raw = "CEF:0|Vendor|App|1.0|1|Test|3|src=1.2.3.4 msg=Hello"
    ev1 = parse_log_line(cef_raw)
    assert ev1["format"] == "CEF"
    assert ev1["src_ip"] == "1.2.3.4"

    rfc5424_raw = "<14>1 2026-10-11T20:00:00Z web01 nginx 100 - - GET /index.html 200"
    ev2 = parse_log_line(rfc5424_raw)
    assert ev2["format"] == "RFC5424"

    rfc3164_raw = "<13>Oct 11 12:00:00 server01 su: 'su root' succeeded"
    ev3 = parse_log_line(rfc3164_raw)
    assert ev3["format"] == "RFC3164"


def test_empty_line_raises():
    with pytest.raises(LogParseError):
        parse_log_line("   ")
