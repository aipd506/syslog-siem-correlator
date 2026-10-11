"""Universal security log parsers for RFC 3164, RFC 5424, CEF, and LEEF formats."""

from __future__ import annotations

import datetime
import re
import time
from typing import Any


class LogParseError(Exception):
    """Raised when a log line fails parsing in strict mode."""
    pass


# RFC 3164 (BSD Syslog) regex
# Example: <34>Oct 11 22:14:15 gateway-01 sshd[4210]: Failed password for root
RFC3164_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

# RFC 5424 (IETF Syslog) regex
# Example: <165>1 2026-10-11T22:14:15.003Z gateway-01 sshd 4210 ID_AUTH [sd@123 iut="3"] Failed password
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d+)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>\[.*?\]|-)\s*"
    r"(?P<msg>.*)$"
)

# Common regex patterns to extract entities from freeform messages
IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
USER_REGEX = re.compile(
    r"(?:"
    r"(?:failed|accepted)\s+(?:password|publickey|authentication)\s+for\s+(?:invalid\s+user\s+)?"
    r"|for\s+(?:invalid\s+)?user\s+"
    r"|for\s+"
    r"|(?:user|usr|account|username)\s*[=:\s]\s*"
    r")([a-zA-Z0-9_\-\.]+)",
    re.IGNORECASE,
)


def _nil_or_val(val: str | None) -> str | None:
    if val is None or val == "-":
        return None
    return val


def _parse_month_timestamp(ts_str: str) -> tuple[str, float]:
    """Parse BSD syslog timestamp 'Mmm dd hh:mm:ss' to ISO string and epoch float."""
    current_year = datetime.datetime.now(datetime.timezone.utc).year
    # normalize multi-spaces like 'Oct  9'
    parts = ts_str.split()
    if len(parts) == 3:
        month_str, day_str, time_str = parts
        formatted = f"{current_year} {month_str} {int(day_str):02d} {time_str}"
        try:
            dt = datetime.datetime.strptime(formatted, "%Y %b %d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
            return dt.isoformat(), dt.timestamp()
        except ValueError:
            pass
    now = time.time()
    return datetime.datetime.now(datetime.timezone.utc).isoformat(), now


def _parse_iso_timestamp(ts_str: str) -> tuple[str, float]:
    """Parse ISO timestamp to ISO string and epoch float."""
    try:
        # replace trailing Z with +00:00
        norm = ts_str.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.isoformat(), dt.timestamp()
    except Exception:
        now = time.time()
        return datetime.datetime.now(datetime.timezone.utc).isoformat(), now


def _extract_heuristic_entities(message: str) -> tuple[str | None, str | None, str | None]:
    """Extract src_ip, dst_ip, user from message text via heuristics."""
    src_ip = None
    dst_ip = None
    user = None

    # Check for IP addresses
    ips = IP_REGEX.findall(message)
    if len(ips) == 1:
        src_ip = ips[0]
    elif len(ips) >= 2:
        src_ip = ips[0]
        dst_ip = ips[1]

    # Check for username
    user_match = USER_REGEX.search(message)
    if user_match:
        cand = user_match.group(1)
        if cand.lower() not in ("the", "a", "an", "all", "each", "this", "from", "at"):
            user = cand

    return src_ip, dst_ip, user


def parse_rfc3164(line: str) -> dict[str, Any]:
    """Parse RFC 3164 BSD syslog message into canonical event dictionary."""
    line = line.strip()
    match = RFC3164_PATTERN.match(line)
    if not match:
        raise LogParseError(f"Line does not match RFC 3164 format: {line[:50]}...")

    pri_str = match.group("pri")
    pri = int(pri_str) if pri_str else 13  # Default notice/user
    facility = pri >> 3
    severity = pri & 0x07

    ts_iso, epoch = _parse_month_timestamp(match.group("ts"))
    host = match.group("host")
    tag = match.group("tag")
    pid = match.group("pid")
    msg = match.group("msg") or ""

    src_ip, dst_ip, user = _extract_heuristic_entities(msg)

    return {
        "timestamp": ts_iso,
        "epoch": epoch,
        "format": "RFC3164",
        "facility": facility,
        "severity": severity,
        "hostname": host,
        "app_name": tag,
        "procid": pid or "",
        "msgid": "",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": None,
        "dst_port": None,
        "user": user,
        "message": msg,
        "raw": line,
        "extensions": {},
    }


def parse_rfc5424(line: str) -> dict[str, Any]:
    """Parse RFC 5424 IETF syslog message into canonical event dictionary."""
    line = line.strip()
    match = RFC5424_PATTERN.match(line)
    if not match:
        raise LogParseError(f"Line does not match RFC 5424 format: {line[:50]}...")

    pri = int(match.group("pri"))
    facility = pri >> 3
    severity = pri & 0x07

    ts_iso, epoch = _parse_iso_timestamp(match.group("ts"))
    host = _nil_or_val(match.group("host")) or ""
    app = _nil_or_val(match.group("app")) or ""
    procid = _nil_or_val(match.group("procid")) or ""
    msgid = _nil_or_val(match.group("msgid")) or ""
    sd = match.group("sd")
    msg = match.group("msg") or ""

    # Parse structured data if present
    extensions: dict[str, Any] = {}
    if sd and sd != "-":
        sd_matches = re.findall(r'(\w+)="([^"]*)"', sd)
        for k, v in sd_matches:
            extensions[k] = v

    src_ip = extensions.get("src") or extensions.get("src_ip")
    dst_ip = extensions.get("dst") or extensions.get("dst_ip")
    user = extensions.get("user") or extensions.get("usrName")

    if not src_ip or not user:
        h_src, h_dst, h_user = _extract_heuristic_entities(msg)
        src_ip = src_ip or h_src
        dst_ip = dst_ip or h_dst
        user = user or h_user

    src_port = None
    if "spt" in extensions or "src_port" in extensions:
        try:
            src_port = int(extensions.get("spt") or extensions.get("src_port"))
        except ValueError:
            pass

    dst_port = None
    if "dpt" in extensions or "dst_port" in extensions:
        try:
            dst_port = int(extensions.get("dpt") or extensions.get("dst_port"))
        except ValueError:
            pass

    return {
        "timestamp": ts_iso,
        "epoch": epoch,
        "format": "RFC5424",
        "facility": facility,
        "severity": severity,
        "hostname": host,
        "app_name": app,
        "procid": procid,
        "msgid": msgid,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "user": user,
        "message": msg,
        "raw": line,
        "extensions": extensions,
    }


def parse_cef(line: str) -> dict[str, Any]:
    """Parse ArcSight Common Event Format (CEF) log line."""
    line = line.strip()
    if not line.startswith("CEF:"):
        # Could be preceded by syslog prefix
        idx = line.find("CEF:")
        if idx != -1:
            line = line[idx:]
        else:
            raise LogParseError("Line is not a CEF event")

    # Split header fields handling escaped pipes \|
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|" and len(parts) < 7:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))

    if len(parts) < 8:
        raise LogParseError("CEF line contains fewer than 8 fields")

    # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    version_part = parts[0]
    cef_version = version_part[4:] if version_part.startswith("CEF:") else "0"
    device_vendor = parts[1]
    device_product = parts[2]
    device_version = parts[3]
    event_class_id = parts[4]
    name = parts[5]
    severity_raw = parts[6]
    extension_raw = parts[7]

    # Parse severity
    try:
        severity = int(severity_raw)
    except ValueError:
        sev_map = {"Low": 3, "Medium": 5, "High": 8, "Very-High": 10, "Critical": 10}
        severity = sev_map.get(severity_raw, 5)

    # Parse key=value pairs in extension
    extensions: dict[str, Any] = {}
    # Regex to capture key=value where value runs until next key= or end
    kv_matches = re.findall(r'(\w+)=(.*?)(?=\s+\w+=|$)', extension_raw)
    for k, v in kv_matches:
        # unescape \| and \= and \\
        unescaped = v.replace(r"\|", "|").replace(r"\=", "=").replace(r"\\", "\\")
        extensions[k] = unescaped

    src_ip = extensions.get("src") or extensions.get("sourceAddress")
    dst_ip = extensions.get("dst") or extensions.get("destinationAddress")
    src_port = None
    if "spt" in extensions:
        try:
            src_port = int(extensions["spt"])
        except ValueError:
            pass
    dst_port = None
    if "dpt" in extensions:
        try:
            dst_port = int(extensions["dpt"])
        except ValueError:
            pass

    user = extensions.get("suser") or extensions.get("duser") or extensions.get("user")
    msg = extensions.get("msg") or name

    # Epoch/timestamp
    if "rt" in extensions:
        try:
            epoch = float(extensions["rt"]) / 1000.0 if len(extensions["rt"]) > 11 else float(extensions["rt"])
            ts_iso = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).isoformat()
        except ValueError:
            ts_iso, epoch = datetime.datetime.now(datetime.timezone.utc).isoformat(), time.time()
    else:
        ts_iso, epoch = datetime.datetime.now(datetime.timezone.utc).isoformat(), time.time()

    return {
        "timestamp": ts_iso,
        "epoch": epoch,
        "format": "CEF",
        "facility": 1,
        "severity": severity,
        "hostname": extensions.get("dhost") or extensions.get("shost") or device_product,
        "app_name": device_product,
        "procid": event_class_id,
        "msgid": name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "user": user,
        "message": msg,
        "raw": line,
        "extensions": extensions,
    }


def parse_leef(line: str) -> dict[str, Any]:
    """Parse QRadar Log Event Extended Format (LEEF 1.0 & 2.0)."""
    line = line.strip()
    idx = line.find("LEEF:")
    if idx != -1:
        line = line[idx:]
    else:
        raise LogParseError("Line is not a LEEF event")

    parts = line.split("|")
    if len(parts) < 6:
        raise LogParseError("LEEF line contains fewer than 6 fields")

    # LEEF:1.0|Vendor|Product|Version|EventID|Extension
    # LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|Extension
    leef_ver = parts[0][5:]
    vendor = parts[1]
    product = parts[2]
    version = parts[3]
    event_id = parts[4]

    if leef_ver.startswith("2.0") and len(parts) >= 7:
        delim = parts[5]
        if delim == "x09" or delim == "0x09":
            delim = "\t"
        extension_raw = "|".join(parts[6:])
    else:
        delim = "\t" if "\t" in parts[5] else "^"
        extension_raw = "|".join(parts[5:])

    extensions: dict[str, Any] = {}
    kv_items = extension_raw.split(delim) if delim in extension_raw else extension_raw.split()
    for item in kv_items:
        if "=" in item:
            k, v = item.split("=", 1)
            extensions[k.strip()] = v.strip()

    src_ip = extensions.get("src") or extensions.get("srcIP")
    dst_ip = extensions.get("dst") or extensions.get("dstIP")
    src_port = None
    if "srcPort" in extensions:
        try:
            src_port = int(extensions["srcPort"])
        except ValueError:
            pass
    dst_port = None
    if "dstPort" in extensions:
        try:
            dst_port = int(extensions["dstPort"])
        except ValueError:
            pass

    user = extensions.get("usrName") or extensions.get("identSrc") or extensions.get("accountName")
    msg = extensions.get("msg") or extensions.get("message") or f"{vendor} {product} {event_id}"

    ts_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    epoch = time.time()
    if "devTime" in extensions:
        try:
            ts_iso, epoch = _parse_iso_timestamp(extensions["devTime"])
        except Exception:
            pass

    return {
        "timestamp": ts_iso,
        "epoch": epoch,
        "format": "LEEF",
        "facility": 1,
        "severity": 5,
        "hostname": extensions.get("devTimeFormat") or product,
        "app_name": product,
        "procid": event_id,
        "msgid": event_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "user": user,
        "message": msg,
        "raw": line,
        "extensions": extensions,
    }


def parse_log_line(line: str, format_name: str = "auto") -> dict[str, Any]:
    """Parse log line using specified or auto-detected format."""
    s = line.strip()
    if not s:
        raise LogParseError("Cannot parse empty line")

    fmt = format_name.lower()
    if fmt == "rfc5424":
        return parse_rfc5424(s)
    elif fmt == "rfc3164":
        return parse_rfc3164(s)
    elif fmt == "cef":
        return parse_cef(s)
    elif fmt == "leef":
        return parse_leef(s)

    # Auto-detection
    if "CEF:" in s:
        try:
            return parse_cef(s)
        except Exception:
            pass

    if "LEEF:" in s:
        try:
            return parse_leef(s)
        except Exception:
            pass

    if s.startswith("<"):
        # Check if version digit follows <pri>
        if re.match(r"^<\d{1,3}>\d+\s+", s):
            try:
                return parse_rfc5424(s)
            except Exception:
                pass
        try:
            return parse_rfc3164(s)
        except Exception:
            pass

    # Fallback to generic message
    now = time.time()
    src_ip, dst_ip, user = _extract_heuristic_entities(s)
    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "epoch": now,
        "format": "GENERIC",
        "facility": 1,
        "severity": 6,
        "hostname": "localhost",
        "app_name": "generic",
        "procid": "",
        "msgid": "",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": None,
        "dst_port": None,
        "user": user,
        "message": s,
        "raw": s,
        "extensions": {},
    }
