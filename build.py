#!/usr/bin/env python3
"""Build the ylluminate blocklist outputs from lists/*.txt into dist/.

Python 3 standard library only. Deterministic: the only varying field is the
build date, which can be pinned with the SOURCE_DATE_EPOCH environment
variable.
"""

import datetime
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

NAME = "ylluminate-blocklist"
DESCRIPTION = "Personal network blocklist: domains and IPv4 ranges."
URL = "https://github.com/ylluminate/ylluminate-blocklist"  # placeholder until published
DEFAULT_IP_DESCRIPTION = "blocklist"

ROOT = Path(__file__).resolve().parent

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ListError(ValueError):
    """A source list contains an invalid line. Message includes file:line."""


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _split_line(raw):
    """Return (entry, note) for one source line; entry is '' for blank/comment."""
    entry, _, note = raw.partition("#")
    return entry.strip(), note.strip()


def validate_domain(value):
    """Return the normalised (lowercase) domain or raise ValueError."""
    domain = value.strip().lower()
    if not domain:
        raise ValueError("empty domain")
    if any(ord(c) > 127 for c in domain):
        raise ValueError("non-ASCII domain; use the punycode (xn--) form")
    if domain.endswith("."):
        domain = domain[:-1]
    if len(domain) > 253:
        raise ValueError("domain longer than 253 characters")
    if re.fullmatch(r"[0-9.]+", domain):
        raise ValueError("looks like an IP address; put it in lists/ips.txt")
    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("needs at least two labels (for example example.com)")
    for label in labels:
        if not label:
            raise ValueError("empty label (stray or doubled dot)")
        if len(label) > 63:
            raise ValueError("label %r longer than 63 characters" % label)
        if not _LABEL_RE.match(label):
            raise ValueError(
                "invalid label %r (letters, digits and inner hyphens only)" % label
            )
    if labels[-1].isdigit():
        raise ValueError("top-level label must not be all digits")
    return domain


def parse_domains(text, source="domains.txt"):
    """Parse domain list text. Returns a sorted, de-duplicated list of domains."""
    seen = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        entry, _note = _split_line(raw)
        if not entry:
            continue
        if len(entry.split()) != 1:
            raise ListError(
                "%s:%d: invalid domain %r: expected one domain per line"
                % (source, lineno, entry)
            )
        try:
            seen.add(validate_domain(entry))
        except ValueError as exc:
            raise ListError("%s:%d: invalid domain %r: %s" % (source, lineno, entry, exc))
    return sorted(seen)


def _parse_ipv4(value):
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError("%r is not a valid IPv4 address" % value)


def parse_ip_entry(entry):
    """Convert 'a.b.c.d', 'a.b.c.d/n' or 'a.b.c.d-e.f.g.h' to (start, end) ints."""
    entry = entry.strip()
    if ":" in entry:
        raise ValueError("IPv6 is not supported")
    if "/" in entry:
        try:
            net = ipaddress.IPv4Network(entry, strict=True)
        except ValueError as exc:
            raise ValueError("invalid CIDR %r: %s" % (entry, exc))
        return int(net.network_address), int(net.broadcast_address)
    if "-" in entry:
        left, _, right = entry.partition("-")
        start = _parse_ipv4(left.strip())
        end = _parse_ipv4(right.strip())
        if int(start) > int(end):
            raise ValueError("range start %s is after end %s" % (start, end))
        return int(start), int(end)
    addr = _parse_ipv4(entry)
    return int(addr), int(addr)


def parse_ips(text, source="ips.txt"):
    """Parse IP list text. Returns sorted, de-duplicated (start, end, description)."""
    found = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        entry, note = _split_line(raw)
        if not entry:
            continue
        try:
            start, end = parse_ip_entry(entry)
        except ValueError as exc:
            raise ListError("%s:%d: invalid IP entry %r: %s" % (source, lineno, entry, exc))
        found.setdefault((start, end), note)  # first description wins
    return [(s, e, found[(s, e)]) for (s, e) in sorted(found)]


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _ip(value):
    return str(ipaddress.IPv4Address(value))


def _padded(value):
    return ".".join("%03d" % int(octet) for octet in _ip(value).split("."))


def _clean_description(description):
    """Make a description safe for the ',' and ':' delimited IP formats."""
    cleaned = re.sub(r"[,:]", " ", description or "")
    return " ".join(cleaned.split()) or DEFAULT_IP_DESCRIPTION


def build_date(env=None):
    """Return the build date (YYYY-MM-DD, UTC), honouring SOURCE_DATE_EPOCH."""
    env = os.environ if env is None else env
    epoch = env.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            moment = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
        except (ValueError, OverflowError, OSError):
            raise ValueError("SOURCE_DATE_EPOCH must be an integer Unix timestamp")
    else:
        moment = datetime.datetime.now(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%d")


def render_hosts(domains, date):
    lines = [
        "# Title: %s" % NAME,
        "# Description: %s" % DESCRIPTION,
        "# URL: %s" % URL,
        "# Entries: %d" % len(domains),
        "# Last updated: %s" % date,
        "#",
    ]
    lines += ["0.0.0.0 %s" % d for d in domains]
    return "\n".join(lines) + "\n"


def render_domains(domains):
    return "".join(d + "\n" for d in domains)


def render_adblock(domains, date):
    lines = [
        "! Title: %s" % NAME,
        "! Description: %s" % DESCRIPTION,
        "! Homepage: %s" % URL,
        "! Entries: %d" % len(domains),
        "! Last modified: %s" % date,
        "!",
    ]
    lines += ["||%s^" % d for d in domains]
    return "\n".join(lines) + "\n"


def render_ipfilter(ranges, date):
    lines = [
        "# %s (eMule / PeerGuardian DAT format)" % NAME,
        "# URL: %s" % URL,
        "# Entries: %d" % len(ranges),
        "# Last updated: %s" % date,
    ]
    for start, end, description in ranges:
        lines.append(
            "%s - %s , 000 , %s" % (_padded(start), _padded(end), _clean_description(description))
        )
    return "\n".join(lines) + "\n"


def render_p2p(ranges, date):
    lines = [
        "# %s (PeerGuardian P2P text format)" % NAME,
        "# URL: %s" % URL,
        "# Entries: %d" % len(ranges),
        "# Last updated: %s" % date,
    ]
    for start, end, description in ranges:
        lines.append("%s:%s-%s" % (_clean_description(description), _ip(start), _ip(end)))
    return "\n".join(lines) + "\n"


def render_lsrules(domains):
    group = {
        "name": NAME,
        "description": "%s %d domains." % (DESCRIPTION, len(domains)),
        "denied-remote-domains": list(domains),
    }
    return json.dumps(group, indent=2, ensure_ascii=True) + "\n"


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def build(root=ROOT, date=None):
    """Read root/lists, write root/dist. Returns {filename: content}."""
    root = Path(root)
    date = date or build_date()
    domains_path = root / "lists" / "domains.txt"
    ips_path = root / "lists" / "ips.txt"
    domains = parse_domains(domains_path.read_text(encoding="utf-8"), "lists/domains.txt")
    ranges = parse_ips(ips_path.read_text(encoding="utf-8"), "lists/ips.txt")

    outputs = {
        "hosts.txt": render_hosts(domains, date),
        "domains.txt": render_domains(domains),
        "adblock.txt": render_adblock(domains, date),
        "ipfilter.dat": render_ipfilter(ranges, date),
        "p2p.txt": render_p2p(ranges, date),
        "blocklist.lsrules": render_lsrules(domains),
    }
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    for filename, content in outputs.items():
        with open(dist / filename, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    return outputs


def main(root=ROOT):
    try:
        outputs = build(root)
    except (ListError, ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    for filename in outputs:
        print("wrote dist/%s" % filename)
    return 0


if __name__ == "__main__":
    sys.exit(main())
