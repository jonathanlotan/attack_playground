#!/usr/bin/env python3
"""
print what attack_network_endpoints.conf allows, for the shell scripts.

the config is read through the same parser that builds the iptables chains, so a
script that needs "the configured ranges" or "an allowed port" follows the file
rather than repeating a number from it - which is how verify.sh once came to
check for a range the config no longer had.

    endpoints.py ranges      the configured ranges in iptables syntax, one per line
    endpoints.py ports N     the first N allowed ports, space separated

a missing config, one that allows nothing, or fewer ports than were asked for is
a message on stderr and exit 1: a verifier with nothing to verify against must
not look like one that passed.
"""

import contextlib
import sys

from network_common_linux import CONFIG_FILE, find_config, parse_config, port_arg, range_bounds

USAGE = "usage: endpoints.py ranges | endpoints.py ports N"


def configured_ranges(config_path):
    """
    the ranges the config allows, validated the way the chain builder does it.

    the parser prints a warning for every line it skips. those go to stderr from
    here: stdout is what the shell scripts capture, and a warning in it would be
    taken for a range.
    """
    if not config_path:
        return []
    with contextlib.redirect_stdout(sys.stderr):
        return parse_config(config_path)


def allowed_ports(ranges, count):
    """the first `count` ports the ranges allow, in config order."""
    ports = []
    for rng in ranges:
        start, end = range_bounds(rng)
        ports.extend(range(start, min(end, start + count) + 1))
        if len(ports) >= count:
            break
    return ports[:count]


def main(argv):
    if len(argv) == 2 and argv[1] == "ranges":
        count = None
    elif len(argv) == 3 and argv[1] == "ports" and argv[2].isdigit() and int(argv[2]) > 0:
        count = int(argv[2])
    else:
        print(USAGE, file=sys.stderr)
        return 2

    config_path = find_config()
    ranges = configured_ranges(config_path)
    if not ranges:
        problem = "was not found" if not config_path else "allows no ports"
        print(f"error: {CONFIG_FILE} {problem}", file=sys.stderr)
        return 1

    if count is None:
        for rng in ranges:
            print(port_arg(rng))
        return 0

    ports = allowed_ports(ranges, count)
    if len(ports) < count:
        print(f"error: {CONFIG_FILE} allows only {len(ports)} port(s), {count} were asked for",
              file=sys.stderr)
        return 1
    print(*ports)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
