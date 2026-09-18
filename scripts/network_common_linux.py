#!/usr/bin/env python3
"""
common functions for iptables management of the playground docker network.

policy: a guest may open connections to the host on the tcp ports listed in
attack_network_endpoints.conf, and to nothing else. no internet, no other host on
the lan, no other docker network, and no other guest.

the network ("attack_playground_net") is created with --internal, which already stops
docker from routing the guest out to the internet. that alone is not enough:

  * an internal network still leaves the host itself reachable on the bridge gateway
    ip, and that is where the attack endpoints live - so the allowlist has to be
    enforced in INPUT.
  * guests on the same bridge can still reach each other - so intra-bridge traffic
    has to be dropped explicitly.

three dedicated chains are used so that setup is idempotent and teardown is exact:

  ATTACK_PG_INPUT   hooked from INPUT for "-i <bridge>"
                    guest -> host. only the tcp ports from the config file (on the
                    gateway ip) are accepted, everything else is dropped.

  ATTACK_PG_FWD     hooked from DOCKER-USER for "-i <bridge>"
                    guest -> forwarded. dropped outright. this covers guest-to-guest
                    (same bridge), guest -> other docker network and guest -> lan.

  ATTACK_PG_FWD_IN  hooked from DOCKER-USER for "-o <bridge>"
                    forwarded -> guest. dropped, so no other host can reach a guest.
                    the host itself is unaffected: host-originated traffic is routed
                    through OUTPUT, not FORWARD.

  ATTACK_PG_SSH     hooked from INPUT for "-p tcp --dport <ssh port> --syn"
                    lan -> containerssh. caps the number of concurrent ssh
                    connections, and with it the number of live guest containers.
                    the auth webhook says yes to everybody, so without this anyone
                    on the lan can mint guests until the host runs out of memory.

published attack endpoints are a special case. a docker-published port is DNATed in
the nat table *before* routing, so a guest packet to <gateway>:<port> arrives in
FORWARD with the endpoint container as its destination and never reaches INPUT.
ATTACK_PG_FWD therefore also allows connections whose *original* destination was
an allowed port on the gateway (conntrack --ctorigdst/--ctorigdstport), and
ATTACK_PG_FWD_IN lets the replies of connections a guest opened come back. a
guest can only ever open connections the allowlist permits, so an ESTABLISHED
match there does not widen the policy.

note that DOCKER-USER only ever sees FORWARDed packets, so a rule matching the
gateway ip there can never fire - that is why the endpoint allowlist belongs in INPUT.

the same three chain names are also used in ip6tables (a separate namespace) to drop
every packet on the bridge - see the ipv6 section below.

two invariants everything else here is built around:

  * chains are never open. a chain is flushed and given its terminal DROP before any
    allow rule goes in, so a rebuild that fails half way through leaves the guests
    locked out rather than falling through to the (ACCEPT) policy of the parent chain.
  * a rule that cannot fire is a bug, not a safety net. a chain nobody jumps to is
    silently dead, so hooks are verified rather than assumed.
"""

import os
import re
import shlex
import subprocess


DOCKER_NET_NAME = "attack_playground_net"
CONFIG_FILE = "attack_network_endpoints.conf"

INPUT_CHAIN = "ATTACK_PG_INPUT"
FORWARD_CHAIN = "ATTACK_PG_FWD"
FORWARD_IN_CHAIN = "ATTACK_PG_FWD_IN"
SSH_LIMIT_CHAIN = "ATTACK_PG_SSH"

# how many ssh connections may be open at once, over all sources. every
# connection is a guest container with the memory reservation in config.yaml, so
# this is the cap on what the lan can make the host spend. the port it is keyed
# on is the one containerssh is published on, which .env sets and start.sh passes
# in as SSH_PORT - see ssh_port_from_env().
MAX_SSH_CONNECTIONS = 32
SSH_PORT_ENV = "SSH_PORT"

# bridged traffic only reaches iptables / ip6tables when the matching sysctl is
# on. docker turns on the ipv4 one itself for an ipv4 network and leaves the ipv6
# one alone, and some distros ship it off - but the ipv6 guest-to-guest DROP in
# FORWARD depends on it just as much.
BRIDGE_NF_SYSCTL = "net.bridge.bridge-nf-call-iptables"
BRIDGE_NF6_SYSCTL = "net.bridge.bridge-nf-call-ip6tables"
BRIDGE_NF_SYSCTLS = (BRIDGE_NF_SYSCTL, BRIDGE_NF6_SYSCTL)

IPTABLES = "iptables"
IP6TABLES = "ip6tables"

# built-in / docker chains that may hold a jump to one of our chains
HOOK_PARENTS = ("INPUT", "FORWARD", "DOCKER-USER")

MIN_PORT = 1
MAX_PORT = 65535


class IptablesError(RuntimeError):
    """an iptables command failed. carries the tool's own stderr, which the caller needs."""

    def __init__(self, binary, args, returncode, stderr):
        self.binary = binary
        self.args = list(args)
        self.returncode = returncode
        self.stderr = stderr
        detail = stderr.strip() if stderr else "no error output"
        super().__init__(
            f"{binary} {' '.join(args)} failed (exit {returncode}): {detail}"
        )


def _privileged_prefix():
    """use sudo only when we are not already root (start.sh already runs us as root)."""
    if os.geteuid() == 0:
        return []
    return ["sudo"]


def run_iptables(binary, args, ignore_error=False):
    """
    run an iptables/ip6tables command.

    stderr is captured and carried on the exception rather than discarded: an
    unexplained non-zero exit here used to surface as a bare CalledProcessError
    traceback with the actual reason ("invalid port/service", "no chain by that
    name", ...) thrown away.
    """
    cmd = _privileged_prefix() + [binary] + args
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        if ignore_error:
            return False
        # cmd[0] is "sudo" when we are not root, so report whichever binary is
        # actually missing. a host with no sudo installed (a root shell on a
        # minimal image, where this script is run by hand rather than by
        # start.sh) otherwise gets told that iptables is missing when it is not.
        raise IptablesError(binary, args, 127, f"{cmd[0]} not found")

    if proc.returncode == 0:
        return True
    if ignore_error:
        return False
    raise IptablesError(binary, args, proc.returncode, proc.stderr)


def iptables_cmd(args, ignore_error=False):
    """run an ipv4 iptables command. if ignore_error, don't raise."""
    return run_iptables(IPTABLES, args, ignore_error=ignore_error)


def ip6tables_cmd(args, ignore_error=False):
    """run an ipv6 ip6tables command. if ignore_error, don't raise."""
    return run_iptables(IP6TABLES, args, ignore_error=ignore_error)


def ip6tables_available():
    """true if ip6tables is installed and the kernel lets us talk to it."""
    return run_iptables(IP6TABLES, ["-n", "-L", "INPUT"], ignore_error=True)


def get_bridge_interface(network_name):
    """return the bridge interface name for the given docker network."""
    try:
        # honour an explicitly configured bridge name if the network sets one
        cmd_opt = ["docker", "network", "inspect", network_name,
                   "-f", '{{index .Options "com.docker.network.bridge.name"}}']
        name = subprocess.check_output(cmd_opt, text=True, stderr=subprocess.DEVNULL).strip()
        if name and name != "<no value>":
            return name

        cmd_id = ["docker", "network", "inspect", network_name, "-f", "{{.Id}}"]
        net_id = subprocess.check_output(cmd_id, text=True).strip()
        if not net_id:
            return None
        return f"br-{net_id[:12]}"
    except subprocess.CalledProcessError:
        return None


def get_gateway_ip(network_name):
    """return the gateway ip for the docker network."""
    try:
        cmd = ["docker", "network", "inspect", network_name,
               "-f", "{{(index .IPAM.Config 0).Gateway}}"]
        gateway = subprocess.check_output(cmd, text=True).strip()
        return gateway or None
    except subprocess.CalledProcessError:
        return None


def get_subnet(network_name):
    """return the subnet cidr for the docker network."""
    try:
        cmd = ["docker", "network", "inspect", network_name,
               "-f", "{{(index .IPAM.Config 0).Subnet}}"]
        subnet = subprocess.check_output(cmd, text=True).strip()
        return subnet or None
    except subprocess.CalledProcessError:
        return None


def port_arg(port_range):
    """turn '1337-1355' into iptables' '1337:1355'. a bare port is passed through."""
    if '-' in port_range:
        start, end = port_range.split('-', 1)
        return f"{start}:{end}"
    return port_range


# ---------------------------------------------------------------- chain helpers

def chain_exists(chain, binary=IPTABLES):
    return run_iptables(binary, ["-n", "-L", chain], ignore_error=True)


def ensure_chain(chain, binary=IPTABLES):
    """create the chain if needed, then flush it so setup is idempotent."""
    if not chain_exists(chain, binary):
        run_iptables(binary, ["-N", chain])
    else:
        run_iptables(binary, ["-F", chain])


def ensure_chain_closed(chain, binary=IPTABLES):
    """
    (re)create the chain in a deny-all state.

    the terminal DROP goes in *before* any allow rule, and allow rules are then
    inserted above it with insert_rule(). that way the chain denies by default at
    every instant - during the rebuild window, and after a rebuild that raised part
    way through. building the chain the other way round (allows first, DROP last)
    means a single bad rule leaves a live hook pointing at a chain with no DROP,
    and every guest packet falls through to the ACCEPT policy of INPUT.
    """
    ensure_chain(chain, binary)
    run_iptables(binary, ["-A", chain, "-j", "DROP"])


def insert_rule(chain, rule, position, binary=IPTABLES):
    """insert a rule at `position`, i.e. above the chain's terminal DROP."""
    run_iptables(binary, ["-I", chain, str(position)] + list(rule))


def append_rule(chain, rule, binary=IPTABLES):
    """append a rule at the end of the chain."""
    run_iptables(binary, ["-A", chain] + list(rule))


def delete_chain(chain, binary=IPTABLES):
    """
    flush and delete the chain. returns True once the chain is gone.

    a chain that is still referenced cannot be deleted, so callers must unhook it
    first - see remove_all_hooks().
    """
    if not chain_exists(chain, binary):
        return True
    run_iptables(binary, ["-F", chain], ignore_error=True)
    run_iptables(binary, ["-X", chain], ignore_error=True)
    return not chain_exists(chain, binary)


def _hook_args(parent, bridge_if, chain, direction="-i"):
    return [parent, direction, bridge_if, "-j", chain]


def ensure_jump(parent, match, chain, binary=IPTABLES):
    """
    insert "-I <parent> <match...> -j <chain>" at the top of the parent chain,
    unless an identical rule is already there.
    """
    args = [parent] + list(match) + ["-j", chain]
    if run_iptables(binary, ["-C"] + args, ignore_error=True):
        return False
    run_iptables(binary, ["-I"] + args)
    return True


def ensure_hook(parent, bridge_if, chain, direction="-i", binary=IPTABLES):
    """insert the jump from the parent chain at the top, if not already present."""
    return ensure_jump(parent, [direction, bridge_if], chain, binary)


def remove_hook(parent, bridge_if, chain, direction="-i", binary=IPTABLES):
    """remove every copy of the jump from the parent chain."""
    args = _hook_args(parent, bridge_if, chain, direction)
    removed = 0
    while run_iptables(binary, ["-D"] + args, ignore_error=True):
        removed += 1
    return removed


def _saved_rules(parent, binary=IPTABLES):
    """`iptables -S <parent>` split into lines, or [] if the chain isn't there."""
    try:
        out = subprocess.check_output(_privileged_prefix() + [binary, "-S", parent],
                                      text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return out.splitlines()


def remove_all_hooks(chain, binary=IPTABLES):
    """
    remove every jump to `chain` from the parent chains, whatever interface it matches.

    remove_hook() can only delete a hook whose bridge interface we can still name, and
    by teardown time the docker network - and with it the bridge name - is often
    already gone. without this the jump stays in INPUT forever: the chain gets flushed
    but "-X" fails because it is still referenced, so the restrictions silently rot
    into a growing pile of dangling rules that no later teardown can find.
    """
    removed = 0
    for parent in HOOK_PARENTS:
        if not chain_exists(parent, binary):
            continue
        for line in _saved_rules(parent, binary):
            if not line.startswith("-A "):
                continue
            if not line.rstrip().endswith(f"-j {chain}"):
                continue
            args = shlex.split(line)
            args[0] = "-D"
            if run_iptables(binary, args, ignore_error=True):
                removed += 1
    return removed


def ensure_docker_user_chain():
    """
    make sure DOCKER-USER exists *and* is actually reached from FORWARD.

    docker normally creates DOCKER-USER and inserts "-A FORWARD -j DOCKER-USER"
    itself. if it has not (daemon not started yet, daemon restarted, iptables
    flushed), simply creating the chain leaves it at 0 references - the guest ->
    forwarded and forwarded -> guest DROPs are then a silent no-op and the guests
    keep full lan/other-network reachability while setup happily reports success.

    returns True if DOCKER-USER is reachable from FORWARD by the time we are done.
    """
    if not chain_exists("DOCKER-USER"):
        iptables_cmd(["-N", "DOCKER-USER"], ignore_error=True)
    if not chain_exists("DOCKER-USER"):
        return False

    if not iptables_cmd(["-C", "FORWARD", "-j", "DOCKER-USER"], ignore_error=True):
        iptables_cmd(["-I", "FORWARD", "1", "-j", "DOCKER-USER"], ignore_error=True)

    return iptables_cmd(["-C", "FORWARD", "-j", "DOCKER-USER"], ignore_error=True)


# ----------------------------------------------------------- bridge netfilter

def _sysctl_get(key):
    try:
        out = subprocess.check_output(_privileged_prefix() + ["sysctl", "-n", key],
                                      text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _ensure_sysctl_on(key):
    """set `key` to 1 and return True if it reads back as 1."""
    if _sysctl_get(key) == "1":
        return True
    subprocess.run(_privileged_prefix() + ["sysctl", "-w", f"{key}=1"],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return _sysctl_get(key) == "1"


def ensure_bridge_netfilter():
    """
    make sure bridged traffic is actually handed to iptables *and* ip6tables.

    traffic between two guests on the same bridge only traverses the FORWARD chain
    when br_netfilter is loaded and net.bridge.bridge-nf-call-iptables is 1. if it
    is not, the guest-to-guest DROP is silently a no-op and the guests can still
    reach each other. docker normally sets this up itself, but do not rely on it -
    a silent no-op here is exactly the failure mode this whole change is about.

    the same goes for net.bridge.bridge-nf-call-ip6tables and the ipv6 mirror of
    the forward chains: docker only turns that one on for an ipv6-enabled network,
    and the playground network is ipv4-only, so two guests could otherwise still
    talk over their link-local addresses.

    returns the names of the sysctls that are *not* on by the time we are done.
    """
    if _sysctl_get(BRIDGE_NF_SYSCTL) is None:
        # the sysctls only appear once br_netfilter is loaded
        subprocess.run(_privileged_prefix() + ["modprobe", "br_netfilter"],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return [key for key in BRIDGE_NF_SYSCTLS if not _ensure_sysctl_on(key)]


# ------------------------------------------------------- legacy rule cleanup

def remove_legacy_rules(bridge_if, gateway_ip, ranges):
    """
    remove the flat DOCKER-USER rules written by earlier versions of this script.

    the old blanket "-i <bridge> -j DROP" also killed guest-to-guest traffic inside
    the playground, so it must not be left behind after an upgrade.
    """
    legacy = [
        ["DOCKER-USER", "-i", bridge_if, "-j", "DROP"],
        ["DOCKER-USER", "-i", bridge_if, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    if gateway_ip:
        for rng in ranges:
            legacy.append([
                "DOCKER-USER", "-i", bridge_if, "-d", gateway_ip,
                "-p", "tcp", "--dport", port_arg(rng), "-j", "ACCEPT",
            ])

    removed = 0
    for rule in legacy:
        while iptables_cmd(["-D"] + rule, ignore_error=True):
            removed += 1
    return removed


# ------------------------------------------------- published endpoint shadowing

def range_bounds(port_range):
    """turn '1337-1355' (or a bare '1337') into an inclusive (start, end) pair."""
    if '-' in port_range:
        start, end = port_range.split('-', 1)
        return int(start), int(end)
    port = int(port_range)
    return port, port


_DNAT_DPORT_RE = re.compile(r"--dport\s+(\d+)")
_DNAT_TARGET_RE = re.compile(r"--to-destination\s+(\S+)")
_DNAT_BIND_RE = re.compile(r"\s-d\s+(\d+\.\d+\.\d+\.\d+)")


def parse_published_ports(rules):
    """
    pull (host_port, destination) out of docker's published-port DNAT rules.

    docker writes one rule per published port into nat/DOCKER:

      -A DOCKER ! -i br-x -p tcp -m tcp --dport 1337 -j DNAT --to-destination 172.18.0.15:1337

    a publish bound to loopback ("-d 127.0.0.1/32", i.e. "127.0.0.1:2223:8080") can
    never be hit from the bridge, so it is not a conflict and is skipped here.
    """
    published = []
    for line in rules:
        if "-j DNAT" not in line:
            continue
        dport = _DNAT_DPORT_RE.search(line)
        target = _DNAT_TARGET_RE.search(line)
        if not dport or not target:
            continue
        bind = _DNAT_BIND_RE.search(line)
        if bind and bind.group(1).startswith("127."):
            continue
        published.append((int(dport.group(1)), target.group(1)))
    return published


def endpoint_conflicts(ranges, published):
    """
    published container ports that fall inside a configured endpoint range.

    such a port is not an endpoint on the host at all. nat/PREROUTING runs *before*
    the routing decision, so a guest packet to <gateway>:<port> is rewritten to the
    container and forwarded - it never reaches INPUT, and so never reaches
    ATTACK_PG_INPUT. a host process listening on that port of the gateway is
    shadowed: it keeps its socket and stops receiving guest connections.

    the connection still succeeds, which is exactly why this has to be reported.
    "nc -z <gateway> 1337" cannot tell the host listener from the container that
    took the port over, so an endpoint the operator believes is a host service is
    quietly a container, and the check that was meant to exercise the INPUT
    allowlist exercises the FORWARD one twice instead.

    returns (host_port, destination, range) triples.
    """
    conflicts = []
    for host_port, target in published:
        for rng in ranges:
            start, end = range_bounds(rng)
            if start <= host_port <= end:
                conflicts.append((host_port, target, rng))
                break
    return conflicts


def find_endpoint_conflicts(ranges):
    """endpoint_conflicts() against the live nat/DOCKER chain."""
    try:
        out = subprocess.check_output(
            _privileged_prefix() + [IPTABLES, "-t", "nat", "-S", "DOCKER"],
            text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return endpoint_conflicts(ranges, parse_published_ports(out.splitlines()))


# ------------------------------------------------------------------- config io

def _valid_port(value):
    """true if `value` is a port number iptables will accept."""
    try:
        return MIN_PORT <= int(value) <= MAX_PORT
    except ValueError:
        return False


def ssh_port_from_env(environ=None):
    """
    the host port containerssh is published on, from the SSH_PORT variable that
    start.sh passes through from .env.

    the connection cap is keyed on it, so a missing or malformed value is an error
    rather than a fallback: a cap on the wrong port is no cap at all, and nothing
    would say so.
    """
    value = (os.environ if environ is None else environ).get(SSH_PORT_ENV)
    if value is None:
        problem = "not set"
    elif not _valid_port(value):
        problem = f"{value!r}, which is not a port number"
    else:
        return int(value)
    raise ValueError(f"{SSH_PORT_ENV} is {problem}. start.sh sets it from .env;"
                     " bring the playground up through start.sh")


def parse_config(config_path):
    """
    read port ranges from config file, ignoring comments and blank lines.

    ports are range-checked here rather than left to iptables. "70000" or "1337-99999"
    matches the digit patterns below but is rejected by iptables with "invalid
    port/service", which used to abort the rebuild half way through the chain.
    """
    if not os.path.exists(config_path):
        return []

    ranges = []
    with open(config_path, 'r') as f:
        for line in f:
            line = line.strip()

            # comment line
            if not line or line.startswith('#'):
                continue

            # a single port specified
            if re.match(r'^\d+$', line):
                if _valid_port(line):
                    ranges.append(line)
                else:
                    print(f"warning: port out of range ({MIN_PORT}-{MAX_PORT}): {line}")

            # port range specified
            elif re.match(r'^\d+-\d+$', line):
                start, end = line.split('-')
                if not (_valid_port(start) and _valid_port(end)):
                    print(f"warning: port out of range ({MIN_PORT}-{MAX_PORT}): {line}")
                elif int(start) <= int(end):
                    ranges.append(line)
                else:
                    print(f"warning: invalid range (start > end): {line}")

            else:
                print(f"warning: skipping invalid line: {line}")
    return ranges


def find_config():
    """locate the endpoints config: repo root first, then script dir, then cwd."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    for candidate in (
        os.path.join(repo_root, CONFIG_FILE),
        os.path.join(script_dir, CONFIG_FILE),
        os.path.join(os.getcwd(), CONFIG_FILE),
    ):
        if os.path.exists(candidate):
            return candidate
    return None

