#!/usr/bin/env python3
"""
apply the network restrictions for the playground guest network.

a guest may reach the host on the tcp ports listed in the endpoints config, and
nothing else. see network_common_linux.py for the chain layout, for why the
endpoint allowlist lives in INPUT rather than in DOCKER-USER, for how published
(docker) endpoints are let through FORWARD, and for why the chains are built
deny-first.
"""

import sys

from network_common_linux import (
    DOCKER_NET_NAME, INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN, SSH_LIMIT_CHAIN,
    SSH_PORT, MAX_SSH_CONNECTIONS,
    IPTABLES, IP6TABLES, IptablesError,
    get_bridge_interface, get_gateway_ip,
    port_arg, insert_rule, append_rule,
    ensure_chain, ensure_chain_closed, ensure_hook, ensure_jump,
    ensure_docker_user_chain,
    ensure_bridge_netfilter, ip6tables_available, remove_legacy_rules,
    parse_config, find_config,
)

CHAINS = (INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN)


def build_input_chain(gateway_ip, ranges):
    """
    guest -> host: allow only the configured attack endpoints on the gateway.

    ensure_chain_closed() has already put a terminal DROP in the chain, so every rule
    here is *inserted above* it. the chain therefore denies by default the whole time
    it is being built: if one of these inserts fails, the guests are locked out rather
    than let through.
    """
    position = 1

    # replies for connections the guest already opened (and host-initiated ones)
    insert_rule(INPUT_CHAIN,
                ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                position)
    position += 1

    for rng in ranges:
        insert_rule(INPUT_CHAIN,
                    ["-d", gateway_ip, "-p", "tcp", "--dport", port_arg(rng), "-j", "ACCEPT"],
                    position)
        position += 1
        print(f"  allow tcp {rng} -> {gateway_ip}")


def build_forward_chains(gateway_ip, ranges):
    """
    guest -> forwarded, and forwarded -> guest.

    an attack endpoint that is itself a docker container with a published port is
    DNATed in the nat table before routing, so from a guest it looks like
    <gateway>:<port> but arrives in FORWARD addressed to the endpoint container.
    the INPUT allowlist never sees it. so ATTACK_PG_FWD allows connections whose
    *original* destination - what the guest actually dialled - was an allowed
    port on the gateway, and ATTACK_PG_FWD_IN lets the replies back in.

    the ACCEPT here is evaluated from DOCKER-USER, which docker puts first in
    FORWARD, so it takes precedence over docker's own isolation rules for the
    --internal network. that is the documented purpose of DOCKER-USER.

    both chains already end in DROP; everything here goes above it.
    """
    position = 1
    for rng in ranges:
        insert_rule(FORWARD_CHAIN,
                    ["-p", "tcp", "-m", "conntrack", "--ctstate", "DNAT",
                     "--ctproto", "tcp", "--ctorigdst", gateway_ip,
                     "--ctorigdstport", port_arg(rng), "-j", "ACCEPT"],
                    position)
        position += 1
    if ranges:
        print(f"  allow tcp {', '.join(ranges)} -> {gateway_ip} when published by a container")

    # only replies to connections a guest opened, and a guest can only open what
    # the two allowlists permit - so this widens nothing
    insert_rule(FORWARD_IN_CHAIN,
                ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                1)


def apply_ssh_limit(binary=IPTABLES):
    """
    cap the number of concurrent ssh connections to containerssh.

    every accepted connection is a guest container, the webhook accepts everyone,
    and containerssh has no cap of its own - so without this anyone on the lan
    can mint guests until the host runs out of memory. counted over all sources
    (--connlimit-mask 0): the point is what the host spends, not fairness.

    this is a limit rather than a restriction, so a kernel without xt_connlimit
    is a warning and not a refusal to start. the chain is built empty and only
    then given its DROP: an empty chain here just means "no cap", which is the
    same as not having the chain at all.
    """
    try:
        ensure_chain(SSH_LIMIT_CHAIN, binary)
        append_rule(SSH_LIMIT_CHAIN,
                    ["-m", "connlimit", "--connlimit-above", str(MAX_SSH_CONNECTIONS),
                     "--connlimit-mask", "0", "-j", "DROP"],
                    binary)
        ensure_jump("INPUT", ["-p", "tcp", "--dport", str(SSH_PORT), "--syn"],
                    SSH_LIMIT_CHAIN, binary)
    except IptablesError as exc:
        print(f"  warning: could not cap ssh connections ({binary}): {exc}")
        return False
    return True


def apply_ipv6_restrictions(bridge_if):
    """
    the same policy, for ipv6.

    iptables only covers ipv4. the playground network is ipv4-only, but as long as the
    host kernel has ipv6 enabled the guest's eth0 and the host side of the bridge both
    still get link-local (fe80::/64) addresses, so a guest can reach any host port over
    ipv6 and walk straight past the ipv4 allowlist. every configured endpoint is a tcp
    port on the ipv4 gateway, so there is nothing to allow over ipv6 - drop the lot.

    docker only maintains DOCKER-USER in ip6tables when its ip6tables support is turned
    on, so hook into FORWARD directly instead of relying on it being there.

    a missing ip6tables is a warning, not a failure: the ipv4 policy is still applied.
    """
    if not ip6tables_available():
        print("  warning: ip6tables unavailable, ipv6 on the bridge is NOT filtered.")
        return False

    try:
        for chain in CHAINS:
            ensure_chain_closed(chain, IP6TABLES)
        ensure_hook("INPUT", bridge_if, INPUT_CHAIN, "-i", IP6TABLES)
        ensure_hook("FORWARD", bridge_if, FORWARD_CHAIN, "-i", IP6TABLES)
        ensure_hook("FORWARD", bridge_if, FORWARD_IN_CHAIN, "-o", IP6TABLES)
    except IptablesError as exc:
        print(f"  warning: could not apply ipv6 restrictions: {exc}")
        return False

    # port 2222 is published on :: as well as 0.0.0.0
    apply_ssh_limit(IP6TABLES)

    print("  deny all ipv6 on the bridge (link-local would bypass the ipv4 allowlist)")
    return True


def apply_restrictions(bridge_if, gateway_ip, ranges):
    print(f"applying restrictions on {bridge_if} (gateway {gateway_ip})")

    # without this, guest-to-guest traffic never reaches iptables and the drop below
    # is silently a no-op
    for key in ensure_bridge_netfilter():
        print(f"  warning: could not enable {key}.")
        print("           guest-to-guest traffic on the bridge may bypass the firewall"
              " and stay reachable.")

    # drop the flat rules written by older versions of this script before rebuilding
    removed = remove_legacy_rules(bridge_if, gateway_ip, ranges)
    if removed:
        print(f"  removed {removed} legacy DOCKER-USER rule(s)")

    # rebuild every chain from scratch - safe to re-run. each one comes back as
    # deny-all first and only then gets its allow rules, so the guests are never
    # briefly unrestricted mid-rebuild.
    for chain in CHAINS:
        ensure_chain_closed(chain)

    build_input_chain(gateway_ip, ranges)
    build_forward_chains(gateway_ip, ranges)
    print("  deny everything else (internet, lan, other networks, guest-to-guest)")

    # a chain nothing jumps to is silently dead, so make sure FORWARD really reaches
    # DOCKER-USER before hanging the forward policy off it
    if not ensure_docker_user_chain():
        print("  error: DOCKER-USER is not reachable from FORWARD.")
        print("         the guest -> lan and lan -> guest drops would be a no-op.")
        return False

    ensure_hook("INPUT", bridge_if, INPUT_CHAIN, "-i")
    ensure_hook("DOCKER-USER", bridge_if, FORWARD_CHAIN, "-i")
    ensure_hook("DOCKER-USER", bridge_if, FORWARD_IN_CHAIN, "-o")

    if apply_ssh_limit():
        print(f"  cap concurrent ssh connections on port {SSH_PORT} at {MAX_SSH_CONNECTIONS}")

    apply_ipv6_restrictions(bridge_if)

    # the rules are deliberately *not* persisted with netfilter-persistent: that
    # would also freeze docker's own dynamic nat/filter rules into a file that is
    # restored before dockerd starts on the next boot. the systemd unit in
    # systemd/ re-runs start.sh - and with it this script - after docker is up.
    return True


def main():
    bridge_if = get_bridge_interface(DOCKER_NET_NAME)
    if not bridge_if:
        print(f"error: network '{DOCKER_NET_NAME}' not found.")
        sys.exit(1)

    gateway_ip = get_gateway_ip(DOCKER_NET_NAME)
    if not gateway_ip:
        print("error: could not determine gateway ip for network.")
        sys.exit(1)

    config_path = find_config()
    if not config_path:
        print("warning: endpoints config file not found, no endpoints will be allowed.")
        ranges = []
    else:
        ranges = parse_config(config_path)
        if not ranges:
            print(f"warning: no valid port ranges in {config_path}, "
                  "no endpoints will be allowed.")

    try:
        ok = apply_restrictions(bridge_if, gateway_ip, ranges)
    except IptablesError as exc:
        # the chains were built deny-first, so the guests are locked out rather than
        # wide open - but the restrictions are not what the config asked for, and the
        # caller must not go on to advertise a working playground.
        print(f"error: {exc}")
        print("       restrictions are incomplete; the chains are left denying traffic.")
        sys.exit(1)

    if not ok:
        sys.exit(1)

    print("network restrictions applied")


if __name__ == "__main__":
    main()
