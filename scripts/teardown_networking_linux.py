#!/usr/bin/env python3
"""
remove the network restrictions applied by setup_networking_linux.py.
"""

import sys

from network_common_linux import (
    DOCKER_NET_NAME, INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN, SSH_LIMIT_CHAIN,
    IPTABLES, IP6TABLES,
    get_bridge_interface, get_gateway_ip,
    remove_all_hooks, delete_chain, remove_legacy_rules,
    ip6tables_available,
    parse_config, find_config,
)

CHAINS = (INPUT_CHAIN, FORWARD_CHAIN, FORWARD_IN_CHAIN, SSH_LIMIT_CHAIN)


def drop_chains(binary):
    """
    unhook and delete our chains for one address family.

    the hooks are found by scanning the parent chains for jumps to our chains rather
    than by rebuilding the "-i <bridge>" rule: by teardown time the docker network is
    often already gone, and with it the bridge name the hook was written with. a hook
    we cannot name is a hook we cannot delete, and a chain that is still referenced
    cannot be deleted either - it just gets flushed and left behind, live, forever.

    returns the names of any chains that could not be removed.
    """
    stuck = []
    for chain in CHAINS:
        remove_all_hooks(chain, binary)
        if not delete_chain(chain, binary):
            stuck.append(chain)
    return stuck


def main():
    bridge_if = get_bridge_interface(DOCKER_NET_NAME)
    if bridge_if:
        print(f"removing restrictions on {bridge_if}")
    else:
        # the network is already gone; the chains are still around, so drop them
        print(f"info: network '{DOCKER_NET_NAME}' not found, removing leftover chains.")

    stuck = drop_chains(IPTABLES)
    if ip6tables_available():
        stuck += drop_chains(IP6TABLES)

    if bridge_if:
        # also clear anything left by older versions of the setup script
        gateway_ip = get_gateway_ip(DOCKER_NET_NAME)
        config_path = find_config()
        ranges = parse_config(config_path) if config_path else []
        remove_legacy_rules(bridge_if, gateway_ip, ranges)

    # the FORWARD -> DOCKER-USER jump and the bridge-nf sysctls are left alone on
    # purpose - both belong to docker, which relies on them.

    if stuck:
        print(f"error: could not remove chain(s): {', '.join(sorted(set(stuck)))}")
        print("       something outside this script still references them.")
        sys.exit(1)

    print("cleanup complete.")


if __name__ == "__main__":
    main()
