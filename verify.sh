#!/bin/bash
# end-to-end verification of the attack playground on a real linux host.
# run from inside the repo directory on the VM. does not abort on first failure -
# the point is a full picture.

cd "$(dirname "$0")"

# the published ports (.env) and the stats helper
# shellcheck source=scripts/common.sh
source scripts/common.sh
load_ports || exit 1

PASS=0; FAIL=0
ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
hdr()  { echo; echo "=== $* ==="; }

# private scratch dir rather than fixed names under /tmp, which another local
# user could pre-create as symlinks
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

GUEST_IMAGE="attack_playground_image:latest"
NET="attack_playground_net"

hdr "unit tests"
if python3 -m unittest discover -s scripts -p 'test_*.py' > "$WORK/unit.log" 2>&1; then
    ok "$(grep -oE 'Ran [0-9]+ tests' "$WORK/unit.log") OK"
else
    bad "unit tests failed"; tail -20 "$WORK/unit.log"
fi

hdr "start.sh"
if ./start.sh > "$WORK/start.log" 2>&1; then
    ok "start.sh exited 0"
else
    bad "start.sh exited $?"; tail -30 "$WORK/start.log"
fi
grep -q "playground is running" "$WORK/start.log" && ok "reported running" || bad "no 'running' line"

hdr "iptables chains"
for c in ATTACK_PG_INPUT ATTACK_PG_FWD ATTACK_PG_FWD_IN ATTACK_PG_SSH; do
    if sudo iptables -n -L "$c" > /dev/null 2>&1; then
        ok "$c exists"
        # the terminal rule must be a DROP - that is the fail-closed invariant
        if sudo iptables -S "$c" | tail -1 | grep -q -- "-j DROP"; then
            ok "$c ends in DROP"
        else
            bad "$c does NOT end in DROP"; sudo iptables -S "$c"
        fi
    else
        bad "$c missing"
    fi
done

# the allowlist must be in INPUT, and must name the gateway ip
GW=$(docker network inspect "$NET" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
echo "  (gateway: $GW)"
# every range the config allows, read through the parser the setup used: the
# expectation follows attack_network_endpoints.conf rather than a copy of it
RANGES=$(python3 scripts/endpoints.py ranges 2>/dev/null)
[ -n "$RANGES" ] || bad "attack_network_endpoints.conf allows no ports - nothing to verify against"
for R in $RANGES; do
    sudo iptables -S ATTACK_PG_INPUT | grep -qE -- "--dports? $R( |$)" \
        && ok "endpoint range $R allowed" || bad "endpoint range $R not in ATTACK_PG_INPUT"
done
sudo iptables -S ATTACK_PG_INPUT | grep -q -- "-d $GW" \
    && ok "allow rules are scoped to the gateway ip" || bad "allow rules not scoped to gateway"

# a docker-published endpoint is DNATed and forwarded, so the same allowlist must
# also exist in the forward chain keyed on the *original* destination
for R in $RANGES; do
    sudo iptables -S ATTACK_PG_FWD | grep -qE -- "--ctstate DNAT.*--ctorigdst $GW.*--ctorigdstport $R( |$)" \
        && ok "published endpoints in $R allowed through FORWARD" || bad "no DNAT allow for $R in ATTACK_PG_FWD"
done
sudo iptables -S ATTACK_PG_FWD_IN | grep -qE -- "--ctstate (RELATED,ESTABLISHED|ESTABLISHED,RELATED)" \
    && ok "replies to guest connections allowed back" || bad "no ESTABLISHED allow in ATTACK_PG_FWD_IN"

# the ssh connection cap
sudo iptables -S ATTACK_PG_SSH | grep -q -- "--connlimit-above" \
    && ok "ssh connection cap in place" || bad "no connlimit rule in ATTACK_PG_SSH"

hdr "hooks are live"
sudo iptables -S INPUT | grep -q "ATTACK_PG_INPUT" && ok "INPUT -> ATTACK_PG_INPUT" || bad "INPUT hook missing"
sudo iptables -S INPUT | grep -q -- "--dport $SSH_PORT .*ATTACK_PG_SSH" && ok "INPUT -> ATTACK_PG_SSH (port $SSH_PORT)" || bad "ssh cap hook missing on port $SSH_PORT"
sudo iptables -S DOCKER-USER | grep -q "ATTACK_PG_FWD" && ok "DOCKER-USER -> ATTACK_PG_FWD" || bad "forward hook missing"
sudo iptables -n -L DOCKER-USER | head -1 | grep -q "0 references" \
    && bad "DOCKER-USER has 0 references (chain is dead)" || ok "DOCKER-USER is referenced"

hdr "endpoint shadowing"
# an allowed endpoint is supposed to be a service on the host, reached through
# ATTACK_PG_INPUT. if a container publishes a host port inside one of the ranges,
# docker's DNAT rule in nat/PREROUTING takes that port over: the guest's packet is
# rewritten to the container before the routing decision, travels FORWARD, and the
# INPUT allowlist never sees it. the connection still succeeds, so a "nc -z" probe
# cannot tell the two apart - this check reads the nat table instead.
SHADOW=$(python3 - <<'PY' 2>/dev/null
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "scripts"))
import network_common_linux as nc
config = nc.find_config()
ranges = nc.parse_config(config) if config else []
for host_port, target, rng in nc.find_endpoint_conflicts(ranges):
    print(host_port, target, rng)
PY
)
if [ -z "$SHADOW" ]; then
    ok "no configured endpoint is shadowed by a published container port"
else
    while read -r port target rng; do
        [ -z "$port" ] && continue
        bad "tcp $port (endpoint range $rng) is published by $target - dialling the gateway there reaches the container, not the host, and skips ATTACK_PG_INPUT"
    done <<< "$SHADOW"
fi

# docker hands out dynamic host ports ("-p 80" with no host side) from the kernel's
# ip_local_port_range, so a range that overlaps it can be taken over by a container
# nobody published deliberately.
EPHEMERAL=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null)
if [ -n "$EPHEMERAL" ]; then
    OVERLAP=$(python3 - "$EPHEMERAL" <<'PY' 2>/dev/null
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "scripts"))
import network_common_linux as nc
lo, hi = (int(x) for x in sys.argv[1].split())
config = nc.find_config()
for rng in (nc.parse_config(config) if config else []):
    start, end = nc.range_bounds(rng)
    if start <= hi and lo <= end:
        print(rng)
PY
)
    if [ -z "$OVERLAP" ]; then
        ok "no endpoint range overlaps docker's dynamic publish range ($EPHEMERAL)"
    else
        bad "endpoint range(s) $(echo $OVERLAP | tr '\n' ' ')overlap docker's dynamic publish range ($EPHEMERAL) - an unrelated container can be assigned one of these host ports and become guest-reachable"
    fi
fi

hdr "ipv6 mirror"
if sudo ip6tables -n -L ATTACK_PG_INPUT > /dev/null 2>&1; then
    sudo ip6tables -S ATTACK_PG_INPUT | tail -1 | grep -q -- "-j DROP" \
        && ok "ipv6 ATTACK_PG_INPUT ends in DROP" || bad "ipv6 chain not closed"
else
    bad "ipv6 chain missing"
fi

hdr "bridge netfilter"
for key in net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables; do
    V=$(sysctl -n "$key" 2>/dev/null)
    [ "$V" = "1" ] && ok "$key=1" || bad "$key=$V"
done

hdr "services"
docker ps --format '{{.Names}}' | grep -q containerssh && ok "containerssh up" || bad "containerssh not running"
docker ps --format '{{.Ports}}' | grep -q "127.0.0.1:$AUTH_PORT->" \
    && ok "auth webhook bound to loopback ($AUTH_PORT)" || bad "auth webhook not on 127.0.0.1:$AUTH_PORT"
# a docker-restarted containerssh would come back after a reboot with no chains
RP=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' containerssh 2>/dev/null)
[ "$RP" = "no" ] && ok "containerssh restart policy is 'no'" || bad "containerssh restart policy is '$RP' (must be 'no')"
docker ps --format '{{.Names}} {{.Ports}}' | grep "playground-stats" | grep -q "127.0.0.1:$STATS_PORT->" \
    && ok "stats server up and bound to loopback ($STATS_PORT)" || bad "stats server not running on 127.0.0.1:$STATS_PORT"

hdr "connection statistics"
# the numbers themselves are checked from inside real guests by verify_guest.sh;
# this is that the service answers on the port .env publishes it on, is
# following docker, and persists. stats_fields is in scripts/common.sh.
STATS=$(stats_fields /stats currently_connected connected_in_window ever_connected \
                     window_seconds collector.connected)
if [ -z "$STATS" ]; then
    bad "stats server did not answer on http://127.0.0.1:$STATS_PORT/stats"
else
    read -r S_NOW S_WIN S_EVER S_WINDOW S_LIVE <<< "$STATS"
    ok "stats server answers (now=$S_NOW, last ${S_WINDOW}s=$S_WIN, ever=$S_EVER)"
    [ "$S_LIVE" = "True" ] && ok "collector is following docker events" \
        || bad "collector is not connected to docker - the numbers are stale"
    [ "$S_NOW" -le "$S_WIN" ] && [ "$S_WIN" -le "$S_EVER" ] \
        && ok "counts nest (now <= window <= ever)" \
        || bad "counts do not nest: now=$S_NOW window=$S_WIN ever=$S_EVER"
    W=$(stats_fields '/stats?window=15m' window_seconds)
    [ "$W" = "900" ] && ok "window is configurable per request (?window=15m -> 900s)" \
        || bad "?window=15m answered '$W' instead of 900"
    # root-owned: the service runs as root, like containerssh
    if sudo test -f stats_data/stats.db; then
        ok "sessions persisted in stats_data/stats.db"
    else
        bad "stats_data/stats.db was not written - 'ever connected' will not survive a restart"
    fi
fi

hdr "guest-only name for the gateway"
# researchlabs.tech is an /etc/hosts entry docker writes into every guest, rendered
# from config.yaml with the gateway ip this run's network actually got. config.yaml
# itself keeps the placeholder - what containerssh reads is the rendered copy, so
# check that one, and check it is really the file that was mounted.
if [ ! -f config.runtime.yaml ]; then
    bad "config.runtime.yaml was not rendered (start.sh renders it from config.yaml)"
else
    if grep -q "__GATEWAY_IP__" config.runtime.yaml; then
        bad "config.runtime.yaml still holds the __GATEWAY_IP__ placeholder - guests would fail to start"
    else
        ok "no unrendered placeholder in config.runtime.yaml"
    fi
    if grep -qF "\"researchlabs.tech:$GW\"" config.runtime.yaml; then
        ok "researchlabs.tech -> $GW (this run's gateway)"
    else
        bad "config.runtime.yaml does not map researchlabs.tech to $GW"
        grep -n "researchlabs" config.runtime.yaml
    fi
fi
if docker inspect containerssh -f '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null \
     | grep -q "config.runtime.yaml"; then
    ok "containerssh is running with the rendered config"
else
    bad "containerssh is not mounting config.runtime.yaml - it is running an unrendered config"
fi
# and the entry is supposed to exist inside the guests and nowhere else. checked
# against the gateway ip rather than "does not resolve at all": researchlabs.tech is
# a real domain name, and a host with a resolver may well have an answer for it.
if getent hosts researchlabs.tech 2>/dev/null | grep -q "$GW"; then
    bad "the host itself resolves researchlabs.tech to $GW - that entry belongs in the guests only"
else
    ok "the host does not resolve researchlabs.tech to the gateway"
fi

hdr "persisted rules"
# netfilter-persistent would freeze docker's dynamic rules into a file that is
# restored before dockerd starts; the systemd unit re-runs start.sh instead
if [ -f /etc/iptables/rules.v4 ] && grep -q ATTACK_PG /etc/iptables/rules.v4; then
    bad "ATTACK_PG chains are in /etc/iptables/rules.v4 - remove them, they are re-applied by start.sh"
else
    ok "no stale ATTACK_PG rules persisted on disk"
fi

echo
echo "======================================"
echo " passed: $PASS   failed: $FAIL"
echo "======================================"
[ "$FAIL" -eq 0 ]
