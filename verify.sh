#!/bin/bash
# end-to-end verification of the attack playground on a real linux host.
# run from inside the repo directory on the VM. does not abort on first failure -
# the point is a full picture.

cd "$(dirname "$0")"

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
sudo iptables -S ATTACK_PG_INPUT | grep -q "dports\? 1337:1355" \
    && ok "endpoint range 1337-1355 allowed" || bad "endpoint range not in chain"
sudo iptables -S ATTACK_PG_INPUT | grep -q -- "-d $GW" \
    && ok "allow rules are scoped to the gateway ip" || bad "allow rules not scoped to gateway"

# a docker-published endpoint is DNATed and forwarded, so the same allowlist must
# also exist in the forward chain keyed on the *original* destination
sudo iptables -S ATTACK_PG_FWD | grep -q -- "--ctstate DNAT.*--ctorigdst $GW.*--ctorigdstport 1337:1355" \
    && ok "published endpoints allowed through FORWARD" || bad "no DNAT allow in ATTACK_PG_FWD"
sudo iptables -S ATTACK_PG_FWD_IN | grep -qE -- "--ctstate (RELATED,ESTABLISHED|ESTABLISHED,RELATED)" \
    && ok "replies to guest connections allowed back" || bad "no ESTABLISHED allow in ATTACK_PG_FWD_IN"

# the ssh connection cap
sudo iptables -S ATTACK_PG_SSH | grep -q -- "--connlimit-above" \
    && ok "ssh connection cap in place" || bad "no connlimit rule in ATTACK_PG_SSH"

hdr "hooks are live"
sudo iptables -S INPUT | grep -q "ATTACK_PG_INPUT" && ok "INPUT -> ATTACK_PG_INPUT" || bad "INPUT hook missing"
sudo iptables -S INPUT | grep -q -- "--dport 2222.*ATTACK_PG_SSH" && ok "INPUT -> ATTACK_PG_SSH" || bad "ssh cap hook missing"
sudo iptables -S DOCKER-USER | grep -q "ATTACK_PG_FWD" && ok "DOCKER-USER -> ATTACK_PG_FWD" || bad "forward hook missing"
sudo iptables -n -L DOCKER-USER | head -1 | grep -q "0 references" \
    && bad "DOCKER-USER has 0 references (chain is dead)" || ok "DOCKER-USER is referenced"

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
docker ps --format '{{.Ports}}' | grep -q "127.0.0.1:2223" \
    && ok "auth webhook bound to loopback" || bad "auth webhook not on loopback"
# a docker-restarted containerssh would come back after a reboot with no chains
RP=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' containerssh 2>/dev/null)
[ "$RP" = "no" ] && ok "containerssh restart policy is 'no'" || bad "containerssh restart policy is '$RP' (must be 'no')"

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
