#!/bin/bash
# proves the network policy from inside real guest containers:
# a guest may reach the host on the configured tcp ports and nothing else.
#
# a probe that never ran is an ERROR, never a PASS - otherwise a broken containerssh
# makes the whole suite go green while nothing was tested.
#
# guests are torn down the moment their ssh session ends, so long-lived "hold"
# sessions are opened first and everything is inspected while they are up.

cd "$(dirname "$0")"

PASS=0; FAIL=0; ERR=0
ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
err()  { echo "  ERROR (not tested): $*"; ERR=$((ERR+1)); }
hdr()  { echo; echo "=== $* ==="; }

NET="attack_playground_net"
IMG="attack_playground_image:latest"
GW=$(docker network inspect "$NET" -f '{{(index .IPAM.Config 0).Gateway}}')
echo "gateway: $GW"

# the listener below serves a directory over http. an *empty* private one - the
# repo has the ssh host private key in it - and bound to the gateway only, so the
# test endpoint is reachable from the guests and from nowhere else.
WORK=$(mktemp -d)
LISTENER=""; ENDPOINT_CTR=""; H1=""; H2=""
cleanup() {
    # the hold sessions run under setsid, so killing the group takes sshpass and
    # the ssh it forked with it - killing sshpass alone leaves ssh, and with it a
    # guest, around for the full "sleep 600"
    [ -n "$H1" ] && kill -- -"$H1" 2>/dev/null
    [ -n "$H2" ] && kill -- -"$H2" 2>/dev/null
    [ -n "$LISTENER" ] && kill "$LISTENER" 2>/dev/null
    [ -n "$ENDPOINT_CTR" ] && docker rm -f "$ENDPOINT_CTR" > /dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=30"
guest() { sshpass -p anything ssh $SSH_OPTS -p 2222 guestuser@127.0.0.1 "$1" 2>&1; }
guests_up() { docker ps -q --filter ancestor="$IMG" | grep -c . ; }

hdr "host listener on an allowed endpoint (1337)"
nohup python3 -m http.server 1337 --bind "$GW" --directory "$WORK" > "$WORK/listener.log" 2>&1 &
LISTENER=$!
sleep 2
ss -lnt 2>/dev/null | grep -q "$GW:1337" && ok "listener up on $GW:1337" || bad "listener did not bind"

hdr "docker-published endpoint (1338)"
# an endpoint that is itself a container: from the guest it is <gateway>:1338, but
# docker DNATs it and it travels FORWARD, not INPUT - a different code path
ENDPOINT_CTR=$(docker run -d --rm -p 1338:80 python:3.11-slim \
               python -m http.server 80 --bind 0.0.0.0 2>/dev/null)
if [ -n "$ENDPOINT_CTR" ]; then
    sleep 2
    ok "endpoint container up, published on 1338"
else
    err "could not start the endpoint container"
fi

hdr "open two guest sessions"
setsid sshpass -p anything ssh $SSH_OPTS -p 2222 guestuser@127.0.0.1 'sleep 600' > /dev/null 2>&1 &
H1=$!
setsid sshpass -p anything ssh $SSH_OPTS -p 2222 guestuser@127.0.0.1 'sleep 600' > /dev/null 2>&1 &
H2=$!
for i in $(seq 1 60); do
    [ "$(guests_up)" -ge 2 ] && break
    sleep 5
done
N=$(guests_up)
echo "  guests running: $N"
[ "$N" -ge 1 ] && ok "at least one guest container spawned" || bad "no guest spawned"

hdr "ssh into a guest"
CANARY=$(guest 'echo GUEST_OK')
if echo "$CANARY" | grep -q GUEST_OK; then
    ok "ssh exec into guest works"; GUEST_UP=1
else
    bad "cannot open a guest session: $CANARY"; GUEST_UP=0
fi

hdr "guest is on the restricted network only"
# every guest is inspected, not just the first: a guest is torn down the instant
# its ssh session ends, so "docker ps | head -1" can hand back the short-lived
# canary container as it is being removed and the inspect then fails on a
# container that was never the point of the check.
CHECKED=0
for CID in $(docker ps -q --filter ancestor="$IMG"); do
    NETS=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$CID" 2>/dev/null)
    [ -z "$NETS" ] && continue          # gone between ps and inspect, try the next
    CHECKED=$((CHECKED + 1))
    if [ "$(echo $NETS)" = "$NET" ]; then
        ok "$CID attached to $NET only"
    else
        bad "$CID has unexpected networks: $NETS"
    fi
done
[ "$CHECKED" -eq 0 ] && err "no guest container stayed up long enough to inspect"
[ "$(docker network inspect "$NET" -f '{{.Internal}}')" = "true" ] \
    && ok "network is --internal" || bad "network is not internal"

hdr "guest hardening (config.yaml host section actually took effect)"
# containerssh ignores unknown keys silently, so check the running container
CID=$(docker ps -q --filter ancestor="$IMG" | head -1)
if [ -z "$CID" ]; then
    err "guest hardening - no guest to inspect"
else
    HC=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.PidsLimit}} {{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' "$CID" 2>/dev/null)
    echo "  hostconfig: $HC"
    set -- $HC
    [ "$1" = "true" ]       && ok "root filesystem is read-only"     || bad "root filesystem is writable"
    [ "$2" = "256" ]        && ok "pids limit 256"                   || bad "pids limit is '$2'"
    [ "$3" = "1000000000" ] && ok "cpu capped at 1"                  || bad "nanocpus is '$3'"
    [ "$4" = "536870912" ]  && ok "memory 512 MiB"                   || bad "memory is '$4'"
    [ "$5" = "536870912" ]  && ok "no swap on top of memory"         || bad "memoryswap is '$5'"
    echo "$HC" | grep -q "ALL"               && ok "all capabilities dropped" || bad "capabilities not dropped"
    echo "$HC" | grep -q "no-new-privileges" && ok "no-new-privileges set"    || bad "no-new-privileges missing"
fi

hdr "policy from inside the guest"
if [ "$GUEST_UP" -ne 1 ]; then
    for p in "allowed endpoint 1337" "published endpoint 1338" "host port 22" \
             "host port 2222" "internet" "lan by ip" "dns" "icmp to gateway" \
             "disk fill"; do
        err "$p - no guest session"
    done
else
    PROBES=$(guest "
        nc -w 5 -z $GW 1337 > /dev/null 2>&1; echo ALLOWED=\$?
        nc -w 5 -z $GW 1338 > /dev/null 2>&1; echo PUBLISHED=\$?
        nc -w 5 -z $GW 22   > /dev/null 2>&1; echo SSH22=\$?
        nc -w 5 -z $GW 2222 > /dev/null 2>&1; echo CSSH=\$?
        curl -s -m 8 -o /dev/null https://example.com; echo NET=\$?
        nc -w 5 -z 1.1.1.1 443 > /dev/null 2>&1; echo IP=\$?
        timeout 8 getent hosts example.com > /dev/null 2>&1; echo DNS=\$?
        ping -c 1 -W 3 $GW > /dev/null 2>&1; echo ICMP=\$?
        dd if=/dev/zero of=/home/guestuser/fill bs=1M count=600 > /dev/null 2>&1; echo FILL=\$?; rm -f /home/guestuser/fill
        touch /usr/bin/x > /dev/null 2>&1; echo ROOTFS=\$?
        echo PROBES_DONE
    ")
    echo "$PROBES" | grep -q PROBES_DONE || echo "  (warning: probe script did not finish)"
    rc() { echo "$PROBES" | grep "^$1=" | cut -d= -f2; }
    check_blocked() {
        local v; v=$(rc "$2")
        if   [ -z "$v" ];   then err "$1 - probe did not report"
        elif [ "$v" = "0" ]; then bad "$1 - REACHABLE (policy not enforced)"
        else ok "$1"; fi
    }
    check_allowed() {
        local v; v=$(rc "$2")
        if   [ -z "$v" ];    then err "$1 - probe did not report"
        elif [ "$v" = "0" ]; then ok "$1 reachable"
        else bad "$1 NOT reachable (rc=$v) - allowlist too strict"; fi
    }
    check_allowed "allowed endpoint 1337" ALLOWED
    if [ -n "$ENDPOINT_CTR" ]; then
        check_allowed "published endpoint 1338 (via FORWARD)" PUBLISHED
    else
        err "published endpoint 1338 - endpoint container not running"
    fi

    check_blocked "host port 22 dropped"    SSH22
    check_blocked "host port 2222 dropped"  CSSH
    check_blocked "internet unreachable"    NET
    check_blocked "lan by ip unreachable"   IP
    # docker's embedded dns lives inside the guest's netns and forwards from the
    # host, so it is a covert channel the bridge rules never see. older engines
    # forward lookups from --internal networks; this has to fail.
    check_blocked "dns resolution fails"    DNS
    check_blocked "icmp to gateway dropped" ICMP
    # the home tmpfs is 256m: a 600m write must fail, and the image is read-only
    check_blocked "600m write to home refused (tmpfs bound)" FILL
    check_blocked "root filesystem read-only" ROOTFS
fi

hdr "guest to guest"
IPS=$(docker ps -q --filter ancestor="$IMG" \
      | xargs -r -I{} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} 2>/dev/null)
echo "  guest ips: $(echo $IPS)"
if [ "$GUEST_UP" -ne 1 ]; then
    err "guest-to-guest - no guest session"
elif [ "$(echo "$IPS" | grep -c .)" -lt 2 ]; then
    err "guest-to-guest - could not get two guests up"
else
    TARGET=$(echo "$IPS" | tail -1)
    # the other guest's link-local address, for the ipv6 leg. ip6tables FORWARD
    # only sees it when bridge-nf-call-ip6tables is on.
    TARGET_CID=$(docker ps -q --filter ancestor="$IMG" | tail -1)
    TARGET6=$(docker exec "$TARGET_CID" ip -6 -o addr show dev eth0 scope link 2>/dev/null \
              | awk '{print $4}' | cut -d/ -f1 | head -1)
    echo "  target: $TARGET  link-local: ${TARGET6:-none}"
    R=$(guest "
        nc -w 5 -z $TARGET 22 > /dev/null 2>&1; echo G2G=\$?
        ping -c 1 -W 3 $TARGET > /dev/null 2>&1; echo G2GP=\$?
        [ -n '$TARGET6' ] && { nc -6 -w 5 -z $TARGET6%eth0 22 > /dev/null 2>&1; echo G2G6=\$?; }
    ")
    V=$(echo "$R" | grep "^G2G=" | cut -d= -f2)
    P=$(echo "$R" | grep "^G2GP=" | cut -d= -f2)
    S=$(echo "$R" | grep "^G2G6=" | cut -d= -f2)
    if   [ -z "$V" ];    then err "guest-to-guest tcp - probe did not report"
    elif [ "$V" = "0" ]; then bad "guest reached another guest at $TARGET (tcp)"
    else ok "guest-to-guest tcp blocked ($TARGET)"; fi
    if   [ -z "$P" ];    then err "guest-to-guest icmp - probe did not report"
    elif [ "$P" = "0" ]; then bad "guest pinged another guest at $TARGET"
    else ok "guest-to-guest icmp blocked ($TARGET)"; fi
    if   [ -z "$TARGET6" ]; then echo "  (no link-local address on the target, ipv6 leg skipped: host has ipv6 off)"
    elif [ -z "$S" ];    then err "guest-to-guest ipv6 - probe did not report"
    elif [ "$S" = "0" ]; then bad "guest reached another guest over ipv6 link-local ($TARGET6)"
    else ok "guest-to-guest ipv6 link-local blocked"; fi
fi

echo
echo "=================================================="
echo " guest policy - passed: $PASS  failed: $FAIL  not tested: $ERR"
echo "=================================================="
[ "$FAIL" -eq 0 ] && [ "$ERR" -eq 0 ]
