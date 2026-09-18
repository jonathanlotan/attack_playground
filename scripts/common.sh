#!/bin/bash
#
# shared helpers for the playground lifecycle scripts (start/stop/restart/cleanup).
# meant to be sourced, not executed:
#
#     source "$SCRIPT_DIR/scripts/common.sh"
#
# everything here exists because the playground is deployed on a plain linux host
# rather than on the machine it is developed on. the failure modes below are all
# ones that otherwise surface half way through start.sh - after the host key and the
# guest image have already been created - as an opaque error from docker or python.

# ------------------------------------------------------------- where things are
#
# the directory this file lives in, without calling dirname: the tests source
# this file with a PATH that holds only stubs.
COMMON_DIR="${BASH_SOURCE[0]%/*}"
[ "$COMMON_DIR" = "${BASH_SOURCE[0]}" ] && COMMON_DIR="."

# -------------------------------------------------------------- published ports
#
# the host ports the playground publishes - ssh, the auth webhook, the stats
# server - are set once, in .env at the repo root. docker compose reads that file
# by itself and substitutes the values into docker-compose.yaml; load_ports reads
# the same file for the scripts, exported, so the compose runs from here see the
# identical numbers and start.sh can hand SSH_PORT to the networking script it
# runs under as_root. a port literal anywhere else is a bug.
#
# a variable rather than a literal path so the tests can point it at a file of
# their own.
PLAYGROUND_ENV="${PLAYGROUND_ENV:-$COMMON_DIR/../.env}"
PORT_VARS=(SSH_PORT AUTH_PORT STATS_PORT)

load_ports() {
    if [ ! -f "$PLAYGROUND_ENV" ]; then
        echo "error: $PLAYGROUND_ENV not found. it sets the published ports" >&2
        echo "       (${PORT_VARS[*]}) that docker-compose.yaml and the scripts share." >&2
        return 1
    fi
    set -a
    # shellcheck source=/dev/null
    . "$PLAYGROUND_ENV"
    set +a

    local name value
    for name in "${PORT_VARS[@]}"; do
        value="${!name}"
        case "$value" in
            '' | *[!0-9]*)
                echo "error: $name is not a port number in $PLAYGROUND_ENV: '$value'" >&2
                return 1 ;;
        esac
        if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
            echo "error: $name is out of range in $PLAYGROUND_ENV: $value" >&2
            return 1
        fi
    done
}

# ---------------------------------------------------------------- stats server
#
# GET a path on the stats server (stats_server.py, published on STATS_PORT) and
# print the named json fields, space separated; "collector.connected" walks into
# the nested object. empty output means it did not answer. python rather than
# curl, which is not a host requirement.
stats_fields() {
    local path="$1"
    shift
    python3 - "http://127.0.0.1:$STATS_PORT$path" "$@" <<'PY' 2>/dev/null
import json, sys, urllib.request
with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
    stats = json.load(response)
def field(key):
    value = stats
    for part in key.split("."):
        value = value[part]
    return value
print(*(field(key) for key in sys.argv[2:]))
PY
}

# ---------------------------------------------------------------- running as root
#
# the iptables scripts need root. two host layouts have to work:
#
#   * an unprivileged user with sudo (the common case, "./start.sh")
#   * root with no sudo installed at all (minimal debian images, cloud-init, a
#     root shell over ssh). "sudo python3 ..." is not a no-op there, it is a
#     "command not found" that kills the script.
#
# as_root runs its arguments with the smallest thing that works.
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo > /dev/null 2>&1; then
        sudo "$@"
    else
        echo "error: need root to run '$1' but this is not root and sudo is not installed" >&2
        return 1
    fi
}

# ------------------------------------------------------------------ docker compose
#
# compose v2 is a docker cli plugin ("docker compose"); the standalone v1 script
# ("docker-compose") is what you get from the distro packages on debian/ubuntu when
# docker.io is installed instead of docker-ce. resolve once and reuse.
COMPOSE_CMD=()

resolve_compose() {
    if [ ${#COMPOSE_CMD[@]} -gt 0 ]; then
        return 0
    fi
    if docker compose version > /dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)
    elif command -v docker-compose > /dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)
    else
        return 1
    fi
    return 0
}

compose() {
    if ! resolve_compose; then
        echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
        return 1
    fi
    "${COMPOSE_CMD[@]}" "$@"
}

# ------------------------------------------------------------------------- binfmt
#
# where the kernel registers the qemu-user handler for amd64 binaries. a variable
# rather than a literal so the preflight's two architecture branches can both be
# exercised by the tests.
BINFMT_AMD64="${BINFMT_AMD64:-/proc/sys/fs/binfmt_misc/qemu-x86_64}"

# ----------------------------------------------------------------------- preflight
#
# check everything the playground needs *before* doing any work. the network
# restrictions are the whole point of this playground, so a host that cannot apply
# them must not end up running guests: start.sh refuses rather than degrading.
preflight() {
    local failed=0

    # linux only. the restrictions are iptables chains on a docker bridge; neither
    # exists on macos (docker desktop runs the daemon inside its own vm, so the
    # chains would be applied to the wrong kernel - or to none at all) or on
    # windows. fail here rather than letting setup_networking_linux.py report a
    # missing network and leave the operator guessing.
    local kernel
    kernel="$(uname -s)"
    if [ "$kernel" != "Linux" ]; then
        echo "error: this playground only runs on linux (detected: $kernel)." >&2
        echo "       the guest restrictions are iptables chains on the host kernel's" >&2
        echo "       docker bridge, which a docker desktop vm does not give access to." >&2
        return 1
    fi

    # the playground needs an x86-64 host. this is not a preference: the
    # containerssh/containerssh image is published for linux/amd64 only, so on any
    # other architecture docker pulls the amd64 image anyway and the container dies
    # in a restart loop with "exec /containerssh: exec format error" - while
    # "docker compose up -d" still exits 0 and everything looks fine.
    local arch
    arch="$(uname -m)"
    if [ "$arch" != "x86_64" ]; then
        if [ -e "$BINFMT_AMD64" ]; then
            echo "note: host is $arch. containerssh is published for linux/amd64 only and"
            echo "      will run here under binfmt/qemu emulation, slowly."
        else
            echo "error: host architecture is $arch, but containerssh/containerssh is" >&2
            echo "       published for linux/amd64 only - it exits with 'exec format error'" >&2
            echo "       on this host. use an x86-64 host, or register the qemu-user binfmt" >&2
            echo "       handlers first:" >&2
            echo "       docker run --privileged --rm tonistiigi/binfmt --install amd64" >&2
            failed=1
        fi
    fi

    if ! command -v docker > /dev/null 2>&1; then
        echo "error: docker is not installed. on ubuntu/debian:" >&2
        echo "       curl -fsSL https://get.docker.com | sh" >&2
        failed=1
    elif ! docker info > /dev/null 2>&1; then
        # either the daemon is down or this user cannot reach the socket. those need
        # different fixes, so tell them apart instead of printing a generic error.
        if as_root docker info > /dev/null 2>&1; then
            echo "error: cannot reach the docker daemon as '$(id -un)', but root can." >&2
            echo "       add yourself to the docker group and log back in:" >&2
            echo "       sudo usermod -aG docker $(id -un) && newgrp docker" >&2
        else
            echo "error: the docker daemon is not reachable. is it running?" >&2
            echo "       sudo systemctl start docker" >&2
        fi
        failed=1
    fi

    if ! resolve_compose; then
        echo "error: docker compose is not available. on ubuntu/debian:" >&2
        echo "       sudo apt-get install -y docker-compose-plugin" >&2
        failed=1
    fi

    # start.sh generates the ssh host key on first run. openssh-client is not a
    # given on a minimal image, and without this check the failure lands after
    # the preflight has already said the host is fine.
    if ! command -v ssh-keygen > /dev/null 2>&1; then
        echo "error: ssh-keygen is not installed (needed to create the ssh host key). on ubuntu/debian:" >&2
        echo "       sudo apt-get install -y openssh-client" >&2
        failed=1
    fi

    if ! command -v python3 > /dev/null 2>&1; then
        echo "error: python3 is not installed (needed by the networking scripts). on ubuntu/debian:" >&2
        echo "       sudo apt-get install -y python3" >&2
        failed=1
    fi

    # iptables comes in as a docker-ce dependency on most hosts, but not on every
    # one - and without it there are no restrictions at all.
    if ! command -v iptables > /dev/null 2>&1 && ! as_root test -x /usr/sbin/iptables 2> /dev/null; then
        echo "error: iptables is not installed (needed to restrict the guest network). on ubuntu/debian:" >&2
        echo "       sudo apt-get install -y iptables" >&2
        failed=1
    fi

    if [ "$(id -u)" -ne 0 ] && ! command -v sudo > /dev/null 2>&1; then
        echo "error: not running as root and sudo is not installed; the network" >&2
        echo "       restrictions cannot be applied. run as root or install sudo." >&2
        failed=1
    fi

    # docker 29 can be configured to program nftables directly instead of iptables.
    # in that mode docker maintains no DOCKER-USER chain at all, so the forward
    # drops end up hanging off a chain this script creates itself rather than off
    # docker's. the kernel still evaluates them - a DROP is a DROP whichever table
    # it lives in - but the ordering against docker's own rules is no longer
    # something we control, so say so out loud.
    if docker info 2> /dev/null | grep -qi 'firewall.*backend.*nftables'; then
        echo "warning: the docker daemon is using the nftables firewall backend."
        echo "         docker maintains no DOCKER-USER chain in that mode; the guest"
        echo "         forward drops still apply, but verify them by hand after start."
    fi

    return $failed
}

# ------------------------------------------------------------- service readiness
#
# "docker compose up -d" exits 0 once the containers are *created*, which says
# nothing about whether they stayed up. a containerssh that crash-loops (wrong
# image architecture, bad config, unreadable host key) otherwise leaves start.sh
# cheerfully printing "playground is running" while nothing is listening.
#
# bash's /dev/tcp keeps this dependency free - no nc, no ss.
wait_for_tcp() {
    local host="$1" port="$2" timeout="${3:-60}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if (exec 3<>"/dev/tcp/$host/$port") 2> /dev/null; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}
