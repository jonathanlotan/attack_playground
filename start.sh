#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/scripts/common.sh"

# the published ports, from .env. compose reads the same file, so what is waited
# for and printed below is what was actually published.
if ! load_ports; then
    exit 1
fi

# check the host can actually run the playground before creating anything. the
# guest restrictions are the whole point here, so a host that cannot apply them
# must not end up running guests - bail out before the host key, the image and
# the network exist rather than half way through.
if ! preflight; then
    echo "error: host is not ready to run the playground, refusing to start"
    exit 1
fi

# print starting
echo "starting playground..."

# ssh host key
if [ ! -f host.key ]; then
    echo "generating ssh host key..."
    ssh-keygen -t ed25519 -f ./host.key -N ""
    # keep the private host key owner-only. the containerssh service runs as root
    # (see docker-compose.yaml), so it can read it as is. if you switch that service
    # back to a non-root uid, grant that uid access explicitly rather than making the
    # key world readable - anyone who can read it can impersonate this ssh server.
    chmod 600 ./host.key
else
    echo "ssh host key already exists"
fi

# build the image for the guest docker
GUEST_DOCKER_IMAGE_NAME="attack_playground_image:latest"
if ! docker image inspect "$GUEST_DOCKER_IMAGE_NAME" &> /dev/null; then
    echo "building guest docker image \"$GUEST_DOCKER_IMAGE_NAME\"..."
    docker build -f guest_docker.dockerfile -t "$GUEST_DOCKER_IMAGE_NAME" .
else
    echo "guest docker image already exists"
fi

# stop any existing containers and remove the old network to avoid conflicts
# DOCKER_NET_NAME="attack_playground_net"
# echo "cleaning up existing containers and network..."
# docker compose down 2>/dev/null || true
# docker network rm "$DOCKER_NET_NAME" 2>/dev/null || true
DOCKER_NET_NAME="attack_playground_net"
if ! docker network inspect "$DOCKER_NET_NAME" &> /dev/null; then
    echo "creating internal docker network \"$DOCKER_NET_NAME\"..."
    docker network create --internal --driver bridge "$DOCKER_NET_NAME"
else
    echo "docker network \"$DOCKER_NET_NAME\" already exists"
fi

# apply network restrictions for the docker network.
#
# this runs *before* the services come up on purpose: containerssh starts accepting
# ssh connections - and spawning guests on this network - the moment it is running,
# so applying the restrictions afterwards leaves a window in which a guest is live
# and unrestricted. the bridge exists as soon as the network is created, which is all
# the setup script needs.
#
# SSH_PORT is passed explicitly: sudo resets the environment, and the ssh
# connection cap is keyed on that port.
echo "applying network restrictions for the docker network..."
if ! as_root env PYTHONPATH="$SCRIPT_DIR/scripts" SSH_PORT="$SSH_PORT" python3 "$SCRIPT_DIR/scripts/setup_networking_linux.py"; then
    echo "error: failed to apply network restrictions, refusing to start the playground"
    exit 1
fi

# render the containerssh config for this run.
#
# guests resolve "researchlabs.tech" to the gateway of the network created above
# through an /etc/hosts entry containerssh asks docker for, and docker only numbers
# that network when it creates it - so the address cannot live in the tracked
# config.yaml. this fills it in; compose mounts the rendered copy.
#
# it runs after the network exists and before the services come up: containerssh
# reads its config once, at startup.
echo "rendering containerssh config..."
if ! env PYTHONPATH="$SCRIPT_DIR/scripts" python3 "$SCRIPT_DIR/scripts/render_config.py"; then
    echo "error: failed to render the containerssh config, refusing to start the playground"
    exit 1
fi

# launch services
echo "launching services..."
compose up -d

# "compose up -d" only means the containers were created. wait until containerssh
# is actually accepting ssh, so a service that came up and died immediately is a
# loud failure rather than a playground that is advertised as running with nothing
# listening on it.
#
# containerssh is held back until the auth webhook is healthy (see depends_on in
# docker-compose.yaml), and that webhook is stdlib python with nothing to install,
# so this is a timeout for diagnosing a failure rather than an expected wait.
echo "waiting for containerssh to accept connections..."
if ! wait_for_tcp 127.0.0.1 "$SSH_PORT" 90; then
    echo "error: containerssh is not accepting connections on port $SSH_PORT."
    echo "       the containers were created but the playground is not usable."
    echo "--- containerssh logs ---"
    compose logs --tail 20 containerssh 2>&1 | tail -20
    exit 1
fi

# print running
echo "playground is running"

# print connection info.
# "ip route get 1" prints "... dev <if> src <ip> uid <n>" for an on-link default route
# and "... via <gw> dev <if> src <ip> uid <n>" otherwise, so pick the field after
# "src" rather than a fixed column - $7 lands on the uid value for the on-link form.
HOST_IP=$(ip route get 1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')
if [ -z "$HOST_IP" ]; then
    HOST_IP="localhost"
fi
echo "connect with ssh, target: $HOST_IP, port: $SSH_PORT, user: anyuser, password: <anything> (e.g. ssh -p $SSH_PORT anyuser@$HOST_IP)"
echo "connection statistics: curl http://127.0.0.1:$STATS_PORT/stats (loopback only, see stats_server.py)"
