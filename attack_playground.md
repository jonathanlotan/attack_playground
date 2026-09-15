# attack playground
## overview

## repo structure

## running the playground
`start.sh`: start the playground
`stop.sh`: stop the playground
`restart.sh`: restart the playground
`cleanup.sh`: stop and cleanup the playground

`attack_network_endpoints.conf`: configuration file containing all the exposed attack network endpoints within the playground

`scripts/common.sh`: shared helpers for the lifecycle scripts - the host preflight,
`as_root`, and compose resolution

`systemd/attack-playground.service`: brings the playground up at boot *through*
`start.sh` - see *surviving a reboot* below

## host requirements

the playground runs **on linux x86-64 only**. the guest
restrictions are iptables chains on the host kernel's docker bridge, so the daemon has
to be the host's own: on macos and windows docker runs inside its own vm and the chains
would be applied to the wrong kernel, or to none at all. `start.sh` checks `uname` and
refuses to start rather than bringing guests up unrestricted.

on a fresh ubuntu/debian x64 host:

| need                  | notes                                                              |
| --------------------- | ------------------------------------------------------------------ |
| docker engine         | `curl -fsSL https://get.docker.com \| sh`                            |
| docker compose        | v2 plugin (`docker-compose-plugin`); the standalone v1 `docker-compose` also works |
| python3               | stdlib only, no pip packages                                       |
| ssh-keygen            | `openssh-client`; `start.sh` generates the ssh host key with it   |
| iptables              | normally pulled in by docker-ce, but not on every host             |
| root                  | either run as root, or as a user with sudo                         |
| docker socket access  | `sudo usermod -aG docker $USER && newgrp docker`, or run as root    |
| x86-64                | required - see below                                               |

`start.sh` verifies all of the above **before** it creates the host key, the guest image
or the network, and prints the fix for whatever is missing. running as root on a minimal
image with no sudo installed is supported - `as_root` in `scripts/common.sh` only reaches
for sudo when it is not already root.

### pinned images

`containerssh/containerssh`, `containerssh/agent`, `python` and `ubuntu` are pinned to
exact tags. containerssh ignores config keys it does not recognise rather than rejecting
them, so a schema change arriving through `latest` would not fail loudly - it would
silently drop `networkmode` and put the guests on the default bridge. bump the tags on
purpose and run `./verify.sh` afterwards.

### why x86-64 specifically

this is not a preference. `containerssh/containerssh` is published for **linux/amd64
only**. on any other architecture docker pulls the amd64 image anyway and the container
restart-loops on

```
exec /containerssh: exec format error
```

while `docker compose up -d` still exits 0 - so without a check the playground reports
itself as running with nothing listening on port 2222. verified on an aarch64 ubuntu
24.04 host. the preflight fails on a non-x86-64 host unless the qemu-user binfmt
handlers are registered (`docker run --privileged --rm tonistiigi/binfmt --install
amd64`), in which case it says the emulation is in use and carries on.

guest containers themselves are built from `guest_docker.dockerfile` for the host's
architecture, so on an x86-64 host they are x86-64 and prebuilt x86-64 tooling runs in
them.

### surviving a reboot

the iptables chains live in the kernel and are gone after a reboot (and after a
`ufw`/`firewalld` reload, which flushes the filter table). the compose services are
therefore `restart: "no"` on purpose: a containerssh that docker brought back on its
own would accept logins onto a network with no restrictions at all. docker's own
`--internal` isolation would still hold, but every host port and every other guest
would be reachable.

to have the playground come back after a reboot, install the systemd unit, which
runs `start.sh` after `docker.service` so the chains are applied before containerssh
is started:

```
sudo cp systemd/attack-playground.service /etc/systemd/system/   # fix WorkingDirectory first
sudo systemctl daemon-reload
sudo systemctl enable --now attack-playground
```

after a firewall reload, `sudo systemctl restart attack-playground` (or `./restart.sh`).

the rules are deliberately **not** saved with `netfilter-persistent`: that would also
freeze docker's own nat and filter rules into a file that gets restored before dockerd
starts on the next boot, which is a well known way to end up with duplicated and stale
docker rules. `verify.sh` fails if it finds `ATTACK_PG` chains in `/etc/iptables/rules.v4`.

### start is not "containers created"

`docker compose up -d` exits 0 once the containers exist, which says nothing about
whether they stayed up. `start.sh` therefore waits for containerssh to actually accept
tcp on 2222 before printing `playground is running`, and dumps the container logs and
exits non-zero if it never does. a crash-looping service - wrong image architecture, bad
config, an unreadable host key - is a loud failure rather than a playground that is
advertised as working.

### docker's firewall backend

docker 29 can be told to program nftables directly (`"firewall-backend": "nftables"`),
and in that mode it maintains **no `DOCKER-USER` chain at all**. the forward drops then
hang off a `DOCKER-USER` chain that `setup_networking_linux.py` creates and hooks into
`FORWARD` itself. the kernel still evaluates them - a `DROP` is a `DROP` whichever table
it lives in - but their ordering against docker's own rules is no longer ours to control,
so the preflight warns and the rules should be verified by hand (see *verifying* below).
the default iptables backend needs none of this.

### the auth webhook

`containerssh-auth` authenticates *anybody* as whatever username they ask for - that is
the point of a playground, but it means the port must not be reachable from the lan. it
is published on `127.0.0.1:2223` only. note that a docker published port is DNATed in the
`nat` table before ufw or firewalld ever sees it, so binding it to `0.0.0.0` would expose
it regardless of the host firewall. containerssh itself reaches the webhook by service
name on `containerssh_net` and does not need the published port at all.

`auth_server.py` is stdlib only (`http.server`). it used to be a flask app whose
container ran `pip install flask` on every start, which meant the auth service needed
working network access each time it booted, and that containerssh - which is held back
until the webhook is healthy - could not start until that install finished. the webhook
now serves within a second of the container being created and works with no network at
all.

it answers `POST /auth/password` and `POST /auth/pubkey` with
`{"success": true, "authenticatedUsername": "<whatever was asked for>"}`. a missing or
malformed body - or a `username` that is not a string - falls back to `guestuser` rather
than failing: this webhook says yes to everyone by design, and a rejected login reads as
a broken playground.

## what a guest can cost the host

a guest is an untrusted shell anyone on the lan can open, so the `host` section of
`config.yaml` bounds it: a read-only root filesystem with bounded in-memory tmpfs
mounts for `/home/guestuser`, `/tmp` and `/var/tmp` (so a `dd if=/dev/zero` cannot
fill docker's data directory and take the daemon down), 512 MiB of memory with no
swap on top, 256 pids, one cpu, no capabilities, and `no-new-privileges`. the names
are docker's `HostConfig` fields in lowercase, like `networkmode` - see the note on
casing in that file. `verify_guest.sh` inspects a running guest and checks that every
one of them actually took effect, because containerssh ignores a mistyped key silently.

the number of guests is capped as well. containerssh has no limit of its own and the
webhook accepts everyone, so `setup_networking_linux.py` installs an `ATTACK_PG_SSH`
chain hooked from `INPUT` for new connections to port 2222 with a `connlimit` of 32
concurrent connections over all sources (`MAX_SSH_CONNECTIONS` in
`network_common_linux.py`). a kernel without `xt_connlimit` gets a warning rather than
a refusal to start: this is a limit, not a restriction. what is *not* capped is how
long a session may stay open; if that matters, reap old guest containers from a timer.

## network restrictions

**policy: a guest may open connections to the host on the tcp ports listed in
`attack_network_endpoints.conf`, and to nothing else.** no internet, no other host on
the lan, no other docker network, and no other guest.

guest containers are attached to `attack_playground_net`, an `--internal` docker bridge
network. the attachment is configured in `config.yaml` under `docker.execution.host.networkmode`.

> the keys under `docker.execution.container` map to docker's `container.Config` and the
> keys under `docker.execution.host` map to docker's `container.HostConfig`. those docker
> structs have no yaml tags, so containerssh matches them by the **all-lowercase** go field
> name (`networkmode`, not `networkMode`). containerssh **silently ignores** keys it does
> not recognise, so a misplaced or mis-cased key is a no-op and the guest quietly falls
> back to the default bridge with full internet access. double check this section after
> editing it.

`--internal` stops docker from routing the guests out to the internet, but it is not
enough on its own. it still leaves the host reachable on the bridge gateway ip - which is
where the attack endpoints are exposed - and it still lets guests on the same bridge reach
each other. `scripts/setup_networking_linux.py` therefore installs three iptables chains:

| chain              | hooked from   | matches       | effect                                                                 |
| ------------------ | ------------- | ------------- | ---------------------------------------------------------------------- |
| `ATTACK_PG_INPUT`  | `INPUT`       | `-i <bridge>` | guest -> host: only the tcp ports in `attack_network_endpoints.conf` (on the gateway ip) are accepted, everything else is dropped |
| `ATTACK_PG_FWD`    | `DOCKER-USER` | `-i <bridge>` | guest -> forwarded: dropped, except connections whose *original* destination was an allowed port on the gateway (a docker-published endpoint, see below). covers guest-to-guest, guest -> other docker network and guest -> lan |
| `ATTACK_PG_FWD_IN` | `DOCKER-USER` | `-o <bridge>` | forwarded -> guest: dropped, except replies to connections a guest opened, so no other host can reach a guest |
| `ATTACK_PG_SSH`    | `INPUT`       | `-p tcp --dport 2222 --syn` | lan -> containerssh: drops new connections above the concurrency cap |

the split matters: `DOCKER-USER` is only consulted for **forwarded** packets, while traffic
aimed at the gateway ip is delivered locally and hits **`INPUT`**. an endpoint allowlist
placed in `DOCKER-USER` can never match, which leaves the host fully reachable from a guest.

the host itself is not affected by the two forward chains - host-originated traffic is
routed through `OUTPUT`, not `FORWARD` - so the host can still reach the guests normally.

### endpoints that are docker containers

an attack endpoint that is itself a container with a published port (`-p 1338:80`) is a
different code path. docker DNATs a published port in the `nat` table **before routing**,
so a guest packet to `<gateway>:1338` arrives in `FORWARD` addressed to the endpoint
container's ip - it never reaches `INPUT`, and an allowlist that only lived there would
let host processes through and drop every containerised endpoint. `ATTACK_PG_FWD`
therefore also accepts connections whose original destination (`conntrack --ctorigdst
<gateway> --ctorigdstport <range>`) was an allowed port, and `ATTACK_PG_FWD_IN` accepts
`ESTABLISHED,RELATED` so the replies get back to the guest. a guest can only ever open
connections the two allowlists permit, so neither rule widens the policy. the accept is
evaluated from `DOCKER-USER`, which docker puts first in `FORWARD`, so it wins over
docker's own isolation rules for the `--internal` network - which is what `DOCKER-USER`
is for. `verify_guest.sh` starts a published endpoint on 1338 and proves the path.

the restrictions are applied **before** `docker compose up`, not after: containerssh starts
accepting ssh connections - and spawning guests on this network - the moment it is running,
so applying them afterwards leaves a window in which a guest is live and unrestricted. if
setup fails, `start.sh` refuses to launch the services at all.

### fail-closed chains

each chain is rebuilt **deny-first**: it is flushed, given its terminal `DROP`, and only
then are the allow rules *inserted above* that drop. the chain therefore denies by default
at every instant - during the rebuild window, and after a rebuild that failed part way
through.

this matters because the allow rules come from a config file. a port like `70000` or a
range like `1337-99999` is rejected by iptables, and building the chain the other way round
(allows first, `DROP` last) meant a single bad entry left a **live hook pointing at a chain
with no `DROP`** - every guest packet then fell straight through to the `ACCEPT` policy of
`INPUT`, i.e. the whole host. ports are now range checked before they reach iptables, and
the deny-first construction means even an unforeseen iptables rejection fails closed.

### ipv6

`iptables` only covers ipv4. the playground network is ipv4-only, but as long as the host
kernel has ipv6 enabled the guest's `eth0` and the host side of the bridge both still get
link-local (`fe80::/64`) addresses, so a guest could reach any host port over ipv6 and walk
straight past the ipv4 allowlist. every configured endpoint is a tcp port on the ipv4
gateway, so there is nothing to allow over ipv6: the same three chain names are created in
`ip6tables` and drop everything on the bridge.

docker only maintains `DOCKER-USER` in `ip6tables` when its ip6tables support is turned on,
so the ipv6 forward chains hook straight into `FORWARD` instead of relying on it. a missing
`ip6tables` is a warning, not a failure - the ipv4 policy still applies.

### bridge netfilter

guest-to-guest traffic on one bridge only traverses `FORWARD` when `br_netfilter` is loaded
and `net.bridge.bridge-nf-call-iptables` is `1`. if it is not, the guest-to-guest drop is
**silently a no-op**. the same holds for `net.bridge.bridge-nf-call-ip6tables` and the ipv6
mirror: docker only turns that one on for an ipv6-enabled network, and the playground
network is ipv4-only, so without it two guests could still talk over their link-local
addresses. setup loads the module and sets both sysctls, and prints a warning for any it
cannot. teardown deliberately leaves them alone, since docker relies on them.

### hooks are verified, not assumed

a chain nothing jumps to is silently dead. two places this bites:

* `DOCKER-USER` is normally created *and* hooked into `FORWARD` by docker. if docker has not
  done that yet (daemon just started, iptables flushed), merely creating the chain leaves it
  at 0 references and both forward drops become a no-op while setup reports success. setup
  now checks that `FORWARD` really reaches `DOCKER-USER` and fails loudly if it cannot.
* teardown finds our hooks by scanning the parent chains for jumps to our chains, rather
  than by rebuilding the `-i <bridge>` rule. by teardown time the docker network - and with
  it the bridge name - is often already gone, and a hook that cannot be named cannot be
  deleted: the chain would just get flushed and left behind, referenced and live, with no
  later run able to find it. `stop.sh` runs teardown unconditionally for the same reason.

both scripts are idempotent - `setup` rebuilds the chains from scratch on every run and
also clears the flat `DOCKER-USER` rules written by earlier versions.

### verifying

`./verify.sh` runs the host checks below and reports pass/fail: the unit tests,
`start.sh`, every chain and its terminal `DROP`, the hooks, the forward allow for
published endpoints, the ssh cap, the ipv6 mirror, both sysctls, the loopback binding,
the restart policy and that nothing was persisted to `/etc/iptables`. `./verify_guest.sh`
then proves the policy from inside real guest containers: the host and published
endpoints are reachable, everything else (other host ports, the internet, the lan, dns,
icmp, the other guest over ipv4 and ipv6 link-local) is not, and the guest hardening
took effect. its test listener is bound to the gateway ip and serves an empty
directory - the repo contains the ssh host private key, so it must never be what gets
served. both need `sshpass` and `netcat-openbsd` on the host, and a playground that is
not already running. a probe that could not run is reported as "not tested" rather
than as a pass.

to check by hand instead, after `./start.sh`, check the rules on the host:

```
sudo iptables -n -L ATTACK_PG_INPUT          # must end in DROP
sudo iptables -n -L ATTACK_PG_FWD            # DNAT allow for published endpoints, then DROP
sudo iptables -n -L ATTACK_PG_FWD_IN         # ESTABLISHED allow, then DROP
sudo iptables -n -L ATTACK_PG_SSH            # connlimit DROP
sudo iptables -n -L DOCKER-USER              # must NOT say "(0 references)"
sudo ip6tables -n -L ATTACK_PG_INPUT         # ipv6 mirror, drops everything
sysctl net.bridge.bridge-nf-call-iptables    # must be 1
sysctl net.bridge.bridge-nf-call-ip6tables   # must be 1
```

then ssh in and confirm the guest is actually restricted:

```
docker inspect -f '{{json .NetworkSettings.Networks}}' <guest-container>   # attack_playground_net only
nc -vz <gateway-ip> 1337        # allowed endpoint, must succeed
nc -vz <gateway-ip> 22          # must fail
nc -6 -vz <host-link-local>%eth0 22   # must fail
curl -m 5 https://example.com   # must fail
getent hosts example.com        # must fail - docker's embedded dns must not forward
nc -vz <other-guest-ip> <port>  # must fail
nc -6 -vz <other-guest-link-local>%eth0 <port>  # must fail
```

note that icmp to the gateway is dropped as well, so `ping <gateway-ip>` failing is expected.

### tests

the config parsing, the fail-closed chain construction, the forward allow for published
endpoints, the ssh cap and the webhook contract have unit tests. they are stdlib only
and need neither root nor docker:

```
python3 -m unittest discover -s scripts -p 'test_*.py'
```

the shell helpers in `scripts/common.sh` are covered too - those tests stub every
external command on `PATH`, so they behave the same on a developer laptop as on
the deployment host.
