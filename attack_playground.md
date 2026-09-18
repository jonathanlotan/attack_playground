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

`config.yaml`: the containerssh config - the guest image, the restricted network and the
limits a guest runs under. it carries a placeholder for the docker network's gateway ip;
`start.sh` renders it into `config.runtime.yaml` (generated, gitignored) with
`scripts/render_config.py`, and containerssh mounts *that* - see *researchlabs.tech* below

`systemd/attack-playground.service`: brings the playground up at boot *through*
`start.sh` - see *surviving a reboot* below

`stats_server.py`: how many users are connected now, were in the last hour, and
ever - the `playground-stats` service in `docker-compose.yaml`, see *connection
statistics* below

`.env`: the host ports the playground publishes - ssh (`SSH_PORT`), the auth webhook
(`AUTH_PORT`) and the stats server (`STATS_PORT`) - set once, here. see *one place
for every port* below

`guest_docker.dockerfile`: the guest image - ubuntu with the usual tooling (gcc, python,
git, curl, wget, netcat, ping, nslookup and dig). `start.sh` only builds it when it is
missing, so after editing it run `./cleanup.sh` and then `./start.sh` (or
`docker rmi attack_playground_image:latest`) to have the change picked up.

### one place for every port

the ports fall in two groups, and neither is written down twice:

  * **the published host ports** - ssh, the auth webhook, the stats server - are set
    in `.env`. docker compose reads that file on its own and substitutes the values
    into `docker-compose.yaml` (as `${SSH_PORT:?...}`, so a missing value is a loud
    failure and not a silently different port). `scripts/common.sh` loads the same
    file (`load_ports`) for `start.sh` and the verify scripts, and `start.sh` hands
    `SSH_PORT` to `setup_networking_linux.py`, which keys the ssh connection cap on
    it and refuses to run without it - a cap on the wrong port would be no cap at
    all. the container-side ports (2222 inside containerssh, 8080 and 8081 inside
    the webhook and stats containers) are not published and stay in the compose file.
  * **the attack endpoints** are set in `attack_network_endpoints.conf`. the iptables
    chains are built from it, and so are the verify scripts' expectations:
    `scripts/endpoints.py` prints the configured ranges and the first allowed ports
    through the same parser, so `verify.sh` checks every configured range and
    `verify_guest.sh` puts its host listener on the first allowed port and its
    published container on the second.

the numbers in this document - 2222, 2223, 2224, 1337, 1338 - are the shipped values.


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
tcp on the ssh port before printing `playground is running`, and dumps the container logs and
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
is published on `127.0.0.1` only, on `AUTH_PORT` from `.env` (2223 as shipped). note that a docker published port is DNATed in the
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
chain hooked from `INPUT` for new connections to the ssh port (`SSH_PORT` in `.env`,
handed to the script by `start.sh`) with a `connlimit` of 32 concurrent connections
over all sources (`MAX_SSH_CONNECTIONS` in `network_common_linux.py`). a kernel without `xt_connlimit` gets a warning rather than
a refusal to start: this is a limit, not a restriction. what is *not* capped is how
long a session may stay open; if that matters, reap old guest containers from a timer.

## connection statistics

`stats_server.py` answers, as json on `http://127.0.0.1:2224/stats` (`STATS_PORT` in
`.env`), how many users are connected right now, how many were connected at some point during the last
hour, and how many have ever connected:

```
$ curl -s http://127.0.0.1:2224/stats
{"currently_connected": 2, "connected_in_window": 5, "window_seconds": 3600,
 "ever_connected": 123, "generated_at": "2026-09-18T14:03:21Z",
 "collector": {"connected": true, "reconciled_at": "2026-09-18T09:12:40Z",
               "last_event_at": "2026-09-18T14:01:07Z"}}
```

`?window=` picks another window - seconds (`?window=900`) or a count with a unit
(`15m`, `2h`, `7d`) - and `STATS_WINDOW` in `docker-compose.yaml` sets the one used
when a request names none. a window that does not parse, or is zero, is a 400.
`start.sh` prints the url once the playground is up.

### what is counted

a **user is one ssh session**. the auth webhook says yes to anybody under any
name, so a username identifies nobody, and a client address may be one person or a
whole nat - sessions are the only thing the playground can count honestly.
containerssh turns every ssh connection into exactly one guest container, so the
server follows docker's event stream: a guest container starting is a user
connecting, and that container dying is the user leaving. the username and client
address containerssh puts on each guest as labels (`containerssh_username`,
`containerssh_ip`) are stored with the session, for anyone who wants to slice the
numbers differently later. containers from any other image - containerssh itself,
the webhook, a published endpoint - are not users.

*connected in the window* counts every session that was open at any moment of it:
the ones still open, and the ones that ended inside it. the three numbers therefore
nest: `currently_connected <= connected_in_window <= ever_connected`.

### where the numbers live

sessions are rows in `stats_data/stats.db`, a sqlite file bind-mounted into the
service, so *ever connected* survives restarts of the server and of the playground.
`cleanup.sh` leaves it alone; `rm -rf stats_data` starts the count over. the file is
root-owned - the service runs as root, like containerssh - and
`sudo sqlite3 stats_data/stats.db 'select * from sessions'` lists every session with
its start, end, username and client address.

on startup, and again whenever the docker event stream has to be reopened, the
store is reconciled against the guests actually running: guests that appeared while
the server was down are added, and sessions still open whose guest is gone are
closed at that moment and marked `reconcile`, because their real end was not seen.
a session that both started and ended while the server was down is not recorded.
`stop.sh` therefore stops containerssh alone before sweeping the guests, and keeps
the other services - this one included - up until `compose down`, so a normal stop
records every session's end exactly.

`collector.connected` in the response says whether the event stream is being
followed right now. `false` means docker is unreachable: the numbers are as of
`reconciled_at` and `last_event_at`, the server keeps serving what it knows, and it
retries every few seconds.

### what it can reach

the service has the docker socket, which is root on the host. it only ever sends
`GET` requests over it (list the running guests, follow events), and it is stdlib
only, so nothing is installed at start and it needs no network access to come up.
the socket is mounted `:ro` to say so, but that makes the socket *file* unwritable,
not the api behind it. the port is published on loopback only, like the auth
webhook - from another machine, tunnel it (`ssh -L 2224:127.0.0.1:2224 <host>`).
the service sits on `containerssh_net`, which no guest can reach, and the stats
port is not in the endpoint allowlist either.

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
| `ATTACK_PG_SSH`    | `INPUT`       | `-p tcp --dport <ssh port> --syn` | lan -> containerssh: drops new connections above the concurrency cap |

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
is for. `verify_guest.sh` starts a published endpoint on the second allowed port (1338
as shipped) and proves the path.

the restrictions are applied **before** `docker compose up`, not after: containerssh starts
accepting ssh connections - and spawning guests on this network - the moment it is running,
so applying them afterwards leaves a window in which a guest is live and unrestricted. if
setup fails, `start.sh` refuses to launch the services at all.

### a published port shadows the host endpoint behind it

the DNAT above is keyed on the **port**, not on who is supposed to own it. docker's rule
in `nat/DOCKER` is `! -i <its own bridge> -p tcp --dport <port> -j DNAT`, and `PREROUTING`
runs before the routing decision - so if any container publishes a host port that falls
inside one of the configured endpoint ranges, a guest dialling `<gateway>:<that port>` is
rewritten to the container and forwarded. it never reaches `INPUT`, and `ATTACK_PG_INPUT`
never sees it. a host process listening on the same port of the gateway keeps its socket
and silently stops receiving guest connections.

the policy is not widened by this - the `ATTACK_PG_FWD` accept is still keyed on the
original destination being an allowed port on the gateway - but two things break quietly:

  * the endpoint is not what the operator thinks it is. the guest reaches a container,
    not the host service.
  * the check meant to exercise `ATTACK_PG_INPUT` exercises `ATTACK_PG_FWD` instead, so
    the INPUT allowlist goes untested and a regression there would not be caught.

it is invisible from the guest, because a connect-and-close probe cannot tell the two
apart. in a capture the give-away is that the packet leaves with a **rewritten
destination** and a decremented ttl:

```
172.24.0.2:34400 > 172.24.0.1:1337   [S] ttl 64     # what the guest dialled
172.24.0.2:34400 > 172.18.0.15:1337  [S] ttl 63     # what actually went on the wire
```

so it is checked on the host instead, against the `nat` table rather than by probing:
`setup_networking_linux.py` warns about it at startup, and `verify.sh` fails on it. it is
a warning at setup and not a refusal to start, because publishing an endpoint as a
container is a supported way to run one - doing it by accident on a port the host is also
serving is not.

`verify_guest.sh` additionally makes the host-listener probe (the first allowed port,
1337 as shipped) prove *which* listener answered: the host listener serves a random token, the guest fetches it, and a missing or different
token fails the check even though the connection succeeded.

for the same reason an endpoint range should not overlap the kernel's
`net.ipv4.ip_local_port_range` (commonly `32768-60999`), which is where docker draws
**dynamic** host ports from when a container publishes a port without naming the host
side (`-p 80`). a range that overlaps it can be taken over by a container nobody
published deliberately. the shipped `40000-40100` range does overlap it, and `verify.sh`
reports that.

### researchlabs.tech, a guest-only name for the gateway

inside a guest, `researchlabs.tech` resolves to the gateway ip of
`attack_playground_net` - the address the attack endpoints are exposed on. it is an
`/etc/hosts` entry, configured in `config.yaml` under
`docker.execution.host.extrahosts` (docker's `HostConfig.ExtraHosts`) and written by
docker into every guest container it creates:

```
extrahosts:
  - "researchlabs.tech:<gateway ip>"
```

a hosts entry rather than a dns record, for three reasons:

  * **it exists only inside a guest.** the host's own resolver, the `containerssh` and
    auth containers, and every other container on the daemon are untouched - nothing
    outside a guest resolves the name. `verify.sh` checks that the *host* does not
    resolve it to the gateway.
  * **it needs no packets.** a guest may only open the tcp ports in
    `attack_network_endpoints.conf`, so a resolver on the gateway would mean punching
    udp/53 through the allowlist - and docker's embedded dns has to keep failing, which
    `verify_guest.sh` checks. glibc consults `files` before `dns` (`/etc/nsswitch.conf`),
    so the entry answers without a query ever leaving the container.
  * **the guest cannot edit it.** with `readonlyrootfs` docker mounts `/etc/hosts`
    read-only, so the name means the same thing for the whole session.

the name is an **alias, not a permission**. `researchlabs.tech:1337` works because
tcp/1337 on the gateway is in the allowlist; `researchlabs.tech:22` is dropped exactly
like the gateway ip on 22. nothing in the iptables policy knows about the name.

#### the containerssh config is rendered, not static

docker numbers `attack_playground_net` when it creates it, so the gateway address is not
known until then and cannot be written down in a tracked file. `config.yaml` carries a
`__GATEWAY_IP__` placeholder instead; `start.sh` runs `scripts/render_config.py` once the
network exists and writes `config.runtime.yaml`, and **that** is the file
`docker-compose.yaml` mounts into containerssh. it is generated per host, gitignored, and
removed by `cleanup.sh` along with the network it describes.

this is why the playground has to be brought up with `./start.sh` (or the systemd unit,
which runs it) rather than with `docker compose up`: without the rendered file docker
mounts an empty directory over the config path and containerssh comes up with no config
at all. rendering refuses - and with it `start.sh` - on a missing network, a missing or
empty gateway, an address that is not ipv4, or a `config.yaml` with the placeholder
edited out. the alternative is a config containerssh loads happily and that only fails
when it creates the first guest, i.e. at someone's first ssh login.

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
the restart policy, the rendered guest hosts entry (and that the host itself does not
resolve `researchlabs.tech` to the gateway), that nothing was persisted to
`/etc/iptables`, that every range in `attack_network_endpoints.conf` is allowed in both
chains, and that the stats server answers on loopback, is following docker and has
written its sqlite file. `./verify_guest.sh`
then proves the policy from inside real guest containers: the host and published
endpoints are reachable, everything else (other host ports, the internet, the lan, dns,
icmp, the other guest over ipv4 and ipv6 link-local) is not, `researchlabs.tech` resolves
to the gateway and reaches the same host listener while still being dropped on a port
outside the allowlist, the guest hardening took effect, `nslookup` is in the image and
comes back empty-handed like `getent`, and the stats server counts exactly the guests
it opened - the two it holds open as connected now, and the one that already ended in
the window. the ports it probes are the first two the config allows and the ssh port
from `.env`, not numbers of its own. its test listener is bound to the gateway ip and serves an empty
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
curl -s <gateway-ip>:1337/     # ... and must be the *host* listener, not a
                               # container that published the same host port
nc -vz <gateway-ip> 22          # must fail
nc -6 -vz <host-link-local>%eth0 22   # must fail
curl -m 5 https://example.com   # must fail
getent hosts example.com        # must fail - docker's embedded dns must not forward
getent hosts researchlabs.tech  # must print the gateway ip - guests only
nc -vz researchlabs.tech 1337   # allowed endpoint, reached by name
nc -vz researchlabs.tech 22     # must fail - the name is an alias, not a permission
nc -vz <other-guest-ip> <port>  # must fail
nc -6 -vz <other-guest-link-local>%eth0 <port>  # must fail
```

note that icmp to the gateway is dropped as well, so `ping <gateway-ip>` failing is expected.

### tests

the config parsing, the fail-closed chain construction, the forward allow for
published endpoints, the ssh cap, the containerssh config rendering, the webhook
contract, the stats server (against a fake docker engine api served on a unix
socket), the endpoint helper the verify scripts read the config through and the
port loading in `common.sh` have unit tests. they are stdlib only
and need neither root nor docker:

```
python3 -m unittest discover -s scripts -p 'test_*.py'
```

the shell helpers in `scripts/common.sh` are covered too - those tests stub every
external command on `PATH`, so they behave the same on a developer laptop as on
the deployment host.
