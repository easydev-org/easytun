# easytun

Relay a guest's UDP through a SOCKS5 proxy, using a tun device the container owns.

```go
import "github.com/easydev-org/easytun"

if err := easytun.Preflight(); err != nil {
    log.Fatal(err) // names which of the two container flags is missing
}

r, err := easytun.Start(easytun.Config{
    GuestIP:  "172.30.0.2",
    Upstream: "mihomo.develop.svc.cluster.local:7891",
    Name:     "relay-udp",
})
if err != nil {
    log.Fatal(err)
}
defer r.Close()
```

## Why this exists

A SOCKS5 proxy forwards UDP over its **own association** (`UDP ASSOCIATE`), not over `CONNECT`. So
`iptables` cannot put a guest's datagrams through one: iptables can redirect a packet to a local
socket, but the SOCKS5 framing and the separate reply socket live in userspace. The only place a
datagram can be handed to userspace and get an answer back as a datagram is a **tun device**.

MEASURED, on a pod whose route to a package mirror was 38–68 KB/s while the same file through the
cluster's proxy took a second: a guest's TCP connections went through the proxy and its QUIC
connections did not, because QUIC is UDP. The result was a browser that loaded pages slowly and then
stalled on every video.

## What the container must give it

```sh
docker run \
  --device /dev/net/tun \
  --cap-add NET_ADMIN \
  ...
```

Two things, and they fail differently:

| missing | error | fix |
|---|---|---|
| `/dev/net/tun` | `ErrNoTun` | `--device /dev/net/tun` |
| `CAP_NET_ADMIN` | `ErrNoNetAdmin` | `--cap-add NET_ADMIN` |

`Preflight()` answers both **before anything is created**, because the raw failure arrives at an
`ip link add` and reads as a broken network rather than a missing capability.

## What it does, precisely

1. Opens `/dev/net/tun` and asks for `IFF_TUN | IFF_NO_PI`.
2. Addresses the device `10.99.<n>.1/24` and raises it.
3. Installs, **for this guest's UDP only**:

   ```
   ip route replace default dev <name> table <n>
   ip rule add from <guest>/32 ipproto udp lookup <n>
   ```

   `ipproto udp` is what keeps TCP out of the tun — TCP is carried by the CONNECT proxy instead.

4. Reads IPv4 UDP packets from the tun, looks up a SOCKS5 `UDP ASSOCIATE` session per flow, frames and
   sends, then rebuilds the reply as a packet **from the destination the guest asked for**. The guest
   would discard a datagram from `10.99.x.1`, so the rewrite is the whole illusion.
5. Closes idle sessions after two minutes — UDP has no close, and a finished QUIC flow leaves nothing
   behind to tell us.

## Routing the flow somewhere else

`Config.Route` is the only policy hook, deliberately. A library that also decided *which*
destinations are allowed would have to guess the caller's policy language.

```go
Route: func(dst net.IP, port uint16) easytun.Route {
    if dst.IsLoopback() {
        return easytun.Route{Direct: true, Drop: false} // leave this pod's own network alone
    }
    if port == 25 {
        return easytun.Route{Drop: true} // a filtered port looks like silence, which is correct
    }
    return easytun.Route{} // the configured upstream
}
```

`Drop` sends nothing: there is no RST in UDP, so the guest's client times out — exactly what a
filtered port looks like everywhere.

## Two relays in one network namespace

`--network container:` puts two services in one namespace. Both need a table and an address, and
neither may collide:

* The table is the caller's (`Config.Table`) or, by default, **the first empty table at or after a
  hash of the device name** in `100..199`. The hash alone is not enough — a hundred buckets cannot
  hold an unbounded set of names without a collision — so `chooseTable` probes until it finds one that
  is free.
* The address follows the chosen table (`10.99.<table%100>.1`), so two relays never claim one /24.

## What it does **not** do

It is not a firewall, not a router, and not a VPN. It relays **one guest's** UDP through **one**
SOCKS5 proxy. IPv6, fragmentation and ICMP are dropped, and the package says so rather than pretending
otherwise. `mihomo` speaks SOCKS5 UDP on a **different port** from its HTTP proxy (`7890` HTTP, `7891`
SOCKS5); deriving one from the other by adding one is a guess that happens to be right for one
implementation.

## Testing

There are two layers, because the tun device is a kernel thing and the rest is not.

**Unit — every machine, no privileges.** The forwarding path is driven through a pipe, against real
in-process servers, not mocks. Every public field is covered, because a knob that is accepted and
ignored is worse than one that is rejected:

| what | how it is checked |
|---|---|
| the framing | build/parse round trips, and a packet that is not IPv4 UDP is refused |
| SOCKS5 | the handshake, then a datagram out and its reply rewritten back into the tun |
| a name on the wire | `Route.Host` becomes ATYP 3, and an empty one is byte-for-byte the address form |
| `Route.Direct` | dials the destination with no proxy, and its reply comes back as the source |
| `Route.Direct` + `Host` | dials the NAME, so an invented address never reaches the network |
| `Route.Drop` | sends nothing |
| `Config.Table` | the caller's number reaches the rule, not the hash bucket |
| `Config.Logf` | receives each failure; nil is silent, not a panic |
| `Config.Name` | empty becomes `tun0`, and the relay remembers it for `Close` |
| `Close` | idempotent, and it reports a cleanup it could not finish |

`go test ./...` skips the kernel half and stays green on a machine with nothing mounted.

**E2E — a real device.** `e2e_test.go` creates a tun device and reads the kernel's own view of it,
because the ioctl, the address, the policy rule and the route cannot be asserted any other way. The
device is the fixture:

| claim | how it is checked |
|---|---|
| the device exists and is up | `ip link show <name>` |
| it is addressed, so a route cannot blackhole | `ip -4 addr` shows `10.99.<n>.1/24` |
| only this guest's UDP is taken, not its TCP | `ip rule` names `ipproto udp`, and no broader rule exists |
| the table the rule points at is populated | `ip route show table <n>` has a default |
| a datagram goes out and comes back | a real socket from the guest address, through a real SOCKS5 server |
| `Close` removes the device and the rule | both are gone afterwards |

A **user namespace is enough** — no root, no privileged container:

```sh
sudo mknod /dev/net/tun c 10 200 && sudo chmod 666 /dev/net/tun   # the tun module is already loaded
unshare -Urn --keep-caps go test ./... -run E2E -v
```

`--keep-caps` matters: `unshare -U` alone drops the capability set and the ioctl then fails with EPERM
in a namespace that otherwise allows it. The policy routing the test installs stays inside the
namespace, so it cannot leak onto the host.

Loopback is **down** in a fresh namespace, and every socket test depends on it being up — so the tests
raise it themselves (`ensureLoopbackUp`). MEASURED: without that, a listener bound to `127.0.0.1`
accepts a connect attempt and never completes it, and the symptom is a five-second timeout that reads
as "the relay is broken".

Without a usable device the e2e tests **skip with the reason**, which is why the CI job in
`.github/workflows/test.yml` asserts that none of them skipped — a green run that skipped everything
proves nothing.
