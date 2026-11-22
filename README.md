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
    Name:     "easyvm-udp",
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

The forwarding path is driven through a pipe in `relay_test.go`, against a real in-process SOCKS5
server — not a mock. That keeps the session table, the handshake and the framing under test on a
runner with no tun device. The kernel half — the ioctl and the policy-routing commands — is asserted
by `TestOpenTunAsksForNoProtocolInfo` and the `chooseTable` tests.

```sh
go test ./... -race
```
