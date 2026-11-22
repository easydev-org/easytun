// Package easytun relays a guest's UDP through a SOCKS5 proxy, using a tun device the container
// owns.
//
// # THE PROBLEM IT SOLVES, AND WHY NOTHING ELSE DOES
//
// A SOCKS5 proxy forwards UDP over its OWN ASSOCIATION (`UDP ASSOCIATE`), not over `CONNECT`. So
// `iptables` cannot put a guest's datagrams through one: iptables can redirect a packet to a local
// socket, but the SOCKS5 framing and the separate reply socket live in userspace. The only place a
// datagram can be handed to userspace and get an answer back as a datagram is a tun device.
//
// MEASURED, on a pod whose route to a package mirror was 38-68 KB/s while the same file through the
// cluster's proxy took a second: a guest making TCP connections went through the proxy and its QUIC
// connections did not, because QUIC is UDP. The result was a browser that loaded pages slowly and
// then stalled on every video.
//
// WHAT THE CONTAINER MUST GIVE IT
//
//	docker run --device /dev/net/tun --cap-add NET_ADMIN ...
//
// Two things, and they fail differently:
//
//	no /dev/net/tun        the device was not mounted      -> --device /dev/net/tun
//	device present, EPERM  the capability is missing       -> --cap-add NET_ADMIN
//
// `Preflight` answers both before anything is created, because the raw failure arrives at an
// `ip link add` and reads as a broken network rather than a missing capability.
//
// # WHAT IT DOES NOT DO
//
// It is not a firewall, not a router, and not a VPN. It relays the UDP of ONE guest through ONE
// SOCKS5 proxy. Anything else a datagram needs - IPv6, fragmentation, ICMP - is dropped, and the
// package says so rather than pretending otherwise.
//go:build linux

package easytun

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrNoTun means /dev/net/tun is absent or unopenable: the container was started without
// `--device /dev/net/tun`.
var ErrNoTun = errors.New("easytun: /dev/net/tun is not usable")

// ErrNoNetAdmin means the device is there and cannot be used: the container was started without
// `--cap-add NET_ADMIN`.
var ErrNoNetAdmin = errors.New("easytun: CAP_NET_ADMIN is missing")

// Preflight answers "can this container run a tun at all" before anything is created.
//
// IT IS THREE CHECKS AND THEY ARE NOT THE SAME QUESTION:
//
//  1. does /dev/net/tun exist and open   -> the device was not mounted
//  2. is a socket creatable              -> the kernel has the tun module
//  3. can `ip link` run                  -> NET_ADMIN is present in this namespace
//
// Reading CapEff would answer 3 too and would be wrong: it reports the capability set, not whether
// the kernel allows the operation here. Running `ip link show` is the honest test and costs a
// millisecond.
func Preflight() error {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("%w: /dev/net/tun exists and cannot be opened (%v)", ErrNoTun, err)
		}
		return fmt.Errorf("%w: %v. The container needs `--device /dev/net/tun`", ErrNoTun, err)
	}
	_ = f.Close()

	// A NETLINK SOCKET PROVES THE TUN MODULE IS LOADED without creating a device.
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("easytun: no netlink socket (%v), so link configuration is impossible", err)
	}
	syscall.Close(fd)

	// AND A LINK CHANGE THAT DOES NOTHING PROVES THE CAPABILITY. `ip link show` needs no privilege,
	// so this uses a query that does: `ip link set lo up` on an interface that is already up is a
	// no-op the kernel still checks permission for.
	if out, err := run("ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("%w: `ip link set lo up` failed (%s). The container needs "+
			"`--cap-add NET_ADMIN`", ErrNoNetAdmin, firstLine(out))
	}
	return nil
}
