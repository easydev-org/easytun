//go:build linux

package easytun

// CONTAINER MODE: TAKE OVER EVERYTHING THIS NETWORK NAMESPACE SENDS.
//
// THE DIFFERENCE FROM `Start`, IN ONE SENTENCE: `Start` relays ONE ADDRESS's UDP out of a network it
// shares with others, and this relays EVERYTHING out of a network it is alone in.
//
//	Start            ip rule from <guest> ipproto udp lookup <table>
//	                 one address, one protocol, and the rest of the namespace is untouched
//
//	StartContainer   ip route replace default dev <tun>
//	                 every packet this namespace sends, whatever made it, arrives at the device
//
// WHY A CONTAINER IS THE EASY CASE AND A MINIMUM OF MACHINERY IS NEEDED: a container has its own
// network namespace, so "everything" is a small, well-defined set - the processes in this container and
// nothing else. There is no bridge, no DHCP, no NAT and no guest address to match on.
//
// WHAT THE DEVICE CAN AND CANNOT CARRY, WHICH DECIDES THE SHAPE OF THIS FILE:
//
//	UDP    the tun carries it. A datagram has no connection, so nothing in the kernel needs to know
//	       the far end - it is read here, framed for a proxy, and the reply is written back.
//
//	TCP    THE TUN DOES NOT CARRY IT. A tun hands out IP packets; a TCP connection is a byte stream the
//	       kernel owns, and implementing one in userspace means writing a TCP stack. So TCP is
//	       DELIVERED TO A LISTENER by an iptables REDIRECT, and the kernel keeps doing the TCP - see
//	       StartTCP, which is the other half of this mode.
//
//	DNS    also a redirect, not the tun: a query is a UDP datagram, but answering it HERE would mean
//	       this process is the resolver, and the `names` package already is one. Redirecting :53 to it
//	       is one rule and gives name-based rules their names - see names.Server.
//
// SO THIS MODE IS three pieces wired together: the device and its default route, the UDP relay behind
// it, and (by the caller) a TCP listener and a resolver. This function does the first two and reports
// the ports for the other two, because the redirect rules are about the caller's topology.

import (
	"fmt"
	"net"
	"strings"
)

// ContainerConfig is what StartContainer needs.
type ContainerConfig struct {
	// Name is the tun device's name. Empty means "easytun0".
	Name string
	// Upstream is the SOCKS5 proxy for UDP, host:port. Empty means UDP goes direct - which for a
	// container that has taken over its own default route means the traffic leaves this process
	// unproxied, and is only useful when something downstream filters it.
	Upstream string
	// Route decides where one datagram goes. Nil means "everything through Upstream".
	Route func(dst net.IP, port uint16) Route
	// Exempt are addresses that must NOT go through the device - the proxy itself, and anything else
	// this process must reach by the original path.
	//
	// THIS IS NOT OPTIONAL IN PRACTICE, EVEN THOUGH IT CAN BE EMPTY. Once the default route moves into
	// the tun, the relay's own connection to its proxy is routed into the tun as well - so the tun
	// reads the relay's traffic as if it were the workload's, and answers it with itself. MEASURED: the
	// proxy's packets appeared in the device. The exception route is what breaks that loop.
	Exempt []string
	// Address is the device's own address, "10.99.0.1/24" by default. Its subnet is what the kernel
	// uses as the source for packets it routes into the device.
	Address string
	// Logf receives one line per failure.
	Logf func(format string, args ...any)
}

// Container is a taken-over namespace.
type Container struct {
	// Name is the device.
	Name string
	// Addr is the device's own address, without the prefix.
	Addr string
	// TCPPort is the port a TCP listener should bind, for the caller's REDIRECT rule. Zero until
	// StartContainerTCP is called - this mode does not start one by itself, because a caller that only
	// wants UDP should not open a TCP port.
	TCPPort int

	relay *Relay
	tun   tunDevice
	// the routing this mode installed, so Close can undo exactly it
	before defaultRoute
	table  int
	exempt []string
	logf   func(string, ...any)
	once   bool
}

// defaultRoute is what the namespace's default route looked like before the takeover.
type defaultRoute struct {
	via string
	dev string
}

// StartContainer takes over the namespace's default route and relays its UDP.
//
// THE ORDER OF THE THREE STEPS IS THE WHOLE CORRECTNESS ARGUMENT:
//
//  1. read the default route, so the exception routes know the way out
//  2. install the exceptions, so the process can still reach its proxy
//  3. move the default into the device
//
// Installing the exceptions after the move would be a window in which the relay's own traffic loops;
// reading the route after it would find the device.
func StartContainer(cfg ContainerConfig) (*Container, error) {
	name := cfg.Name
	if name == "" {
		name = "easytun0"
	}
	addr := cfg.Address
	if addr == "" {
		addr = "10.99.0.1/24"
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	// 1. THE WAY OUT, BEFORE ANYTHING CHANGES.
	before, err := readDefaultRoute()
	if err != nil {
		return nil, err
	}

	// 2. THE EXCEPTIONS. The proxy is exempt by default, because the loop it causes is the one that
	// makes this mode look broken in a way nothing reports.
	exempt := append([]string(nil), cfg.Exempt...)
	if cfg.Upstream != "" {
		if host, _, err := net.SplitHostPort(cfg.Upstream); err == nil {
			exempt = append(exempt, host)
		}
	}
	for _, host := range exempt {
		if err := exemptRouteFn(host, before); err != nil {
			return nil, fmt.Errorf("exempting %s: %w", host, err)
		}
	}

	// THE DEVICE. A fresh one: a leftover from a killed process would carry somebody else's default
	// route, and the takeover below would look like it worked while sending traffic to nothing.
	_ = deleteTun(name)
	tun, err := openDevice(name)
	if err != nil {
		return nil, err
	}
	c := &Container{Name: name, Addr: strings.TrimSuffix(addr, "/24"),
		tun: tun, before: before, exempt: exempt, logf: logf}

	// THE ADDRESS AND THE RAISE. `addrFor`'s job in guest mode is to keep two relays apart; here there
	// is one namespace and one device, so the address is the caller's.
	if err := bringUp(name, addr); err != nil {
		_ = tun.Close()
		_ = deleteTun(name)
		return nil, err
	}

	// 3. THE TAKEOVER.
	if out, err := run("ip", "route", "replace", "default", "dev", name, "metric", "100"); err != nil {
		_ = tun.Close()
		_ = deleteTun(name)
		return nil, fmt.Errorf("moving the default route into %s: %v (%s)", name, err, firstLine(out))
	}

	// THE RELAY BEHIND IT. No policy routing: the device is the default route, so every datagram this
	// namespace sends is already here.
	c.relay = newRelay(name, tun, Config{
		Upstream: cfg.Upstream,
		Route:    cfg.Route,
		Logf:     logf,
		// THE GUEST ADDRESS IS THIS DEVICE'S. Every packet that arrives has it as the destination of
		// the reply path, and the relay needs it to build the packet it writes back.
		GuestIP: c.Addr,
	}, logf)
	c.relay.start()
	return c, nil
}

// Close undoes the takeover: the default route first, then the device, then the exceptions.
//
// THE ORDER IS THE REVERSE OF START AND IT MATTERS. A default route left pointing at a deleted device
// sends every packet in the namespace to nowhere, and the failure is a container that looks healthy and
// can reach nothing - which is why the route goes before the device.
func (c *Container) Close() error {
	if c == nil || c.once {
		return nil
	}
	c.once = true
	var problems []string

	if err := c.relay.Close(); err != nil {
		problems = append(problems, err.Error())
	}

	// THE DEFAULT ROUTE GOES BACK TO WHAT IT WAS, not to nothing: a container whose default route is
	// deleted has no way out at all.
	//
	// THE DEFAULT ROUTE GOES BACK EXACTLY AS IT WAS, AND THE GATEWAY IS NOT OPTIONAL.
	//
	// MEASURED WHILE WRITING THIS: a `default dev <iface>` WITH NO GATEWAY HIJACKS LOCAL ADDRESSES.
	// After such a restore, `ip route get 127.0.0.1` answered `dev veth0` instead of `dev lo` - so
	// every 127.0.0.1 connection in the namespace went to the wire. A gateway-less default is only
	// correct on a point-to-point link; for a namespace that had one, restoring without it breaks
	// loopback, which is worse than the route being absent.
	//
	// So an exact restore that fails is REPORTED rather than approximated. The caller sees which
	// route could not be rebuilt and can re-create it; a wrong route silently breaks everything.
	args := []string{"route", "replace", "default"}
	if c.before.via != "" {
		args = append(args, "via", c.before.via)
	}
	if c.before.dev != "" {
		args = append(args, "dev", c.before.dev)
	}
	if out, err := run("ip", args...); err != nil {
		problems = append(problems, fmt.Sprintf("restoring the default route (%s): %v (%s)",
			strings.Join(args, " "), err, firstLine(out)))
	}

	for _, host := range c.exempt {
		if out, err := run("ip", "route", "del", host+"/32"); err != nil && !contains(out, "No such process") {
			problems = append(problems, fmt.Sprintf("removing the exception for %s: %v (%s)",
				host, err, firstLine(out)))
		}
	}
	if err := removeDevice(c.Name); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return fmt.Errorf("easytun: the container's network was not fully restored: %v", problems)
	}
	return nil
}

// StartTCP listens for the connections an iptables REDIRECT sends here, and reports its port.
//
// THE CALLER WRITES THE RULE, because it is about the caller's topology:
//
//	iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports <Port()>
//
// OUTPUT AND NOT PREROUTING: in a container the traffic is made HERE, so it is a locally generated
// connection and never passes PREROUTING.
//
// IT EXEMPTS NOTHING BY ITSELF. Loopback is not routed, so a listener on 127.0.0.1 is never caught; a
// proxy on a routed address must be in ContainerConfig.Exempt, or the listener's own connection to it
// is redirected back to the listener.
func (c *Container) StartTCP(upstream string, route func(dst net.IP, port uint16) Route) (*TCP, error) {
	tcp, err := StartTCP(TCPConfig{
		// THE DEVICE'S ADDRESS, NOT LOOPBACK: a redirected connection's source is this namespace, but
		// binding the device address keeps the listener off a port that loopback-only clients share.
		Bind:     c.Addr + ":0",
		Upstream: upstream,
		Route:    route,
		Logf:     c.logf,
	})
	if err != nil {
		return nil, err
	}
	if tcp != nil {
		c.TCPPort = tcp.Port
	}
	return tcp, nil
}

// readDefaultRoute reads the namespace's current default route, so the exceptions know the way out and
// Close can put it back.
func readDefaultRoute() (defaultRoute, error) {
	out, err := run("ip", "route", "show", "default")
	if err != nil {
		return defaultRoute{}, fmt.Errorf("reading the default route: %v (%s)", err, firstLine(out))
	}
	var r defaultRoute
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				r.via = f[i+1]
			case "dev":
				r.dev = f[i+1]
			}
		}
		// THE FIRST DEFAULT ROUTE IS THE ONE TO RESTORE. A table with several is already unusual, and
		// taking the first is what `ip route get` would have used before the takeover.
		break
	}
	if r.dev == "" {
		return defaultRoute{}, fmt.Errorf("this namespace has no default route, so there is nothing to " +
			"exempt and nowhere to restore: the container has no way out at all")
	}
	return r, nil
}

// exemptRouteFn is the route installer, a variable so a test can assert which hosts are exempted
// without needing `ip`.
var exemptRouteFn = exemptRoute

// exemptRoute pins one host to the pre-takeover path.
//
// A /32 IS SPECIFIC ENOUGH TO WIN OVER THE DEFAULT, which is the point: the route lookup prefers the
// longest prefix, so the proxy keeps its old way out while everything else moves.
func exemptRoute(host string, before defaultRoute) error {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("%q is not an address and does not resolve", host)
		}
		ip = addrs[0]
	}
	args := []string{"route", "replace", ip.String() + "/32"}
	if before.via != "" {
		args = append(args, "via", before.via)
	}
	args = append(args, "dev", before.dev)
	if out, err := run("ip", args...); err != nil {
		return fmt.Errorf("ip %v: %v (%s)", args, err, firstLine(out))
	}
	return nil
}
