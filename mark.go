//go:build linux

package easytun

// THE RELAY'S OWN SOCKETS MUST NOT GO THROUGH THE RELAY'S OWN DEVICE.
//
// THIS IS THE PROBLEM EVERY USER-SPACE TUN PROXY HAS, and it is the one that looks like a hang rather
// than a bug. Once the default route points into the tun, the relay's outgoing socket - the one it uses
// to reach the proxy, or to send a `direct` datagram - is routed into the tun as well. So the relay
// reads its own traffic back, thinks it is the workload's, and forwards it again. MEASURED in a
// container: the dial failed with `resource temporarily unavailable`, and the device showed the relay's
// own packets.
//
// THE FIX IS A MARK, AND IT IS THE ONE THE KERNEL IS BUILT FOR. A socket marked with SO_MARK is matched
// by `ip rule fwmark <mark> lookup <main>` BEFORE the rule that sends everything to the tun, so it takes
// the original path. That is one setsockopt per socket and one rule per namespace - no address
// exceptions to keep in sync, which is what makes it right for a proxy whose address may change.
//
//	ip route replace default via <gw> dev <iface> table 100
//	ip rule add fwmark 0x1 lookup 100 pref 100
//	ip rule add fwmark 0x1 prohibit   pref 101    (a marked socket with no route fails fast)
//
// The mark is on the SOCKET, not the packet, so nothing a workload sends is affected.

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
)

// relayMark is the fwmark the relay's own sockets carry. Any non-zero value works; this one is what
// the rule below names.
const relayMark = 0x1

// dialer returns a UDP dialer whose sockets are marked when the process MAY mark them.
//
// THE MARK IS BEST-EFFORT, AND THAT IS NOT SLOPPINESS: SO_MARK NEEDS CAP_NET_ADMIN, MEASURED - a plain
// user gets `operation not permitted` from setsockopt, so a relay that treated it as fatal would fail
// to start anywhere it is not privileged. And the mark only matters in container mode, where the
// relay's own traffic would otherwise loop into its own device; in guest mode there is no default-route
// takeover to loop through, so an unmarked socket is correct.
func (r *Relay) dialer() *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			if err := c.Control(func(fd uintptr) {
				// THE ERROR IS DISCARDED ON PURPOSE. See above: EPERM here means "not privileged",
				// which is a configuration the relay works in, not a failure.
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, relayMark)
			}); err != nil {
				return err
			}
			return nil
		},
	}
}

// listenMarked opens a UDP socket whose packets carry the mark.
//
// A SESSION'S SOCKET IS CONNECTED TO THE PROXY, so its own sends must bypass the tun - otherwise the
// request the relay frames goes back into the device it came from.
func listenMarked() (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if err := c.Control(func(fd uintptr) {
				// BEST-EFFORT: SO_MARK needs CAP_NET_ADMIN, and a relay without it still works wherever
				// there is no takeover to loop through. See dialer.
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, relayMark)
			}); err != nil {
				return err
			}
			return nil
		},
	}
	pc, err := lc.ListenPacket(nil, "udp", ":0")
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errNotUDP
	}
	return conn, nil
}

// installMarkRules makes the mark mean "take the original path".
//
// THE RULE GOES IN AT A PREFERENCE BELOW THE TUN'S. `ip rule` is evaluated by ascending preference, and
// `lookup main` is what the namespace used before the takeover - so a marked packet is routed exactly as
// if the takeover had not happened.
//
// THE PROHIBIT RULE IS NOT DECORATION. Without it, a marked socket whose destination has no route in
// `main` falls through to the DEFAULT rule, which is the tun - so the one case the mark was meant to
// fix silently does not. `prohibit` makes it fail immediately, which is why a misconfiguration shows up
// as a connection error rather than a packet in the device.
func installMarkRules(mark, table int) error {
	m := "0x" + strconv.FormatInt(int64(mark), 16)
	t := strconv.Itoa(table)
	for _, step := range [][]string{
		{"rule", "add", "fwmark", m, "lookup", t, "pref", "100"},
		{"rule", "add", "fwmark", m, "prohibit", "pref", "101"},
	} {
		if out, err := run("ip", step...); err != nil && !contains(out, "File exists") {
			return fmt.Errorf("`ip %v`: %v (%s)", step, err, firstLine(out))
		}
	}
	return nil
}

// removeMarkRules undoes installMarkRules.
func removeMarkRules(mark, table int) {
	m := "0x" + strconv.FormatInt(int64(mark), 16)
	t := strconv.Itoa(table)
	_, _ = run("ip", "rule", "del", "fwmark", m, "lookup", t, "pref", "100")
	_, _ = run("ip", "rule", "del", "fwmark", m, "prohibit", "pref", "101")
}
