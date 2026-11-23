// A CONTAINER THAT PROVES easytun's CONTAINER MODE WORKS FROM INSIDE, INCLUDING EGRESS ROUTING.
//
// It runs in a container with /dev/net/tun and NET_ADMIN, takes over the namespace's default route,
// makes the requests a workload would, and reports what happened on stdout so `kubectl logs` is the
// evidence - and exits non-zero when any of it is wrong.
//
// TWO PROXIES AND TWO DESTINATIONS, because "a datagram came back" is not "the rule chose the path".
// Each proxy tags its answer with its own letter, so the tag that arrives at the workload names the
// path that carried it. The addresses are TEST-NET-3 (RFC 5737), reserved for documentation, so a reply
// can only have come from a proxy this process can reach.
//
//	PROXY_A / PROXY_B    host:port of two SOCKS5 relays (the workflow starts them)
//	                       unset: the demo uses a local echo server instead, which still exercises the
//	                       tun, the mark and the reply rewrite but not the routing decision
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/easydev-org/easytun"
)

func main() {
	fmt.Println("=== before the takeover ===")
	if out, _ := exec.Command("ip", "route", "show", "default").Output(); true {
		fmt.Printf("  (the demo will restore: %q)\n", strings.TrimSpace(string(out)))
	}
	show("ip route show default")

	proxyA, proxyB := os.Getenv("PROXY_A"), os.Getenv("PROXY_B")

	// THE FALLBACK: no proxies configured, so a local echo server stands in for the internet. It still
	// proves the tun carries a datagram and the reply reaches the workload; it cannot prove routing.
	var fallbackAddr string
	var stopFallback func()
	if proxyA == "" || proxyB == "" {
		fallbackAddr, stopFallback = startEcho()
		defer stopFallback()
		fmt.Printf("no PROXY_A/PROXY_B set, so a local echo server on %s stands in\n", fallbackAddr)
	}

	c, err := easytun.StartContainer(easytun.ContainerConfig{
		Name: "et0",
		// THE PROXIES ARE EXEMPT, or the relay's own connections to them loop back into its device.
		// StartContainer exempts `Upstream` automatically; the second proxy is named here because it is
		// only reachable by the original route too.
		Exempt:   exemptHosts(proxyA, proxyB, fallbackAddr),
		Upstream: proxyA,
		Route: func(dst net.IP, port uint16) easytun.Route {
			switch {
			case proxyA != "" && dst.String() == "203.0.113.10":
				return easytun.Route{Upstream: proxyA}
			case proxyB != "" && dst.String() == "203.0.113.20":
				return easytun.Route{Upstream: proxyB}
			case proxyA != "" && dst.String() == "203.0.113.40":
				// A DROPPED DESTINATION: the rule says no, so nothing goes anywhere.
				return easytun.Route{Kind: easytun.RouteDrop}
			case fallbackAddr != "":
				// THE FALLBACK MODE: everything goes to the echo server, rewritten, so a reply proves
				// the tun carried the datagram in both directions.
				return easytun.Route{Direct: true, Host: fallbackAddr}
			}
			return easytun.Route{}
		},
		Logf: func(f string, a ...any) { fmt.Printf("  easytun: "+f+"\n", a...) },
	})
	if err != nil {
		fmt.Println("StartContainer:", err)
		os.Exit(1)
	}

	fmt.Println("=== after the takeover ===")
	show("ip route show default")
	show("ip addr show et0")

	// THE WORKLOAD. It knows nothing about any of this.
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		fmt.Println("the client:", err)
		os.Exit(1)
	}
	defer client.Close()

	fail := false
	expect := func(addr, want string) {
		got := ask(client, addr, 3*time.Second)
		if got != want {
			fmt.Printf("FAIL %-18s -> %q, want %q\n", addr, got, want)
			fail = true
			return
		}
		fmt.Printf("ok   %-18s -> %q\n", addr, got)
	}
	silent := func(addr string) {
		if got := ask(client, addr, 900*time.Millisecond); got != "" {
			fmt.Printf("FAIL %-18s -> %q, want silence\n", addr, got)
			fail = true
			return
		}
		fmt.Printf("ok   %-18s -> (silence)\n", addr)
	}

	if proxyA != "" && proxyB != "" {
		// THE ROUTING CLAIM: the letter that comes back names the path, and A's destination must NOT
		// answer with B's letter (that cross-check is what makes the first assertion mean something).
		expect("203.0.113.10:443", "A:udp-from-the-workload")
		expect("203.0.113.20:443", "B:udp-from-the-workload")
		silent("203.0.113.40:443")
	} else {
		expect("203.0.113.10:443", "echo:udp-from-the-workload")
		expect("203.0.113.20:53", "echo:udp-from-the-workload")
	}

	// THE ROUTE COMES BACK, which is what makes this safe in a container that does anything afterwards.
	if err := c.Close(); err != nil {
		if strings.Contains(err.Error(), "could not be restored exactly") {
			fmt.Printf("warn Close: %v\n", err)
		} else {
			fmt.Println("FAIL Close:", err)
			fail = true
		}
	}
	fmt.Println("=== after Close ===")
	show("ip route show default")
	switch out, _ := exec.Command("ip", "route", "show", "default").Output(); {
	case strings.Contains(string(out), "et0"):
		fmt.Println("FAIL: the default route still points at the device after Close")
		fail = true
	case len(strings.TrimSpace(string(out))) == 0:
		fmt.Println("FAIL: Close left the namespace with NO default route, so it can reach nothing")
		fail = true
	default:
		fmt.Println("ok   the default route is restored")
	}

	if fail {
		fmt.Println("RESULT: FAILED")
		os.Exit(1)
	}
	fmt.Println("RESULT: container mode works")
}

// ask sends one datagram and returns the reply, or "" when none arrives inside the window.
func ask(client *net.UDPConn, addr string, wait time.Duration) string {
	u, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return "<bad address: " + err.Error() + ">"
	}
	if _, err := client.WriteToUDP([]byte("udp-from-the-workload"), u); err != nil {
		return "<write failed: " + err.Error() + ">"
	}
	_ = client.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 2048)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

// exemptHosts collects the addresses the process must still reach by the original route.
func exemptHosts(addrs ...string) []string {
	var out []string
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(a); err == nil && host != "" {
			out = append(out, host)
		}
	}
	return out
}

// startEcho answers every datagram with "echo:" and the payload, on the pre-takeover path.
//
// IT BINDS A CONCRETE ADDRESS, NOT 0.0.0.0, because that address is what the relay is told to dial:
// `0.0.0.0:port` is a bind wildcard and not a destination, so a caller that passed it on would ask the
// resolver for a host named "0.0.0.0".
func startEcho() (string, func()) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fmt.Println("the echo server:", err)
		os.Exit(1)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return c.LocalAddr().String(), func() { c.Close() }
}

func show(cmd string) {
	args := strings.Fields(cmd)
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	fmt.Printf("  $ %s\n", cmd)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			fmt.Printf("    %s\n", line)
		}
	}
	if err != nil {
		fmt.Printf("    (%v)\n", err)
	}
}
