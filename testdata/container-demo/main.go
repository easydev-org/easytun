// A CONTAINER THAT PROVES easytun's CONTAINER MODE WORKS FROM INSIDE.
//
// It runs as PID 1-ish in a container with /dev/net/tun and NET_ADMIN, takes over the namespace's
// default route, makes the requests a workload would, and reports what happened on stdout so `kubectl
// logs` is the evidence.
//
// THE REQUESTS ARE UDP AGAINST TEST-NET-3 ADDRESSES: reserved for documentation, so nothing real is at
// one, and a reply can only have come from the tun side of this process.
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
	show("ip addr show")

	// THE DEMO'S "INTERNET" IS A LOCAL ECHO SERVER, reachable only by the ORIGINAL route.
	//
	// It is what makes the measurement meaningful: the workload's datagrams are addressed to
	// TEST-NET-3, so they can ONLY reach this server through the tun, and the server is on the
	// pre-takeover path so it proves the exception route works. A real deployment replaces both with a
	// SOCKS5 proxy and the real internet.
	echoAddr, stopEcho := startEcho()
	defer stopEcho()
	fmt.Printf("the demo's echo server is on %s (reached by the original route)\n", echoAddr)
	echoIP, _, _ := net.SplitHostPort(echoAddr)

	c, err := easytun.StartContainer(easytun.ContainerConfig{
		Name: "et0",
		// THE EXCEPTION IS WHAT LETS THE PROCESS REACH THE ECHO SERVER, exactly as it lets a real
		// deployment reach its proxy.
		Exempt: []string{echoIP},
		// A DIRECT RULE for everything: the datagram leaves this process unproxied, which is the
		// simplest path that still exercises the tun, the mark and the reply rewrite. The address is
		// rewritten to the echo server's, so a datagram addressed to TEST-NET-3 lands there.
		Route: func(dst net.IP, port uint16) easytun.Route {
			return easytun.Route{Direct: true, Host: echoAddr}
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
	for _, target := range []string{"203.0.113.10:443", "203.0.113.20:53"} {
		addr, _ := net.ResolveUDPAddr("udp4", target)
		if _, err := client.WriteToUDP([]byte("from-the-workload"), addr); err != nil {
			fmt.Printf("FAIL %s: %v\n", target, err)
			fail = true
			continue
		}
		client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		if n, from, err := client.ReadFromUDP(buf); err == nil {
			fmt.Printf("ok   %s -> %q from %v\n", target, buf[:n], from)
		} else {
			fmt.Printf("FAIL %s: the datagram did not come back through the device: %v\n", target, err)
			fail = true
		}
	}

	// THE ROUTE COMES BACK, which is the property that makes this safe to run in a container that does
	// anything else afterwards.
	// A DEGRADED RESTORE IS NOT A FAILURE OF THE MODE. If the namespace's original gateway was on a
	// link that no longer reaches anything - which is what a test fixture with a dead peer looks like,
	// and what a container whose interface went away looks like - Close reports it and puts back the
	// device-only form so there is still a default route. That is the right behaviour and the demo
	// treats it as a warning.
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
	// "RESTORED" MEANS THERE IS ONE, NOT MERELY THAT IT IS NOT THE DEVICE.
	//
	// MEASURED: the first version of this check only tested `not et0`, so an EMPTY default route - the
	// namespace with no way out at all - printed `ok`. That is the failure the restore exists to
	// prevent, reported as a success.
	out, _ := exec.Command("ip", "route", "show", "default").Output()
	switch {
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
