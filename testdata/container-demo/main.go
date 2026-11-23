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
	show("ip route show default")
	show("ip addr show")

	c, err := easytun.StartContainer(easytun.ContainerConfig{
		Name: "et0",
		// NO UPSTREAM: this demo measures that traffic reaches the device, and a real deployment
		// points this at a SOCKS5 proxy - which must then be exempted, as StartContainer does.
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
	if err := c.Close(); err != nil {
		fmt.Println("FAIL Close:", err)
		fail = true
	}
	fmt.Println("=== after Close ===")
	show("ip route show default")
	if out, _ := exec.Command("ip", "route", "show", "default").Output(); strings.Contains(string(out), "et0") {
		fmt.Println("FAIL: the default route still points at the device after Close")
		fail = true
	} else {
		fmt.Println("ok   the default route is restored")
	}

	if fail {
		fmt.Println("RESULT: FAILED")
		os.Exit(1)
	}
	fmt.Println("RESULT: container mode works")
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
