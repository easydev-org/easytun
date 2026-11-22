// THE EGRESS DRIVER: PROVE THAT EACH DESTINATION TOOK THE PATH ITS RULE CHOSE.
//
// IT RUNS IN A CONTAINER WITH `--device /dev/net/tun --cap-add NET_ADMIN`, starts a relay with a
// REAL tun device, and sends one datagram to each of four destinations. The rule for each names a
// different path, so DIFFERENT TAGS COMING BACK IS THE PROOF - and the exit status is the assertion,
// which means a routing bug fails the job rather than being noticed in a log later.
//
//	203.0.113.10  proxy:primary   reply must be tagged "A:"
//	203.0.113.20  proxy:backup    reply must be tagged "B:"
//	203.0.113.30  direct          the destination itself answers, tagged "D:"
//	203.0.113.40  drop            NOTHING comes back
//	203.0.113.50  by PORT         :8443 to backup, :443 to the default - the same address, two paths
//
// THE ADDRESSES ARE TEST-NET-3 (RFC 5737), reserved for documentation and guaranteed not to be a real
// host, so a datagram to one cannot accidentally succeed through some other route. The DIRECT
// destination is the exception: it is a local echo server, because "direct" means the datagram leaves
// this host for a real peer, and a TEST-NET address has no peer to answer.
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

const guestIP = "172.30.0.2"

func main() {
	primary := env("PRIMARY_ADDR", "")
	backup := env("BACKUP_ADDR", "")
	if primary == "" || backup == "" {
		fail("PRIMARY_ADDR and BACKUP_ADDR are both required")
	}

	// THE DIRECT DESTINATION: a loopback echo server that tags its replies "D:". It stands in for a
	// real peer, because a direct flow must leave the host to reach one.
	directAddr, stopEcho := startEcho("D")
	defer stopEcho()
	directHost, directPortStr, _ := net.SplitHostPort(directAddr)
	directPort := mustPort(directPortStr)

	// THE RESOLVER IS NOT INVOLVED: every destination is a literal address, so this test is about the
	// PATH and nothing else. Name rules have their own tests.
	r, err := easytun.Start(easytun.Config{
		GuestIP:  guestIP,
		Upstream: primary, // the default is primary, so backup and the others are the interesting cases
		Name:     "egress0",
		Route: func(dst net.IP, port uint16) easytun.Route {
			switch dst.String() {
			case "203.0.113.20":
				return easytun.Route{Upstream: backup}
			case "203.0.113.30", directHost:
				return easytun.Route{Direct: true}
			case "203.0.113.40":
				return easytun.Route{Drop: true}
			case "203.0.113.50":
				if port == 8443 {
					return easytun.Route{Upstream: backup}
				}
			}
			return easytun.Route{}
		},
		Logf: func(format string, args ...any) {
			fmt.Printf("relay: "+format+"\n", args...)
		},
	})
	if err != nil {
		fail("starting the relay: %v", err)
	}
	defer func() { _ = r.Close() }()

	// THE GUEST'S ADDRESS HAS TO EXIST BEFORE A SOCKET CAN USE IT AS A SOURCE.
	//
	// The policy rule in the relay matches `from <guest> ipproto udp`, so the test's socket must be
	// bound to the guest's address - a socket from any other source would bypass the rule entirely.
	// MEASURED on the first container run: without this line, `bind: cannot assign requested address`,
	// because a fresh container namespace has no 172.30.0.2 on any interface.
	//
	// IT GOES ON `lo`, which is enough: the datagram is routed by the relay's policy rule before it
	// ever reaches an interface, so where the address lives does not matter - only that it is local.
	// `lo` MUST BE UP BEFORE AN ADDRESS ON IT IS USABLE. A fresh container namespace usually has it
	// up already, but not always, and an address on a down interface accepts a bind and drops packets.
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		fail("raising lo: %v (%s)", err, out)
	}
	if out, err := exec.Command("ip", "addr", "add", guestIP+"/32", "dev", "lo").CombinedOutput(); err != nil {
		// ALREADY PRESENT IS FINE: `Up` may have added it, or a previous run in this namespace.
		if !strings.Contains(string(out), "File exists") {
			fail("putting %s on lo: %v (%s)", guestIP, err, out)
		}
	}

	// THE GUEST SOCKET. Its source address is the guest's, because the policy rule in the relay sends
	// only THAT guest's UDP into the tun - a socket from any other address would bypass it.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(guestIP), Port: 0})
	if err != nil {
		fail("binding the guest socket to %s: %v", guestIP, err)
	}
	defer conn.Close()

	ok := true
	check := func(name string, dst net.IP, port uint16, want string) {
		got := ask(conn, dst, port, 3*time.Second)
		if got != want {
			fmt.Printf("FAIL %-18s %s:%d -> %q, want %q\n", name, dst, port, got, want)
			ok = false
			return
		}
		fmt.Printf("ok   %-18s %s:%d -> %q\n", name, dst, port, got)
	}
	silent := func(name string, dst net.IP, port uint16) {
		got := ask(conn, dst, port, 800*time.Millisecond)
		if got != "" {
			fmt.Printf("FAIL %-18s %s:%d -> %q, want silence\n", name, dst, port, got)
			ok = false
			return
		}
		fmt.Printf("ok   %-18s %s:%d -> (silence)\n", name, dst, port)
	}

	check("proxy:primary", net.ParseIP("203.0.113.10"), 443, "A:ping")
	check("proxy:backup", net.ParseIP("203.0.113.20"), 443, "B:ping")
	check("direct", net.ParseIP(directHost), directPort, "D:ping")
	silent("drop", net.ParseIP("203.0.113.40"), 443)
	check("by port 8443", net.ParseIP("203.0.113.50"), 8443, "B:ping")
	// THE CROSS-CHECK: the same address on 443 must take the DEFAULT, so a rule that ignored the port
	// would answer B here too and fail.
	check("by port 443", net.ParseIP("203.0.113.50"), 443, "A:ping")

	if !ok {
		fail("one or more destinations did not take the path the rule chose")
	}
	fmt.Println("all six outcomes took the path the rules chose")
}

// ask sends one datagram and waits for a reply addressed to this flow.
func ask(conn *net.UDPConn, dst net.IP, port uint16, wait time.Duration) string {
	if _, err := conn.WriteToUDP([]byte("ping"), &net.UDPAddr{IP: dst, Port: int(port)}); err != nil {
		return "<write failed: " + err.Error() + ">"
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

// startEcho answers every datagram with "<tag>:<payload>", standing in for a direct destination.
func startEcho(tag string) (string, func()) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fail("the echo server: %v", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP(append([]byte(tag+":"), buf[:n]...), from)
		}
	}()
	return c.LocalAddr().String(), func() { _ = c.Close() }
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func mustPort(s string) uint16 {
	var n uint16
	for _, c := range s {
		if c < '0' || c > '9' {
			fail("not a port: %q", s)
		}
		n = n*10 + uint16(c-'0')
	}
	return n
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
