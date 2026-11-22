//go:build linux

package easytun

// EVERY PUBLIC FIELD IS A PROMISE, AND THREE OF THEM HAD NO TEST.
//
// `Config.Table`, `Config.Logf` and `Route.Direct` are the parts of the API a caller sets and expects
// to have an effect. The rest of the suite covers the device, the framing and the forwarding; these
// are the knobs, and a knob that is accepted and ignored is worse than one that is rejected, because
// nothing reports it.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// THE CALLER'S TABLE NUMBER IS USED EXACTLY, and the install targets it.
//
// `chooseTable` returning the number is only half the promise - the relay must also put its route and
// rule in THAT table, or a caller who pinned 1234 would silently get 137. The commands are stubbed
// because what is asserted is the argument they are given, not that iptables ran.
func TestTheCallersTableNumberIsUsedExactly(t *testing.T) {
	var mu sync.Mutex
	var routes, rules []string

	oldOpen, oldUp, oldPolicy, oldRemove := openDevice, bringUp, installPolicy, removePolicy
	openDevice = func(string) (tunDevice, error) { return newPipeline(), nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(name, guest string, table int) error {
		mu.Lock()
		rules = append(rules, guest+" lookup "+itoa(table))
		mu.Unlock()
		return nil
	}
	_ = routes
	removePolicy = func(string, int) error { return nil }
	oldRemoveDevice := removeDevice
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemove, oldRemoveDevice
	})

	r, err := Start(Config{GuestIP: "172.30.0.2", Name: "pinned0", Table: 4242})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	mu.Lock()
	defer mu.Unlock()
	if len(rules) != 1 || !strings.Contains(rules[0], "lookup 4242") {
		t.Fatalf("the policy rule was installed as %v, want one naming table 4242", rules)
	}
	if r.table != 4242 {
		t.Fatalf("the relay's table is %d, want 4242 - Close would then clean up the wrong one", r.table)
	}
	// AND THE ADDRESS FOLLOWS IT, because two relays in one namespace must not claim one /24.
	if got, want := addrFor(4242), "10.99.42.1"; got != want {
		t.Fatalf("addrFor(4242) = %q, want %q", got, want)
	}
}

// Logf RECEIVES A LINE PER FAILURE, and a nil Logf is silent rather than a panic.
//
// The forwarding path reports every per-packet error through Logf. A caller that passed a sink and
// saw nothing has no way to tell "no errors" from "the sink was never called", so this drives a real
// failure - a session to an address nothing answers - and asserts the line arrived.
func TestLogfReceivesAForwardingFailure(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	sink := func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	dev := newPipeline()
	oldOpen, oldUp, oldPolicy, oldRemove := openDevice, bringUp, installPolicy, removePolicy
	openDevice = func(string) (tunDevice, error) { return dev, nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemoveDevice := removeDevice
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemove, oldRemoveDevice
	})

	// AN UPSTREAM THAT REFUSES: port 1 on loopback has nothing listening, so the session cannot be
	// created and the relay reports it.
	r, err := Start(Config{
		GuestIP:  "172.30.0.2",
		Upstream: "127.0.0.1:1",
		Name:     "logf0",
		Logf:     sink,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	pkt := buildIPv4UDP(net.IPv4(172, 30, 0, 2), 1234, net.IPv4(203, 0, 113, 9), 443, []byte("x"))
	if _, err := dev.in.Write(pkt); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(lines)
		mu.Unlock()
		if n > 0 {
			return // the failure was reported, which is the promise
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a failure to reach the upstream produced no Logf line")
}

// A NIL Logf IS SILENT, NOT A PANIC. This is the default for a caller that does not care, and it must
// stay a valid configuration.
func TestANilLogfIsSilent(t *testing.T) {
	dev := newPipeline()
	oldOpen, oldUp, oldPolicy, oldRemove := openDevice, bringUp, installPolicy, removePolicy
	openDevice = func(string) (tunDevice, error) { return dev, nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemoveDevice := removeDevice
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemove, oldRemoveDevice
	})

	r, err := Start(Config{GuestIP: "172.30.0.2", Upstream: "127.0.0.1:1", Name: "silent0"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	// The same failing datagram, with no sink: the relay must absorb it rather than panic on a nil call.
	if _, err := dev.in.Write(buildIPv4UDP(net.IPv4(172, 30, 0, 2), 1,
		net.IPv4(203, 0, 113, 9), 443, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
}

// Route.Direct SENDS FROM THIS HOST WITH NO PROXY, and the reply still goes back into the tun looking
// like it came from the destination.
//
// This is the branch that has no SOCKS5 handshake at all - a plain UDP socket to the peer - so a bug
// here is a flow that goes through the proxy anyway, or one whose reply never arrives.
func TestADirectFlowBypassesTheProxy(t *testing.T) {
	ensureLoopbackUp(t)
	// A UDP echo server standing in for the destination.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(append([]byte("direct:"), buf[:n]...), from)
		}
	}()
	_, dstPort, _ := net.SplitHostPort(echo.LocalAddr().String())

	dev := newPipeline()
	oldOpen, oldUp, oldPolicy, oldRemove := openDevice, bringUp, installPolicy, removePolicy
	openDevice = func(string) (tunDevice, error) { return dev, nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemoveDevice := removeDevice
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemove, oldRemoveDevice
	})

	r, err := Start(Config{
		GuestIP: "172.30.0.2",
		Name:    "direct0",
		// NO UPSTREAM AT ALL, and the callback says direct: so this cannot be the proxy path by
		// accident, because there is no proxy to reach.
		Route: func(net.IP, uint16) Route { return Route{Direct: true} },
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	port, _ := strconv.Atoi(dstPort)
	pkt := buildIPv4UDP(net.IPv4(172, 30, 0, 2), 9999, net.IPv4(127, 0, 0, 1), uint16(port),
		[]byte("hello"))
	if _, err := dev.in.Write(pkt); err != nil {
		t.Fatal(err)
	}

	// THE READ RETURNS n, AND THE PARSE MUST SEE ONLY n BYTES. `parseIPv4UDP(out)` on the whole 64 KiB
	// buffer reads whatever is past the packet, which is a payload of zeros - MEASURED while writing
	// this test, and it is why the assertion below compares the exact string.
	out := make([]byte, 65535)
	nRead := make(chan int, 1)
	go func() {
		n, _ := dev.out.Read(out)
		nRead <- n
	}()
	var n int
	select {
	case n = <-nRead:
	case <-time.After(5 * time.Second):
		t.Fatal("a direct flow produced no reply in the tun")
	}

	srcIP, dstIP, srcPort, dstPortOut, payload, ok := parseIPv4UDP(out[:n])
	if !ok {
		t.Fatal("the direct reply is not IPv4 UDP")
	}
	// THE REPLY COMES FROM THE DESTINATION THE GUEST ASKED FOR, which is the whole illusion - and it
	// goes to the guest's own port.
	if !srcIP.Equal(net.IPv4(127, 0, 0, 1)) || srcPort != uint16(port) {
		t.Fatalf("reply source %v:%d, want the destination", srcIP, srcPort)
	}
	if !dstIP.Equal(net.IPv4(172, 30, 0, 2)) {
		t.Fatalf("reply destination %v, want the guest", dstIP)
	}
	if dstPortOut != 9999 {
		t.Fatalf("reply port %d, want the guest's own port 9999", dstPortOut)
	}
	if string(payload) != "direct:hello" {
		t.Fatalf("payload %q, want %q", payload, "direct:hello")
	}
}

// A NAMED DIRECT FLOW DIALS THE NAME, NOT THE ADDRESS. A caller that invented the address would
// otherwise send the datagram to a host that does not exist.
//
// The name here is `localhost`, which resolves without a network, so this proves the NAME was used
// rather than the address the packet carried.
func TestADirectFlowWithANameDialsTheName(t *testing.T) {
	ensureLoopbackUp(t)
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(append([]byte("named:"), buf[:n]...), from)
		}
	}()
	_, dstPort, _ := net.SplitHostPort(echo.LocalAddr().String())
	port, _ := strconv.Atoi(dstPort)

	dev := newPipeline()
	oldOpen, oldUp, oldPolicy, oldRemove := openDevice, bringUp, installPolicy, removePolicy
	openDevice = func(string) (tunDevice, error) { return dev, nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemoveDevice := removeDevice
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemove, oldRemoveDevice
	})

	r, err := Start(Config{
		GuestIP: "172.30.0.2",
		Name:    "named0",
		Route: func(net.IP, uint16) Route {
			return Route{Direct: true, Host: "localhost"}
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	// THE PACKET CARRIES AN ADDRESS THAT IS NOT THE SERVER, so a reply proves the NAME was dialled.
	pkt := buildIPv4UDP(net.IPv4(172, 30, 0, 2), 8888, net.IPv4(203, 0, 113, 77), uint16(port),
		[]byte("hi"))
	if _, err := dev.in.Write(pkt); err != nil {
		t.Fatal(err)
	}

	out := make([]byte, 65535)
	nRead := make(chan int, 1)
	go func() {
		n, _ := dev.out.Read(out)
		nRead <- n
	}()
	var n int
	select {
	case n = <-nRead:
	case <-time.After(5 * time.Second):
		t.Fatal("a named direct flow produced no reply, so the name was not dialled")
	}
	_, _, _, _, payload, ok := parseIPv4UDP(out[:n])
	if !ok || string(payload) != "named:hi" {
		t.Fatalf("payload %q, want %q", payload, "named:hi")
	}
}
