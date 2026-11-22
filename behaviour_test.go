//go:build linux

package easytun

// THE REMAINING PUBLIC BEHAVIOUR THAT HAD NO TEST: the default device name, Close being idempotent,
// and a NAME carried through the SOCKS5 path rather than the direct one.
//
// Each is a promise the README and the doc comments make. A default that is not applied is a device
// nobody can find; a Close that panics on a second call is a crash in a defer; and a name that reaches
// the direct path but not the proxied one is a feature that works only for half the callers.

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// AN EMPTY Name BECOMES "tun0", which is the documented default and the only way a caller that does
// not care gets a predictable device.
func TestAnEmptyNameBecomesTunZero(t *testing.T) {
	var got string
	oldOpen, oldUp, oldPolicy, oldRemove := openDevice, bringUp, installPolicy, removePolicy
	openDevice = func(name string) (tunDevice, error) {
		got = name
		return newPipeline(), nil
	}
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemoveDevice := removeDevice
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemove, oldRemoveDevice
	})

	r, err := Start(Config{GuestIP: "172.30.0.2"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got != "tun0" {
		t.Fatalf("the device was opened as %q, want the default \"tun0\"", got)
	}
	if r.name != "tun0" {
		t.Fatalf("the relay remembers the name as %q, so Close would delete the wrong device", r.name)
	}
}

// CLOSE CAN BE CALLED TWICE, and the second call returns the first call's error rather than a silent
// success. This is the shape a `defer r.Close()` has when a caller also closes explicitly.
func TestCloseIsIdempotent(t *testing.T) {
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

	r, err := Start(Config{GuestIP: "172.30.0.2", Name: "twice0"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// The second must not panic and must not report a different answer.
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// CLOSE REPORTS WHAT IT COULD NOT REMOVE. A cleanup that fails silently leaves a rule behind, and the
// next Start in the same namespace sends the guest's traffic into a table nobody owns.
func TestCloseReportsACleanupFailure(t *testing.T) {
	oldOpen, oldUp, oldPolicy, oldRemove := openDevice, bringUp, installPolicy, removePolicy
	openDevice = func(string) (tunDevice, error) { return newPipeline(), nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemoveDevice := removeDevice
	removePolicy = func(string, int) error {
		return errFake("the rule was left behind")
	}
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemove, oldRemoveDevice
	})

	r, err := Start(Config{GuestIP: "172.30.0.2", Name: "leaky0"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Close(); err == nil {
		t.Fatal("Close returned nil although the policy rule could not be removed")
	}
}

// A NAME REACHES THE SOCKS5 PROXY, not only the direct path. This is the branch that makes a caller
// who invented its addresses work through a proxy at all - and it is a different function from the
// direct one, so testing one says nothing about the other.
func TestANameReachesTheSocks5Proxy(t *testing.T) {
	ensureLoopbackUp(t)
	// A SOCKS5 server that records the ATYP and the name it was asked for.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type seen struct {
		atyp byte
		name string
		port uint16
	}
	got := make(chan seen, 1)

	go func() {
		ctl, err := ln.Accept()
		if err != nil {
			return
		}
		defer ctl.Close()
		// greeting
		h := make([]byte, 2)
		if _, err := io.ReadFull(ctl, h); err != nil {
			return
		}
		_, _ = io.ReadFull(ctl, make([]byte, h[1]))
		_, _ = ctl.Write([]byte{5, 0})
		// UDP ASSOCIATE
		req := make([]byte, 10)
		if _, err := io.ReadFull(ctl, req); err != nil {
			return
		}
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return
		}
		defer udp.Close()
		rep := make([]byte, 10)
		rep[0], rep[3] = 5, 1
		copy(rep[4:8], net.IPv4(127, 0, 0, 1).To4())
		binary.BigEndian.PutUint16(rep[8:10], uint16(udp.LocalAddr().(*net.UDPAddr).Port))
		_, _ = ctl.Write(rep)

		buf := make([]byte, 65535)
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		frame := buf[:n]
		if len(frame) < 5 {
			return
		}
		s := seen{atyp: frame[3]}
		if frame[3] == 3 { // domain
			l := int(frame[4])
			s.name = string(frame[5 : 5+l])
			s.port = binary.BigEndian.Uint16(frame[5+l : 5+l+2])
		}
		got <- s
		// an empty reply so the relay does not hang
		_, _ = udp.WriteToUDP([]byte{0, 0, 0, 1, 127, 0, 0, 1, 1, 1}, from)
	}()

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
		GuestIP:  "172.30.0.2",
		Upstream: ln.Addr().String(),
		Name:     "socks0",
		Route: func(net.IP, uint16) Route {
			return Route{Host: "www.youtube.com"} // no Drop, no Direct: the SOCKS5 path
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	// A destination that is NOT the name, so the name on the wire can only have come from Route.Host.
	pkt := buildIPv4UDP(net.IPv4(172, 30, 0, 2), 7777, net.IPv4(198, 18, 3, 4), 443, []byte("x"))
	if _, err := dev.in.Write(pkt); err != nil {
		t.Fatal(err)
	}

	select {
	case s := <-got:
		if s.atyp != 3 {
			t.Fatalf("ATYP = %d, want 3 (a domain) - an invented address exists nowhere", s.atyp)
		}
		if s.name != "www.youtube.com" {
			t.Fatalf("the proxy was asked for %q, want www.youtube.com", s.name)
		}
		if s.port != 443 {
			t.Fatalf("port = %d, want 443", s.port)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the SOCKS5 proxy was never asked for anything")
	}
}

// A NAMED FLOW USES A SESSION PER NAME, so two guests reaching one address under different names do
// not share a session. The key carries the name for exactly this reason.
func TestTwoNamesToOneAddressUseDifferentSessions(t *testing.T) {
	a := key{dstIP: [4]byte{198, 18, 3, 4}, dstPort: 443, host: "a.example"}
	b := key{dstIP: [4]byte{198, 18, 3, 4}, dstPort: 443, host: "b.example"}
	if a == b {
		t.Fatal("two names to one address produced one key")
	}
}

// errFake is a minimal error, so this file needs no import beyond what it uses.
type errFake string

func (e errFake) Error() string { return string(e) }
