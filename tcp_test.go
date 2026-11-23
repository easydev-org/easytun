//go:build linux

package easytun

// THE TCP TRANSPARENT PROXY, TESTED THROUGH ITS TWO SEAMS.
//
// `Tunnel` takes the destination rather than reading it, so everything except `SO_ORIGINAL_DST` can be
// driven without a redirected socket - and the handshake, the refusals and the copy loop are the parts
// that go wrong. A fake HTTP CONNECT proxy records what it was asked for; a fake origin records what
// it received.

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// connectProxy is an HTTP CONNECT proxy that records the request line and then relays to the real
// destination, so a test proves the tunnel carries bytes rather than only that a line was sent.
type connectProxy struct {
	ln   net.Listener
	reqs chan string
}

func startConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	ensureLoopbackUp(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &connectProxy{ln: ln, reqs: make(chan string, 4)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *connectProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" || l == "\n" {
			break
		}
	}
	p.reqs <- strings.TrimSpace(line)

	// DRAIN ANY BYTES THE CALLER SENT BEHIND THE HEADERS, then answer 200 and echo what arrives - a
	// tunnel that dropped the payload would still pass a test that only checked the request line.
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\nProxy-Agent: fake\r\n\r\n"))
	_, _ = io.Copy(c, br)
}

// origin is a plain TCP server that answers with a fixed line.
func startOrigin(t *testing.T, greeting string) string {
	t.Helper()
	ensureLoopbackUp(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(greeting))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// throughTunnel runs one Tunnel call with a pipe and returns what the client saw.
func throughTunnel(t *testing.T, p *TCP, dst string, send string) string {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan string, 1)
	go func() {
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 128)
		n, _ := client.Read(buf)
		done <- string(buf[:n])
	}()
	go p.Tunnel(server, dst)
	if send != "" {
		go func() {
			time.Sleep(50 * time.Millisecond)
			_, _ = client.Write([]byte(send))
		}()
	}
	select {
	case got := <-done:
		return got
	case <-time.After(4 * time.Second):
		return "<timeout>"
	}
}

// THE CONNECT LINE NAMES THE DESTINATION THE CLIENT THOUGHT IT WAS REACHING, and the bytes on both
// sides of the tunnel survive.
func TestTheTunnelSpeaksConnectAndCarriesBytes(t *testing.T) {
	proxy := startConnectProxy(t)
	p := &TCP{Upstream: proxy.ln.Addr().String()}

	client, server := net.Pipe()
	defer client.Close()
	go p.Tunnel(server, "pkg.example.org:443")
	go func() {
		time.Sleep(60 * time.Millisecond)
		_, _ = client.Write([]byte("HELLO"))
	}()

	select {
	case got := <-proxy.reqs:
		if !strings.HasPrefix(got, "CONNECT pkg.example.org:443 ") {
			t.Fatalf("the proxy was asked for %q; it must name the ORIGINAL destination", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the fake proxy never saw a request")
	}

	// AND THE BYTES CAME BACK, which proves the copy loop rather than only the handshake.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != "HELLO" {
		t.Fatalf("the tunnel delivered %q, err=%v - the copy loop dropped the client's bytes", buf[:n], err)
	}
}

// A REFUSED CONNECT DELIVERS NOTHING. A 403 or 502 is the proxy's sentence about the request, not data
// for the client - forwarding it would put `HTTP/1.1 502` at the front of a TLS stream.
func TestARefusedConnectDeliversNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				_, _ = br.ReadString('\n')
				_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
				_, _ = io.Copy(io.Discard, br)
			}(c)
		}
	}()

	p := &TCP{Upstream: ln.Addr().String()}
	if got := throughTunnel(t, p, "blocked.example:443", ""); got != "" {
		t.Fatalf("the client received %q from a refused CONNECT", got)
	}
}

// A DIRECT RULE REACHES THE DESTINATION WITH NO PROXY, and the reply comes back.
//
// THIS IS THE BRANCH WITH NO HANDSHAKE AT ALL, so a bug here is a connection that goes through the
// proxy anyway - or one whose reply never arrives because the copy loop returned too early.
func TestADirectRuleReachesTheDestination(t *testing.T) {
	origin := startOrigin(t, "DIRECT-OK")

	p := &TCP{route: func(net.IP, uint16) Route { return Route{Kind: RouteDirect} }}
	if got := throughTunnel(t, p, origin, ""); got != "DIRECT-OK" {
		t.Fatalf("a direct connection delivered %q, want DIRECT-OK", got)
	}
}

// A DROPPED CONNECTION DELIVERS NOTHING AND DOES NOT DIAL, which is what closing looks like.
func TestADroppedConnectionDeliversNothing(t *testing.T) {
	p := &TCP{route: func(net.IP, uint16) Route { return Route{Kind: RouteDrop} }}
	if got := throughTunnel(t, p, "203.0.113.9:443", ""); got != "" {
		t.Fatalf("a dropped connection delivered %q", got)
	}
}

// A NAMED UPSTREAM IS THE ONE DIALLED, so a rule can send a destination to a different proxy.
func TestANamedUpstreamIsTheOneDialled(t *testing.T) {
	first := startConnectProxy(t)
	second := startConnectProxy(t)

	p := &TCP{
		Upstream: first.ln.Addr().String(),
		route: func(net.IP, uint16) Route {
			return Route{Upstream: second.ln.Addr().String()}
		},
	}
	client, server := net.Pipe()
	defer client.Close()
	go p.Tunnel(server, "special.example:443")

	select {
	case <-second.reqs:
		// correct: the rule's upstream carried it
	case <-first.reqs:
		t.Fatal("the default proxy carried a connection a rule sent elsewhere")
	case <-time.After(3 * time.Second):
		t.Fatal("neither proxy saw the request")
	}
}

// NO UPSTREAM AND NO RULE IS A DIRECT CONNECTION, which is the configuration a machine with no proxy
// has - and it must not be an error.
func TestNoUpstreamMeansDirect(t *testing.T) {
	origin := startOrigin(t, "NO-PROXY")
	p := &TCP{}
	if got := throughTunnel(t, p, origin, ""); got != "NO-PROXY" {
		t.Fatalf("with no upstream, the tunnel delivered %q", got)
	}
}

// AN UNRESOLVABLE UPSTREAM IS REFUSED AT START, with a sentence, rather than on the first connection.
func TestStartTCPRefusesABadUpstream(t *testing.T) {
	for _, up := range []string{"nonsense", "host:notaport", "no-such-host.invalid:7890"} {
		if _, err := StartTCP(TCPConfig{Bind: "127.0.0.1:0", Upstream: up}); err == nil {
			t.Errorf("StartTCP accepted upstream %q", up)
		}
	}
}

// AN EMPTY Bind IS "NO PROXY", which returns nil rather than an error - the caller's equivalent of a
// machine with no proxy at all.
func TestStartTCPWithNoBindIsNil(t *testing.T) {
	p, err := StartTCP(TCPConfig{})
	if err != nil {
		t.Fatalf("StartTCP: %v", err)
	}
	if p != nil {
		t.Fatal("StartTCP returned a listener for an empty bind")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close on a nil listener: %v", err)
	}
}

// A REAL LISTENER REPORTS ITS PORT, which is what the caller writes into its redirect rule.
func TestStartTCPReportsItsPort(t *testing.T) {
	ensureLoopbackUp(t)
	p, err := StartTCP(TCPConfig{Bind: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("StartTCP: %v", err)
	}
	defer func() { _ = p.Close() }()
	if p.Port == 0 {
		t.Fatal("StartTCP did not report a port, so no redirect rule could name it")
	}
	// AND IT ACCEPTS: a connection to that port is handled rather than refused.
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(p.Port)), time.Second)
	if err != nil {
		t.Fatalf("connecting to the reported port: %v", err)
	}
	_ = c.Close()
}
