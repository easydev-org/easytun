//go:build linux

package easytun

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// THE WHOLE RELAY, DRIVEN WITH A PIPE INSTEAD OF A TUN.
//
// This is the test that would otherwise need NET_ADMIN and a mounted /dev/net/tun, which means it
// would be a test nobody runs. Everything below the `tunDevice` interface is real: the session table,
// the SOCKS5 handshake, the framing, the reply that is rebuilt into a packet. The stand-in for the
// proxy is a real SOCKS5 UDP-associate server in this process, not a mock, so the handshake and the
// framing are exercised as a proxy would exercise them.
//
// WHAT IS NOT COVERED, STATED RATHER THAN IMPLIED: the real kernel device, the ioctl, and the policy
// routing commands. Those are asserted by TestOpenTunAsksForNoProtocolInfo and the chooseTable tests,
// and their kernel half is what a CI cointainer with the capability provides.

type pipeline struct {
	in  *io.PipeWriter // test writes packets here; the relay reads them
	out *io.PipeReader // the relay writes replies here; the test reads them
	r   *io.PipeReader
	w   *io.PipeWriter
}

func newPipeline() *pipeline {
	// The relay reads from `r` and writes to `w`. The test holds the other ends.
	r, in := io.Pipe()
	out, w := io.Pipe()
	return &pipeline{in: in, out: out, r: r, w: w}
}

func (p *pipeline) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeline) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeline) Close() error {
	_ = p.in.Close()
	_ = p.w.Close()
	return nil
}

// socksUDPEcho is a SOCKS5 server that speaks just enough for UDP ASSOCIATE: no-auth, an associate
// reply, then it unwraps each datagram, sends it to the destination, and frames the reply back.
type socksUDPEcho struct {
	ln   net.Listener
	mu   sync.Mutex
	ctrl []net.Conn
	done chan struct{}
}

func startSocksUDPEcho(t *testing.T) *socksUDPEcho {
	t.Helper()
	ensureLoopbackUp(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksUDPEcho{ln: ln, done: make(chan struct{})}
	go s.serve()
	t.Cleanup(func() {
		close(s.done)
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.ctrl {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	return s
}

func (s *socksUDPEcho) addr() string { return s.ln.Addr().String() }

func (s *socksUDPEcho) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.ctrl = append(s.ctrl, c)
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *socksUDPEcho) handle(c net.Conn) {
	defer c.Close()
	// greeting: VER NMETHODS METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil { // no auth
		return
	}
	// request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 3 { // only UDP ASSOCIATE
		return
	}
	// Read the address and port that follow, size by ATYP.
	switch req[3] {
	case 1:
		_, _ = io.ReadFull(c, make([]byte, 4))
	case 4:
		_, _ = io.ReadFull(c, make([]byte, 16))
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		_, _ = io.ReadFull(c, make([]byte, int(l[0])))
	}
	_, _ = io.ReadFull(c, make([]byte, 2)) // port

	// The UDP socket replies from an ephemeral port; the address in the reply is 127.0.0.1 so the
	// relay dials it rather than treating it as "unspecified".
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return
	}
	defer udp.Close()

	reply := make([]byte, 10)
	reply[0], reply[1], reply[3] = 5, 0, 1
	copy(reply[4:8], net.IPv4(127, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(udp.LocalAddr().(*net.UDPAddr).Port))
	if _, err := c.Write(reply); err != nil {
		return
	}

	buf := make([]byte, 65535)
	for {
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		dstIP, dstPort, payload, ok := socksUDPReply(buf[:n])
		if !ok {
			continue
		}
		// A real proxy forwards to the destination; here the "destination" is answered locally with
		// the payload echoed back, which proves the frame arrived and is addressable.
		echo := append([]byte("echo:"), payload...)
		back := socksUDPRequest([4]byte{dstIP.To4()[0], dstIP.To4()[1], dstIP.To4()[2], dstIP.To4()[3]},
			dstPort, echo)
		_, _ = udp.WriteToUDP(back, from)
	}
}

// THE FULL FORWARDING PATH: a guest datagram goes in the tun, through SOCKS5 UDP ASSOCIATE, and comes
// back into the tun looking like it came from the destination the guest asked for.
func TestTheRelayForwardsADatagramAndRewritesTheReply(t *testing.T) {
	proxy := startSocksUDPEcho(t)

	dev := newPipeline()
	oldOpen, oldUp, oldPolicy := openDevice, bringUp, installPolicy
	openDevice = func(string) (tunDevice, error) { return dev, nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemovePolicy, oldRemoveDevice := removePolicy, removeDevice
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemovePolicy, oldRemoveDevice
	})

	guest := "172.30.0.2"
	r, err := Start(Config{GuestIP: guest, Upstream: proxy.addr(), Name: "test0"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Close()

	// THE GUEST'S DATAGRAM: 172.30.0.2:51234 -> 104.18.27.14:443
	pkt := buildIPv4UDP(net.IPv4(172, 30, 0, 2), 51234, net.IPv4(104, 18, 27, 14), 443,
		[]byte("quic"))
	if _, err := dev.in.Write(pkt); err != nil {
		t.Fatalf("writing the guest's datagram: %v", err)
	}

	// THE REPLY, READ OUT OF THE tun.
	buf := make([]byte, 65535)

	type read struct {
		n   int
		err error
	}
	got := make(chan read, 1)
	go func() {
		n, err := dev.out.Read(buf)
		got <- read{n, err}
	}()

	select {
	case res := <-got:
		if res.err != nil {
			t.Fatalf("reading the reply: %v", res.err)
		}
		srcIP, dstIP, srcPort, dstPort, payload, ok := parseIPv4UDP(buf[:res.n])
		if !ok {
			t.Fatal("the relay wrote a packet that is not IPv4 UDP")
		}
		// THE ILLUSION: the reply appears to come from where the guest sent it, and goes to the
		// guest's own port. A reply from 10.99.x.1 would be discarded by the guest's stack.
		if !srcIP.Equal(net.IPv4(104, 18, 27, 14)) || srcPort != 443 {
			t.Fatalf("reply source %v:%d, want 104.18.27.14:443", srcIP, srcPort)
		}
		if !dstIP.Equal(net.IPv4(172, 30, 0, 2)) || dstPort != 51234 {
			t.Fatalf("reply destination %v:%d, want 172.30.0.2:51234", dstIP, dstPort)
		}
		if string(payload) != "echo:quic" {
			t.Fatalf("payload %q, want %q", payload, "echo:quic")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no reply arrived through the relay within 5s")
	}
}

// A CALLBACK THAT DROPS A FLOW SENDS NOTHING, and the guest sees exactly what a filtered UDP port
// looks like: silence.
func TestADroppedFlowSendsNothing(t *testing.T) {
	proxy := startSocksUDPEcho(t)
	dev := newPipeline()
	oldOpen, oldUp, oldPolicy := openDevice, bringUp, installPolicy
	openDevice = func(string) (tunDevice, error) { return dev, nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	oldRemovePolicy, oldRemoveDevice := removePolicy, removeDevice
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemovePolicy, oldRemoveDevice
	})

	r, err := Start(Config{
		GuestIP:  "172.30.0.2",
		Upstream: proxy.addr(),
		Name:     "test1",
		Route:    func(net.IP, uint16) Route { return Route{Drop: true} },
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Close()

	pkt := buildIPv4UDP(net.IPv4(172, 30, 0, 2), 1111, net.IPv4(8, 8, 8, 8), 53, []byte("q"))
	if _, err := dev.in.Write(pkt); err != nil {
		t.Fatal(err)
	}

	// Nothing must come back. A short deadline is enough because the drop is synchronous.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		_, _ = dev.out.Read(buf)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a dropped flow produced a packet in the tun")
	case <-time.After(300 * time.Millisecond):
		// correct: silence
	}
}

// --- an egress fixture: two proxies that say WHICH one carried a datagram -------------
//
// PROVING A ROUTE IS NOT PROVING A CONNECTION. `proxy` and `direct` both succeed, so a passing check
// says nothing about which path was taken. The only way to tell them apart from outside is to have
// each upstream TAG what it carried - which is what this fixture does: it answers with its own name,
// so the payload that arrives back at the guest is the evidence.

// tagProxy is a SOCKS5 UDP server that prefixes every reply with its own tag.
type tagProxy struct {
	*socksUDPEcho
	tag string
}

// startTagProxy is startSocksUDPEcho with the echo replaced by "<tag>:<payload>".
func startTagProxy(t *testing.T, tag string) *tagProxy {
	t.Helper()
	p := &tagProxy{tag: tag}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ensureLoopbackUp(t)
	p.socksUDPEcho = &socksUDPEcho{ln: ln, done: make(chan struct{})}
	go p.serveTagged()
	t.Cleanup(func() {
		close(p.done)
		_ = ln.Close()
	})
	return p
}

func (p *tagProxy) serveTagged() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleTagged(c)
	}
}

func (p *tagProxy) handleTagged(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 3 {
		return
	}
	switch req[3] {
	case 1:
		_, _ = io.ReadFull(c, make([]byte, 4))
	case 4:
		_, _ = io.ReadFull(c, make([]byte, 16))
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		_, _ = io.ReadFull(c, make([]byte, int(l[0])))
	}
	_, _ = io.ReadFull(c, make([]byte, 2))

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer udp.Close()

	rep := make([]byte, 10)
	rep[0], rep[1], rep[3] = 5, 0, 1
	copy(rep[4:8], net.IPv4(127, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(rep[8:10], uint16(udp.LocalAddr().(*net.UDPAddr).Port))
	if _, err := c.Write(rep); err != nil {
		return
	}

	buf := make([]byte, 65535)
	for {
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		dstIP, dstPort, payload, ok := socksUDPReply(buf[:n])
		if !ok {
			continue
		}
		// THE TAG IS THE EVIDENCE: it names the proxy that carried this datagram.
		body := append([]byte(p.tag+":"), payload...)
		back := socksUDPRequest([4]byte{dstIP.To4()[0], dstIP.To4()[1], dstIP.To4()[2], dstIP.To4()[3]},
			dstPort, body)
		_, _ = udp.WriteToUDP(back, from)
	}
}

// startUDPEcho answers a datagram on loopback with "<tag>:<payload>", standing in for a direct
// destination so a `Route.Direct` flow has something to reach that is not a proxy.
func startUDPEcho(t *testing.T, tag string) (addr string) {
	t.Helper()
	ensureLoopbackUp(t)
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
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
	return c.LocalAddr().String()
}

// withStubbedDevices points the relay at a pipe and skips the kernel work, restoring everything when
// the test ends.
//
// THIS IS THE SEAM THE EGRESS TESTS NEED: `openTun`, `bringUp` and `installPolicy` are variables
// precisely so a test on a machine with no device can still drive the whole forwarding path.
func withStubbedDevices(t *testing.T, dev tunDevice) {
	t.Helper()
	oldOpen, oldUp, oldPolicy, oldRemovePolicy, oldRemoveDevice :=
		openDevice, bringUp, installPolicy, removePolicy, removeDevice
	openDevice = func(string) (tunDevice, error) { return dev, nil }
	bringUp = func(string, string) error { return nil }
	installPolicy = func(string, string, int) error { return nil }
	removePolicy = func(string, int) error { return nil }
	removeDevice = func(string) error { return nil }
	t.Cleanup(func() {
		openDevice, bringUp, installPolicy = oldOpen, oldUp, oldPolicy
		removePolicy, removeDevice = oldRemovePolicy, oldRemoveDevice
	})
}

// atoi16 parses a decimal port from a SplitHostPort result.
func atoi16(s string) uint16 {
	var n uint16
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint16(c-'0')
	}
	return n
}

// A RELAY WITH NO TABLE MUST NOT FLUSH MAIN.
//
// `ip route flush table 0` FLUSHES MAIN, because table 0 IS main. The container mode builds a relay with
// no policy of its own, so its table is zero - and Close wiped the namespace's entire routing while
// reporting success. MEASURED in a pod: `ip route show table main` was empty afterwards and the container
// could reach nothing.
//
// THIS ASSERTS THE COMMAND IS NOT RUN, which is the only part a test can see without a namespace.
func TestARelayWithNoTableDoesNotFlushMain(t *testing.T) {
	var cmds []string
	oldRun := runFn
	runFn = func(name string, args ...string) (string, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return "", nil
	}
	t.Cleanup(func() { runFn = oldRun })

	for _, table := range []int{0, 100} {
		r := &Relay{table: table, guest: "172.30.0.2", ownsDevice: false, tun: newPipeline(),
			done: make(chan struct{}), sessions: map[key]*session{}}
		if err := r.Close(); err != nil {
			t.Fatalf("table %d: Close: %v", table, err)
		}
	}

	flushesMain := false
	flushesTable := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "route flush table 0") {
			flushesMain = true
		}
		if strings.Contains(cmd, "route flush table 100") {
			flushesTable = true
		}
	}
	if flushesMain {
		t.Fatalf("a relay with table 0 flushed MAIN, which is the entire namespace's routing:\n%s",
			strings.Join(cmds, "\n"))
	}
	if !flushesTable {
		t.Fatalf("a relay with a real table did not flush it, so it would leave routes behind:\n%s",
			strings.Join(cmds, "\n"))
	}
}
