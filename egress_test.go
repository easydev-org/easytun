//go:build linux

package easytun

// EGRESS ROUTING, PROVEN BY WHICH UPSTREAM ANSWERED.
//
// THIS IS THE FEATURE THE ROUTE CALLBACK EXISTS FOR, AND IT IS EASY TO TEST WRONG. `proxy:A`,
// `proxy:B` and `direct` all deliver a datagram, so a test that only asserts "something came back"
// proves nothing about which path was chosen. The evidence has to be a property of the REPLY that
// only one path can produce.
//
// SO EACH PATH TAGS ITS ANSWER: proxy A replies "A:<payload>", proxy B "B:<payload>", and a direct
// destination "D:<payload>". The tag that arrives at the guest is then the proof - and each rule is
// also cross-checked, because a bug that sent everything to A would satisfy "A answered A" and fail
// "B answered B".
//
// WHAT IS COVERED: per-destination routing to two different proxies, a different proxy chosen by
// PORT rather than address, direct, drop, and the default when no rule matches. That is the whole
// surface of `Route`.

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// replyReader is ONE goroutine that reads the tun's output for the whole test and files each reply by
// the guest port it was addressed to.
//
// A READER PER `ask` WAS WRONG, AND IT FAILED TWO ASSERTIONS BEFORE IT WAS FIXED. `Route.Drop` sends
// nothing, so a per-call reader for it blocked forever, and the NEXT call's reader never started -
// so the datagram after a dropped one got no reply and the test reported it as a routing bug. One
// reader that runs until the test ends has no such ordering problem.
type replyReader struct {
	mu     sync.Mutex
	byPort map[uint16]string
}

func startReplyReader(t *testing.T, dev *pipeline) *replyReader {
	t.Helper()
	r := &replyReader{byPort: map[uint16]string{}}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := dev.out.Read(buf)
			if err != nil {
				return
			}
			_, _, _, port, payload, ok := parseIPv4UDP(buf[:n])
			if !ok {
				continue
			}
			r.mu.Lock()
			// THE FIRST REPLY WINS, so a duplicate cannot overwrite the answer this test is about.
			if _, seen := r.byPort[port]; !seen {
				r.byPort[port] = string(payload)
			}
			r.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = dev.in.Close() })
	return r
}

// payloadFor waits until a reply for this port has arrived, or reports that none did.
func (r *replyReader) payloadFor(port uint16, wait time.Duration) string {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		p, ok := r.byPort[port]
		r.mu.Unlock()
		if ok {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ""
}

// ask sends one datagram and returns the reply filed under its guest port.
func ask(t *testing.T, dev *pipeline, reader *replyReader, srcIP net.IP, srcPort uint16,
	dst net.IP, dstPort uint16, payload string, wait time.Duration) string {
	t.Helper()
	if _, err := dev.in.Write(buildIPv4UDP(srcIP, srcPort, dst, dstPort, []byte(payload))); err != nil {
		t.Fatalf("writing into the tun: %v", err)
	}
	return reader.payloadFor(srcPort, wait)
}

// THE FOUR OUTCOMES, ONE POLICY, ONE TEST.
func TestEgressRoutesEachDestinationToItsPath(t *testing.T) {
	proxyA := startTagProxy(t, "A")
	proxyB := startTagProxy(t, "B")
	directAddr := startUDPEcho(t, "D")
	directHost, directPort, _ := net.SplitHostPort(directAddr)
	directIP := net.ParseIP(directHost)

	dev := newPipeline()
	withStubbedDevices(t, dev)
	reader := startReplyReader(t, dev)

	// THE RULES, BY ADDRESS. TEST-NET-3 (203.0.113.0/24) belongs to nothing, so a destination there
	// can only be answered by this test's own fixtures.
	const (
		toA      = "203.0.113.10"
		toB      = "203.0.113.20"
		toDirect = "203.0.113.30"
		toDrop   = "203.0.113.40"
		toPort   = "203.0.113.50"
	)
	r, err := Start(Config{
		GuestIP:  "172.30.0.2",
		Upstream: proxyA.addr(), // the default is A, so B and the others are the interesting cases
		Name:     "egress0",
		Route: func(dst net.IP, port uint16) Route {
			switch dst.String() {
			case toB:
				return Route{Upstream: proxyB.addr()}
			case toDirect, directIP.String():
				return Route{Direct: true}
			case toDrop:
				return Route{Drop: true}
			case toPort:
				// THE SAME ADDRESS, A DIFFERENT PROXY BY PORT. This is the half that shows the rule
				// sees the port and not only the address.
				if port == 8443 {
					return Route{Upstream: proxyB.addr()}
				}
				return Route{} // 443 -> the default, A
			}
			return Route{} // unmatched -> the default proxy, A
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	guest := net.IPv4(172, 30, 0, 2)

	// A -> proxy A
	if got := ask(t, dev, reader, guest, 10001, net.ParseIP(toA), 443, "ping", 3*time.Second); got != "A:ping" {
		t.Errorf("destination for proxy A answered %q, want A:ping", got)
	}
	// B -> proxy B, AND NOT A.
	if got := ask(t, dev, reader, guest, 10002, net.ParseIP(toB), 443, "ping", 3*time.Second); got != "B:ping" {
		t.Errorf("destination for proxy B answered %q, want B:ping", got)
	}
	// DIRECT -> the destination itself, which tags D. A proxy answer would start with A: or B:.
	if got := ask(t, dev, reader, guest, 10003, directIP, atoi16(directPort), "ping", 3*time.Second); got != "D:ping" {
		t.Errorf("the direct destination answered %q, want D:ping", got)
	}
	// DROP -> nothing at all. There is no RST in UDP, so silence is the behaviour.
	if got := ask(t, dev, reader, guest, 10004, net.ParseIP(toDrop), 443, "ping", 400*time.Millisecond); got != "" {
		t.Errorf("a dropped destination answered %q, want silence", got)
	}
	// PORT 8443 -> B, even though the default is A.
	if got := ask(t, dev, reader, guest, 10005, net.ParseIP(toPort), 8443, "ping", 3*time.Second); got != "B:ping" {
		t.Errorf("port 8443 answered %q, want B:ping", got)
	}
	// THE SAME ADDRESS ON 443 -> the default, A. This is the cross-check: a rule that ignored the port
	// would answer B here too.
	if got := ask(t, dev, reader, guest, 10006, net.ParseIP(toPort), 443, "ping", 3*time.Second); got != "A:ping" {
		t.Errorf("port 443 answered %q, want A:ping - the rule was supposed to match only 8443", got)
	}
}

// A PER-DATAGRAM RULE SEES EVERY DATAGRAM, so a proxy that fails on one destination does not stop the
// next from taking a different path.
func TestTheRouteIsConsultedForEveryDatagram(t *testing.T) {
	proxyA := startTagProxy(t, "A")
	proxyB := startTagProxy(t, "B")
	dev := newPipeline()
	withStubbedDevices(t, dev)
	reader := startReplyReader(t, dev)

	var calls int
	r, err := Start(Config{
		GuestIP:  "172.30.0.2",
		Upstream: proxyA.addr(),
		Name:     "perflow0",
		Route: func(dst net.IP, _ uint16) Route {
			calls++
			if dst.String() == "203.0.113.20" {
				return Route{Upstream: proxyB.addr()}
			}
			return Route{}
		},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	guest := net.IPv4(172, 30, 0, 2)
	if got := ask(t, dev, reader, guest, 20001, net.ParseIP("203.0.113.10"), 443, "1", 3*time.Second); got != "A:1" {
		t.Errorf("first datagram answered %q", got)
	}
	if got := ask(t, dev, reader, guest, 20002, net.ParseIP("203.0.113.20"), 443, "2", 3*time.Second); got != "B:2" {
		t.Errorf("second datagram answered %q, want B:2", got)
	}
	if calls < 2 {
		t.Errorf("the route callback ran %d times for two datagrams, want at least 2", calls)
	}
}

// A SESSION IS PER FLOW, so two destinations through the same proxy do not share one - and the
// replies still come back to the right guest port.
func TestTwoFlowsThroughOneProxyStaySeparate(t *testing.T) {
	proxyA := startTagProxy(t, "A")
	dev := newPipeline()
	withStubbedDevices(t, dev)
	reader := startReplyReader(t, dev)

	r, err := Start(Config{GuestIP: "172.30.0.2", Upstream: proxyA.addr(), Name: "sep0"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = r.Close() }()

	guest := net.IPv4(172, 30, 0, 2)
	if got := ask(t, dev, reader, guest, 30001, net.ParseIP("203.0.113.10"), 443, "one", 3*time.Second); got != "A:one" {
		t.Errorf("flow one answered %q", got)
	}
	if got := ask(t, dev, reader, guest, 30002, net.ParseIP("203.0.113.11"), 443, "two", 3*time.Second); got != "A:two" {
		t.Errorf("flow two answered %q", got)
	}
}

// A BUSYBOX `ip` CANNOT FILTER BY PROTOCOL, AND THE REFUSAL MUST SAY SO.
//
// MEASURED on alpine:3.21: `/sbin/ip` is busybox, `ipproto` does not exist, and the answer is
//
//	ip: invalid argument 'ipproto' to 'ip'
//
// which names neither the binary nor the package to install. And it cannot be papered over by dropping
// the flag: `ipproto udp` is the rule's whole point - without it the rule takes the guest's TCP too,
// sending it into a tun that only carries datagrams.
func TestAPolicyFailureNamesTheMissingIpproto(t *testing.T) {
	oldRun := runFn
	defer func() { runFn = oldRun }()
	runFn = func(name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "rule" {
			return "ip: invalid argument 'ipproto' to 'ip'", errFake("exit status 1")
		}
		return "", nil
	}

	err := installPolicy("tun0", "172.30.0.2", 162)
	if err == nil {
		t.Fatal("installPolicy accepted a busybox ip")
	}
	if !strings.Contains(err.Error(), "iproute2") {
		t.Fatalf("the error does not name the package to install: %v", err)
	}
	if !strings.Contains(err.Error(), "busybox") {
		t.Fatalf("the error does not name the cause: %v", err)
	}
}

// AND AN ORDINARY FAILURE IS STILL ORDINARY, so the special case above does not swallow every error.
func TestAnOrdinaryPolicyFailureIsReportedPlainly(t *testing.T) {
	oldRun := runFn
	defer func() { runFn = oldRun }()
	runFn = func(name string, args ...string) (string, error) {
		return "RTNETLINK answers: Operation not permitted", errFake("exit status 2")
	}
	err := installPolicy("tun0", "172.30.0.2", 162)
	if err == nil {
		t.Fatal("installPolicy accepted a failure")
	}
	if strings.Contains(err.Error(), "busybox") {
		t.Fatalf("an EPERM was reported as a busybox problem: %v", err)
	}
}
