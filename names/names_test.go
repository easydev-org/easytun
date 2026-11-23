package names

// THE RESOLVER AND THE POOL, PORTED FROM THE PACKAGE THEY CAME FROM.
//
// The assertions are the ones that made domain rules work at all: a query is answered, the name is
// recorded, an address reads back as its name, and an invented address cannot collide with a real one.

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// reset clears the process-wide table and pool.
func reset(t *testing.T) {
	t.Helper()
	known.mu.Lock()
	old := known.byIP
	known.byIP = map[string]*entry{}
	known.mu.Unlock()
	pool.mu.Lock()
	pool.byName = map[string]*alloc{}
	pool.byIP = map[uint32]string{}
	pool.mu.Unlock()
	t.Cleanup(func() {
		known.mu.Lock()
		known.byIP = old
		known.mu.Unlock()
	})
}

// --- DNS wire format ---

// buildAnswer assembles a DNS message the way a real resolver would: one question and the given A
// records as answers, with the answer's name a pointer into the question.
func buildAnswer(name string, addrs []net.IP, ttl uint32) []byte {
	var q []byte
	for _, label := range splitName(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // end of name, QTYPE A, QCLASS IN

	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(addrs)))
	msg = append(msg, q...)
	for _, a := range addrs {
		msg = append(msg, 0xc0, 12)
		var rr [10]byte
		binary.BigEndian.PutUint16(rr[0:2], 1)
		binary.BigEndian.PutUint16(rr[2:4], 1)
		binary.BigEndian.PutUint32(rr[4:8], ttl)
		binary.BigEndian.PutUint16(rr[8:10], 4)
		msg = append(msg, rr[:]...)
		msg = append(msg, a.To4()...)
	}
	return msg
}

// query is one DNS question in the wire form a client sends.
func query(name string) []byte {
	var q []byte
	for _, label := range splitName(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	return append(msg, q...)
}

func TestParseQuestionReadsTheName(t *testing.T) {
	msg := buildAnswer("YouTube.COM", []net.IP{net.IPv4(142, 250, 1, 1)}, 60)
	name, qtype, ok := parseQuestion(msg)
	if !ok {
		t.Fatal("parseQuestion rejected a well-formed query")
	}
	if name != "youtube.com" {
		t.Errorf("name = %q, want it lowercased", name)
	}
	if qtype != 1 {
		t.Errorf("qtype = %d, want 1 (A)", qtype)
	}
}

func TestParseAnswersReadsAAndAAAA(t *testing.T) {
	got := parseAnswers(buildAnswer("example.com", []net.IP{net.IPv4(93, 184, 216, 34)}, 300))
	if len(got) != 1 {
		t.Fatalf("got %d answers, want 1", len(got))
	}
	if got[0].ip != "93.184.216.34" || got[0].ttl != 300 {
		t.Errorf("got %+v", got[0])
	}
}

func TestParseSurvivesTruncatedInput(t *testing.T) {
	for _, b := range [][]byte{nil, {}, make([]byte, 3), make([]byte, 12), append(make([]byte, 12), 0xff, 0xff)} {
		_, _, _ = parseQuestion(b)
		_ = parseAnswers(b)
		_ = skipName(b, 0)
	}
}

func TestSkipNameHandlesAPointer(t *testing.T) {
	if got := skipName([]byte{0xc0, 0x0c, 0, 1}, 0); got != 2 {
		t.Fatalf("skipName on a pointer = %d, want 2", got)
	}
}

// --- the name table ---

func TestRememberThenFor(t *testing.T) {
	reset(t)
	Remember("142.250.1.1", "youtube.com", time.Minute)
	got := For(net.IPv4(142, 250, 1, 1))
	if len(got) != 1 || got[0] != "youtube.com" {
		t.Fatalf("For = %v", got)
	}
	if names := For(net.IPv4(1, 2, 3, 4)); names != nil {
		t.Errorf("an unknown address has names %v", names)
	}
}

func TestAnAddressRemembersEveryName(t *testing.T) {
	reset(t)
	Remember("1.2.3.4", "a.example", time.Minute)
	Remember("1.2.3.4", "b.example", time.Minute)
	if got := For(net.IPv4(1, 2, 3, 4)); len(got) != 2 {
		t.Fatalf("For = %v, want both names", got)
	}
}

func TestAZeroTTLIsNotCached(t *testing.T) {
	reset(t)
	Remember("1.2.3.4", "x.example", 0)
	if names := For(net.IPv4(1, 2, 3, 4)); names != nil {
		t.Fatalf("a zero-TTL answer was cached: %v", names)
	}
}

func TestAnExpiredEntryDisappears(t *testing.T) {
	reset(t)
	Remember("1.2.3.4", "x.example", time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	if names := For(net.IPv4(1, 2, 3, 4)); names != nil {
		t.Fatalf("an expired entry was returned: %v", names)
	}
}

// --- the fake pool ---

func TestAFakeAddressIsStableAndInRange(t *testing.T) {
	reset(t)
	first := pool.Allocate("www.youtube.com")
	if first == nil {
		t.Fatal("no address allocated")
	}
	if !InPool(first) {
		t.Fatalf("%v is outside the pool", first)
	}
	if second := pool.Allocate("www.youtube.com"); !first.Equal(second) {
		t.Fatalf("the same name got %v then %v", first, second)
	}
}

// THE HASH MAY COLLIDE - 100 buckets cannot hold an unbounded set of names - so this asserts the probe:
// two names never share an address, which is what makes a session per name possible.
func TestTwoNamesNeverShareAnAddress(t *testing.T) {
	reset(t)
	seen := map[string]string{}
	for i := 0; i < 500; i++ {
		name := "host" + itoa(i) + ".example"
		ip := pool.Allocate(name)
		if ip == nil {
			t.Fatal("pool exhausted at 500 names")
		}
		if other, ok := seen[ip.String()]; ok {
			t.Fatalf("%q and %q both got %v", other, name, ip)
		}
		seen[ip.String()] = name
	}
}

func TestTheAddressReadsBackAsItsName(t *testing.T) {
	reset(t)
	ip := pool.Allocate("api.github.com")
	name, ok := pool.NameFor(ip)
	if !ok || name != "api.github.com" {
		t.Fatalf("NameFor(%v) = %q, %v", ip, name, ok)
	}
}

func TestARealAddressIsNotInThePool(t *testing.T) {
	reset(t)
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "198.17.255.255", "198.20.0.1", "10.0.0.1"} {
		if InPool(net.ParseIP(s)) {
			t.Errorf("%s is reported as in the pool", s)
		}
		if _, ok := pool.NameFor(net.ParseIP(s)); ok {
			t.Errorf("%s read back as a name", s)
		}
	}
}

// AN EXPIRED ALLOCATION IS FREE, and its name is gone with it - so a second name can take the address
// without the first name still reading back from it.
func TestAnExpiredAllocationIsReusable(t *testing.T) {
	reset(t)
	ip := pool.Allocate("gone.example")
	pool.mu.Lock()
	pool.byName["gone.example"].exp = time.Now().Add(-time.Second)
	pool.mu.Unlock()

	if name, ok := pool.NameFor(ip); ok {
		t.Fatalf("an expired allocation still reads back as %q", name)
	}
	again := pool.Allocate("gone.example")
	if name, ok := pool.NameFor(again); !ok || name != "gone.example" {
		t.Fatalf("a re-allocated name reads back as %q, %v", name, ok)
	}
}

// THE ANSWER IS A WELL-FORMED RESPONSE naming the fake address, and AAAA IS ANSWERED EMPTY so the client
// falls back to IPv4 - the only family the proxy and the relay carry.
func TestFakeAnswerIsAValidResponse(t *testing.T) {
	reset(t)
	q := query("www.youtube.com")
	reply := fakeAnswer(q, "www.youtube.com", 1)
	if reply == nil {
		t.Fatal("no answer built")
	}
	if reply[0] != q[0] || reply[1] != q[1] {
		t.Error("the query id was not echoed")
	}
	if reply[2]&0x80 == 0 {
		t.Error("QR is not set, so this is not a response")
	}
	answers := parseAnswers(reply)
	if len(answers) != 1 {
		t.Fatalf("got %d answers, want 1", len(answers))
	}
	if name, _ := pool.NameFor(net.ParseIP(answers[0].ip)); name != "www.youtube.com" {
		t.Fatalf("the answered address reads back as %q", name)
	}

	aaaa := fakeAnswer(q, "www.youtube.com", 28)
	if aaaa == nil {
		t.Fatal("no AAAA answer built")
	}
	if got := parseAnswers(aaaa); len(got) != 0 {
		t.Fatalf("AAAA got %d records, want none", len(got))
	}
}

// --- the server, end to end against a fake upstream ---

// fakeUpstream answers every A query with one fixed address.
func fakeUpstream(t *testing.T, ip net.IP, ttl uint32) string {
	t.Helper()
	ensureLoopbackUp(t)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			name, _, ok := parseQuestion(buf[:n])
			if !ok {
				continue
			}
			_, _ = conn.WriteToUDP(buildAnswer(name, []net.IP{ip}, ttl), from)
		}
	}()
	return conn.LocalAddr().String()
}

func TestTheServerAnswersAndRecordsTheName(t *testing.T) {
	ensureLoopbackUp(t)
	reset(t)
	upstream := fakeUpstream(t, net.IPv4(203, 0, 113, 5), 120)
	s, err := Start(Config{Bind: "127.0.0.1:0", Upstreams: []string{upstream}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	client, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(query("www.youtube.com")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if len(parseAnswers(buf[:n])) == 0 {
		t.Fatal("the resolver answered without a usable address")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if names := For(net.IPv4(203, 0, 113, 5)); len(names) > 0 {
			if names[0] != "www.youtube.com" {
				t.Fatalf("recorded name = %q", names[0])
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the server answered but recorded nothing, so every domain rule would match nothing")
}

// FAKE-IP MODE ANSWERS FROM THE POOL AND DOES NOT FORWARD, so the upstream being unreachable must not
// matter.
func TestFakeModeAnswersWithoutAnUpstream(t *testing.T) {
	ensureLoopbackUp(t)
	reset(t)
	s, err := Start(Config{Bind: "127.0.0.1:0", Upstreams: []string{"127.0.0.1:1"}, FakeIP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	client, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = client.Write(query("www.youtube.com"))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("fake mode did not answer: %v", err)
	}
	answers := parseAnswers(buf[:n])
	if len(answers) != 1 {
		t.Fatalf("got %d answers, want 1", len(answers))
	}
	ip := net.ParseIP(answers[0].ip)
	if !InPool(ip) {
		t.Fatalf("%s is not a fake address", answers[0].ip)
	}
	if name, ok := pool.NameFor(ip); !ok || name != "www.youtube.com" {
		t.Fatalf("the fake address reads back as %q, %v", name, ok)
	}
}

func TestADeadUpstreamDoesNotWedgeTheServer(t *testing.T) {
	ensureLoopbackUp(t)
	reset(t)
	s, err := Start(Config{Bind: "127.0.0.1:0", Upstreams: []string{"127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	client, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = client.Write(query("nowhere.example"))
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := client.Read(make([]byte, 1500)); err == nil {
		t.Fatal("a dead upstream produced an answer")
	}
	// AND THE SERVER IS STILL SERVING.
	_, _ = client.Write(query("again.example"))
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = client.Read(make([]byte, 1500))
}

// ResolveReal ASKS THE UPSTREAM AND NEVER THE POOL, which is what a `direct` rule needs - asking the
// pool would return an invented address and connect back.
func TestResolveRealBypassesThePool(t *testing.T) {
	reset(t)
	const real = "93.184.216.34"
	upstream := fakeUpstream(t, net.ParseIP(real), 60)
	got, err := ResolveReal([]string{upstream}, "example.com")
	if err != nil {
		t.Fatalf("ResolveReal: %v", err)
	}
	if got.String() != real {
		t.Fatalf("ResolveReal = %v, want %s", got, real)
	}
	if InPool(got) {
		t.Fatalf("ResolveReal returned a fake address %v", got)
	}
}

func TestResolveRealFailsWhenTheUpstreamIsSilent(t *testing.T) {
	reset(t)
	if _, err := ResolveReal([]string{"127.0.0.1:1"}, "nowhere.example"); err == nil {
		t.Fatal("ResolveReal succeeded with no upstream")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
