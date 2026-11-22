//go:build linux

package easytun

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"unsafe"
)

// IFF_NO_PI IS THE WHOLE PARSER'S ASSUMPTION, and this is the only place it can be checked on a CI
// runner with no tun device.
//
// MEASURED, before it was set: the kernel prefixes four bytes of flags and protocol, the parser read
// the flags word as the IP version, and the relay logged `ipversion=6 proto=128` on a device that was
// working correctly. A refactor that drops the flag breaks every packet and nothing else says so.
func TestOpenTunAsksForNoProtocolInfo(t *testing.T) {
	req := buildIfreq("relay-udp")
	if req.flags&iffNoPI == 0 {
		t.Fatal("IFF_NO_PI is not set: the kernel will prefix four bytes and every read will parse " +
			"the flags word as the IP version")
	}
	if req.flags&iffTun == 0 {
		t.Fatal("IFF_TUN is not set: this would create a tap device, which carries Ethernet frames")
	}
	// AND NOT IFF_TAP. The two bits together are what the kernel rejects with EINVAL, and the
	// symptom is a device that never appears.
	if req.flags&0x0002 != 0 {
		t.Fatal("IFF_TAP is set as well as IFF_TUN")
	}
}

// THE NAME IS COPIED, NOT TRUNCATED SILENTLY, and the struct must be the size the ioctl expects.
func TestIfreqHoldsTheNameAndIsTheExpectedSize(t *testing.T) {
	req := buildIfreq("relay-udp")
	if got := string(req.name[:len("relay-udp")]); got != "relay-udp" {
		t.Fatalf("name = %q", got)
	}
	if req.name[len("relay-udp")] != 0 {
		t.Fatal("the name is not NUL-terminated inside its 16 bytes")
	}
	// 16 name + 2 flags + 22 padding = 40, which is what linux/amd64's `struct ifreq` is. A wrong
	// size makes TUNSETIFF read past the struct.
	if got := unsafe.Sizeof(req); got != 40 {
		t.Fatalf("ifreq is %d bytes, not 40", got)
	}
}

// A LONG NAME IS CLIPPED RATHER THAN OVERFLOWING. IFNAMSIZ is 16 including the NUL, so 15 characters
// is the most a device can be called.
func TestALongNameIsClippedToFifteenBytes(t *testing.T) {
	req := buildIfreq("abcdefghijklmnopqrstuvwxyz")
	for i, c := range []byte("abcdefghijklmno") {
		if req.name[i] != c {
			t.Fatalf("byte %d = %q, want %q", i, req.name[i], c)
		}
	}
	if req.name[15] != 0 {
		t.Fatalf("byte 15 = %q, want the NUL terminator", req.name[15])
	}
}

// A GUEST IP OF "" IS NOT AN ERROR - it is "nothing to relay" - and a bare IP with no proxy still
// starts, because direct is a valid configuration.
func TestStartWithNoGuestDoesNothingAndSaysSo(t *testing.T) {
	r, err := Start(Config{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if r != nil {
		t.Fatal("Start returned a relay for an empty guest IP")
	}
}

// A GUEST IP THAT IS NOT IPv4 IS REFUSED BEFORE A DEVICE IS CREATED, because a v6 guest in this relay
// would be parsed as v4 and silently mangled.
func TestStartRefusesANonIPv4Guest(t *testing.T) {
	for _, ip := range []string{"not-an-ip", "2001:db8::1", "::1"} {
		if _, err := Start(Config{GuestIP: ip}); err == nil {
			t.Errorf("Start accepted %q as a guest IP", ip)
		}
	}
}

// CLOSE ON A NIL RELAY IS A NO-OP, so a caller can `defer r.Close()` without checking whether Start
// returned one - which is the shape every caller of this package wants.
func TestCloseOnNilIsSafe(t *testing.T) {
	var r *Relay
	if err := r.Close(); err != nil {
		t.Fatalf("Close on a nil relay: %v", err)
	}
}

// tableFor must not give two device names the same table, or two relays in one namespace install
// their rules into one table and see each other's traffic.
func TestTableForIsStableAndInRange(t *testing.T) {
	for _, name := range []string{"tun0", "relay-udp", "a", "relay-1", "relay-2"} {
		n := tableFor(name)
		if n < 100 || n > 199 {
			t.Errorf("tableFor(%q) = %d, outside 100..199", name, n)
		}
		if again := tableFor(name); again != n {
			t.Errorf("tableFor(%q) is not stable: %d then %d", name, n, again)
		}
	}
}

// THE ONE THAT MATTERS FOR TWO RELAYS IN ONE NAMESPACE: `--network container:` puts them together,
// and a shared table number means each reads the other's datagrams.
//
// THE HASH MAY COLLIDE - 100 buckets cannot hold 200 names - so this asserts the thing that must be
// true: chooseTable probes past an occupied table and never returns one another relay is using.
func TestChooseTableNeverReturnsAnOccupiedOne(t *testing.T) {
	occupied := map[int]bool{}
	for i := 0; i < 100; i++ {
		occupied[100+i] = true
	}
	// Every table but one is taken; the relay must find the one that is free.
	free := 173
	delete(occupied, free)

	old := tableInUse
	tableInUse = func(n int) bool { return occupied[n] }
	defer func() { tableInUse = old }()

	if got := chooseTable("relay-x", 0); got != free {
		t.Fatalf("chooseTable returned %d, want the only free table %d", got, free)
	}
}

// AN EXPLICIT TABLE IS HONOURED EXACTLY, so a caller that knows its namespace can pin one.
func TestChooseTableHonoursAnExplicitNumber(t *testing.T) {
	old := tableInUse
	tableInUse = func(int) bool { return true } // everything is "in use"
	defer func() { tableInUse = old }()

	if got := chooseTable("tun0", 4321); got != 4321 {
		t.Fatalf("chooseTable ignored the explicit table: %d", got)
	}
}

// A TABLE THAT IS FREE IS TAKEN WITHOUT PROBING, so an empty namespace costs one tableFor call.
func TestChooseTableTakesTheHashBucketWhenItIsFree(t *testing.T) {
	old := tableInUse
	tableInUse = func(int) bool { return false }
	defer func() { tableInUse = old }()

	for _, name := range []string{"tun0", "relay-udp", "relay-7"} {
		if got, want := chooseTable(name, 0), tableFor(name); got != want {
			t.Errorf("chooseTable(%q) = %d, want its hash bucket %d", name, got, want)
		}
	}
}

// THE ADDRESS FOLLOWS THE TABLE, so a reader who sees table 137 predicts 10.99.37.1 - and two relays
// in one namespace do not both claim one /24.
func TestAddrForFollowsTheTable(t *testing.T) {
	for _, table := range []int{100, 137, 199, 4321} {
		want := "10.99." + itoa(((table%100)+100)%100) + ".1"
		if got := addrFor(table); got != want {
			t.Errorf("addrFor(%d) = %q, want %q", table, got, want)
		}
	}
	// AND THE OCTET IS ALWAYS VALID, even for a table outside the default range.
	for _, table := range []int{0, 1, 99, 253, 254, 255, 1000} {
		ip := net.ParseIP(addrFor(table))
		if ip == nil {
			t.Errorf("addrFor(%d) = %q is not an address", table, addrFor(table))
		}
	}
}

// Preflight must distinguish "no device" from "no capability". This runner has no /dev/net/tun, so
// the answer here is ErrNoTun - and on a runner that HAS one it must not be.
func TestPreflightReportsTheMissingDeviceOrPasses(t *testing.T) {
	err := Preflight()
	if err == nil {
		return // a runner with the device and the capability: nothing to assert
	}
	if _, statErr := net.InterfaceByName("lo"); statErr != nil {
		t.Skip("no loopback interface, so this is not a Linux networking namespace")
	}
	if !errors.Is(err, ErrNoTun) && !errors.Is(err, ErrNoNetAdmin) {
		t.Fatalf("Preflight returned an error that names neither cause: %v", err)
	}
}

// --- the packet layer, which needs nothing at all ---

func TestBuildAndParseIPv4UDPRoundTrip(t *testing.T) {
	src := net.IPv4(172, 30, 0, 2).To4()
	dst := net.IPv4(104, 18, 27, 14).To4()
	payload := []byte("a quic initial, roughly")

	pkt := buildIPv4UDP(src, 51234, dst, 443, payload)

	if pkt[0] != 0x45 {
		t.Fatalf("version/IHL = %#x, want 0x45", pkt[0])
	}
	if got := binary.BigEndian.Uint16(pkt[2:4]); int(got) != len(pkt) {
		t.Fatalf("total length = %d, packet is %d", got, len(pkt))
	}
	if pkt[9] != 17 {
		t.Fatalf("protocol = %d, want 17 (UDP)", pkt[9])
	}
	if ipv4Checksum(pkt[:20]) != 0 {
		t.Fatal("the header checksum does not verify to zero over its own header")
	}

	srcIP, dstIP, srcPort, dstPort, gotPayload, ok := parseIPv4UDP(pkt)
	if !ok {
		t.Fatal("parseIPv4UDP rejected a packet it had just built")
	}
	if !srcIP.Equal(src) || !dstIP.Equal(dst) {
		t.Fatalf("endpoints %v -> %v, want %v -> %v", srcIP, dstIP, src, dst)
	}
	if srcPort != 51234 || dstPort != 443 {
		t.Fatalf("ports %d -> %d, want 51234 -> 443", srcPort, dstPort)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload %q, want %q", gotPayload, payload)
	}
}

// A PACKET THAT IS NOT IPv4 UDP IS NOT OURS. IPv6 neighbour discovery is constant on a tun and this
// relay has no answer for it, so the caller must get false rather than a wrong parse.
func TestParseRejectsOtherPackets(t *testing.T) {
	cases := map[string][]byte{
		"short": make([]byte, 20),
		"ipv6":  append([]byte{0x60}, make([]byte, 40)...),
		"tcp": func() []byte {
			b := buildIPv4UDP(net.IPv4(1, 2, 3, 4), 1, net.IPv4(5, 6, 7, 8), 2, nil)
			b[9] = 6
			return b
		}(),
		"empty":     {},
		"truncated": make([]byte, 27),
	}
	for name, b := range cases {
		if _, _, _, _, _, ok := parseIPv4UDP(b); ok {
			t.Errorf("%s: parseIPv4UDP accepted a packet it should reject", name)
		}
	}
}

// THE SOCKS5 FRAMING, BOTH DIRECTIONS, because a mismatch here is a relay that sends well-formed
// datagrams the proxy drops.
func TestSocksUDPFramingRoundTrip(t *testing.T) {
	dst := [4]byte{104, 18, 27, 14}
	payload := []byte("hello")
	framed := socksUDPRequest(dst, 443, payload)

	if framed[3] != 1 {
		t.Fatalf("ATYP = %d, want 1 (IPv4)", framed[3])
	}
	if got := [4]byte{framed[4], framed[5], framed[6], framed[7]}; got != dst {
		t.Fatalf("address = %v, want %v", got, dst)
	}
	if got := binary.BigEndian.Uint16(framed[8:10]); got != 443 {
		t.Fatalf("port = %d, want 443", got)
	}

	ip, port, body, ok := socksUDPReply(framed)
	if !ok {
		t.Fatal("socksUDPReply rejected a frame socksUDPRequest had just built")
	}
	if !ip.Equal(net.IP(dst[:])) || port != 443 || string(body) != string(payload) {
		t.Fatalf("decoded %v:%d %q, want %v:%d %q", ip, port, body, dst, 443, payload)
	}
}

// FRAGMENTED REPLIES ARE REFUSED, not silently assembled into a datagram the guest cannot use.
func TestSocksUDPReplyRefusesFragmentsAndJunk(t *testing.T) {
	base := socksUDPRequest([4]byte{1, 2, 3, 4}, 53, []byte("x"))

	frag := append([]byte(nil), base...)
	frag[2] = 1 // FRAG != 0
	if _, _, _, ok := socksUDPReply(frag); ok {
		t.Error("a fragmented reply was accepted")
	}

	domain := append([]byte(nil), base...)
	domain[3] = 3 // ATYP = domain, which this relay does not ask for
	if _, _, _, ok := socksUDPReply(domain); ok {
		t.Error("a domain-named reply was accepted")
	}

	if _, _, _, ok := socksUDPReply(base[:9]); ok {
		t.Error("a reply shorter than the header was accepted")
	}
}

func TestIPv4ChecksumOfAZeroHeader(t *testing.T) {
	// The checksum of an all-zero 20-byte header is 0xffff (the complement of 0), which is the
	// value a correct implementation returns and a broken one returns as 0.
	if got := ipv4Checksum(make([]byte, 20)); got != 0xffff {
		t.Fatalf("checksum of a zero header = %#x, want 0xffff", got)
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
