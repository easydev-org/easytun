//go:build linux

package easytun

import (
	"encoding/binary"
	"net"
	"testing"
)

// A FAKE DESTINATION NEEDS A NAME ON THE WIRE, and this is where it becomes one.
//
// A caller that invents the address it hands a guest cannot ask a proxy for that address - it exists
// nowhere. SOCKS5's domain form (ATYP 3) is what lets the proxy resolve the real host, and it is the
// whole reason `Route.Host` exists.

// THE DOMAIN FORM IS ATYP 3, A LENGTH, THE BYTES, A PORT, THEN THE PAYLOAD - and the offset of the
// payload depends on the name's length, which is the thing an address form never had to handle.
func TestSocksUDPTargetSendsADomainWhenGiven(t *testing.T) {
	payload := []byte("quic")
	frame := socksUDPTarget([4]byte{198, 18, 7, 3}, 443, "www.youtube.com", payload)

	if frame[3] != 3 {
		t.Fatalf("ATYP = %d, want 3 (domain)", frame[3])
	}
	if int(frame[4]) != len("www.youtube.com") {
		t.Fatalf("length byte = %d, want %d", frame[4], len("www.youtube.com"))
	}
	if got := string(frame[5 : 5+len("www.youtube.com")]); got != "www.youtube.com" {
		t.Fatalf("name = %q", got)
	}
	portAt := 5 + len("www.youtube.com")
	if got := binary.BigEndian.Uint16(frame[portAt : portAt+2]); got != 443 {
		t.Fatalf("port = %d, want 443", got)
	}
	if got := string(frame[portAt+2:]); got != "quic" {
		t.Fatalf("payload = %q", got)
	}
}

// AN EMPTY HOST IS THE ADDRESS FORM, so a real destination is unchanged by this feature.
func TestSocksUDPTargetFallsBackToTheAddress(t *testing.T) {
	withName := socksUDPTarget([4]byte{1, 2, 3, 4}, 53, "", []byte("x"))
	plain := socksUDPRequest([4]byte{1, 2, 3, 4}, 53, []byte("x"))
	if string(withName) != string(plain) {
		t.Fatal("an empty host did not produce the address form")
	}
	if withName[3] != 1 {
		t.Fatalf("ATYP = %d, want 1 (IPv4)", withName[3])
	}
}

// A REPLY MAY NAME AN ADDRESS IN EITHER FAMILY, AND A DOMAIN IS REFUSED.
//
// The relay needs an address to put in the packet the guest receives. A reply naming a domain would
// give it nothing to write there, and resolving it on the reply path would be a second lookup for
// every datagram.
func TestSocksUDPReplyAcceptsBothAddressFamilies(t *testing.T) {
	// IPv4
	v4 := socksUDPRequest([4]byte{203, 0, 113, 9}, 443, []byte("hi"))
	ip, port, payload, ok := socksUDPReply(v4)
	if !ok || !ip.Equal(net.IPv4(203, 0, 113, 9)) || port != 443 || string(payload) != "hi" {
		t.Fatalf("IPv4 reply decoded as %v:%d %q ok=%v", ip, port, payload, ok)
	}

	// IPv6: ATYP 4, sixteen address bytes, then the port.
	v6 := make([]byte, 22+2)
	v6[3] = 4
	copy(v6[4:20], net.ParseIP("2001:db8::1").To16())
	binary.BigEndian.PutUint16(v6[20:22], 443)
	copy(v6[22:], "hi")
	ip, port, payload, ok = socksUDPReply(v6)
	if !ok || port != 443 || string(payload) != "hi" {
		t.Fatalf("IPv6 reply decoded as %v:%d %q ok=%v", ip, port, payload, ok)
	}

	// A domain in a reply is refused.
	dom := socksUDPTarget([4]byte{}, 443, "example.com", []byte("hi"))
	if _, _, _, ok := socksUDPReply(dom); ok {
		t.Fatal("a domain-named reply was accepted; the relay has no address to write")
	}
}

// THE KEY CARRIES THE NAME, so two flows to one address under different names do not share a session.
func TestTheFlowKeyIncludesTheName(t *testing.T) {
	a := key{dstIP: [4]byte{198, 18, 7, 3}, dstPort: 443, host: "a.example"}
	b := key{dstIP: [4]byte{198, 18, 7, 3}, dstPort: 443, host: "b.example"}
	if a == b {
		t.Fatal("two flows to one address with different names produced the same key")
	}
}
