package easytun

import (
	"encoding/binary"
	"net"
	"strconv"
)

// THE PACKET LAYER: BUILD AN IPv4+UDP DATAGRAM, AND STRIP SOCKS5's FRAMING.
//
// Everything here is a pure function of its arguments, which is why it is in its own file: it is the
// part of the relay that can be tested on a machine with no tun device, no capability and no
// network.

// buildIPv4UDP assembles a minimal IPv4+UDP packet with the given endpoints.
//
// THE UDP CHECKSUM IS LEFT ZERO, which IPv4 allows and means "not computed". Computing it would be a
// pass over every byte of a payload that has already crossed a hypervisor and a proxy, and the
// receiving kernel recomputes nothing for UDP unless it is configured to.
func buildIPv4UDP(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45 // version 4, header length 5 words
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	copy(p[12:16], srcIP.To4())
	copy(p[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(p[10:12], ipv4Checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

// ipv4Checksum is the one's-complement sum the IP header carries.
func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i : i+2]))
	}
	if len(h)%2 == 1 {
		sum += uint32(h[len(h)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseIPv4UDP reads the endpoints and payload out of a datagram read from the tun.
//
// A PACKET THAT IS NOT IPv4 UDP IS NOT OURS. IPv6 neighbour discovery is constant on a tun and this
// relay has no answer for it, so the caller gets false rather than a wrong parse.
func parseIPv4UDP(b []byte) (srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, ok bool) {
	if len(b) < 28 || b[0]>>4 != 4 || b[9] != 17 {
		return nil, nil, 0, 0, nil, false
	}
	ihl := int(b[0]&0x0f) * 4
	if len(b) < ihl+8 {
		return nil, nil, 0, 0, nil, false
	}
	srcIP = net.IP(append([]byte(nil), b[12:16]...))
	dstIP = net.IP(append([]byte(nil), b[16:20]...))
	srcPort = binary.BigEndian.Uint16(b[ihl : ihl+2])
	dstPort = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
	payload = b[ihl+8:]
	return srcIP, dstIP, srcPort, dstPort, payload, true
}

// socksUDPRequest frames a payload the way SOCKS5 wants it:
//
//	RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) DATA
func socksUDPRequest(dstIP [4]byte, dstPort uint16, payload []byte) []byte {
	out := make([]byte, 10+len(payload))
	out[3] = 1 // ATYP = IPv4
	copy(out[4:8], dstIP[:])
	binary.BigEndian.PutUint16(out[8:10], dstPort)
	copy(out[10:], payload)
	return out
}

// socksUDPTarget frames a datagram for a NAME when one is given, and an address otherwise.
//
// SOCKS5 CARRIES A DOMAIN AS ATYP 3 - a length byte and the bytes of the name - and it exists for
// exactly this case: the caller has a name and the address is one it invented, so the proxy is the
// only thing that can resolve it. Using the address form for a fake destination would ask the proxy
// for a host that cannot exist.
//
// THE PORT IS STILL NEEDED IN THE ADDRESS FORM, and a domain carries its own length so there is no
// fixed 4-byte address to copy - which is why this is a separate function rather than a flag on the
// address one.
func socksUDPTarget(dstIP [4]byte, dstPort uint16, host string, payload []byte) []byte {
	if host == "" {
		return socksUDPRequest(dstIP, dstPort, payload)
	}
	// A HOST THAT CARRIES ITS OWN PORT IS SPLIT, so the SOCKS5 request names the right one. The name
	// form of this frame has a length byte and then the bytes, so appending ":port" to a name would be
	// a malformed address the proxy cannot resolve.
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err == nil {
			dstPort = uint16(n)
		}
	}
	if len(host) > 255 {
		// A DNS NAME CANNOT EXCEED 255 BYTES, and a length byte that wrapped would send a truncated
		// name the proxy resolves to something else.
		host = host[:255]
	}
	out := make([]byte, 0, 7+len(host)+len(payload))
	out = append(out, 0, 0, 0, 3) // RSV, FRAG=0, ATYP=domain
	out = append(out, byte(len(host)))
	out = append(out, host...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], dstPort)
	out = append(out, p[:]...)
	out = append(out, payload...)
	return out
}

// socksUDPReply strips that framing from a reply.
//
// FRAGMENTED REPLIES ARE NOT SUPPORTED and there is no reason to: the fragmentation field exists for
// proxies that split a datagram, none of the ones measured do, and a partial UDP datagram is useless
// to the guest anyway.
func socksUDPReply(b []byte) (net.IP, uint16, []byte, bool) {
	if len(b) < 10 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return nil, 0, nil, false
	}
	switch b[3] {
	case 1: // IPv4
		return net.IP(b[4:8]), binary.BigEndian.Uint16(b[8:10]), b[10:], true
	case 4: // IPv6
		if len(b) < 22 {
			return nil, 0, nil, false
		}
		return net.IP(b[4:20]), binary.BigEndian.Uint16(b[20:22]), b[22:], true
	default:
		// A DOMAIN IN A REPLY (ATYP 3) IS REFUSED: this relay asked with an address or a name and needs
		// an ADDRESS back to build the packet the guest receives - a reply naming a domain gives it
		// nothing to put in the source field, and resolving it here would be a second lookup on the
		// reply path.
		return nil, 0, nil, false
	}
}
