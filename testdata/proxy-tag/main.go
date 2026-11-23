// A SOCKS5 UDP SERVER THAT TAGS ITS REPLIES, FOR THE CONTAINER MODE'S EGRESS TEST.
//
// THIS IS NOT A PROXY. Nothing is forwarded: the question is "which upstream did this datagram go to",
// and the answer has to be a property of the upstream rather than of a far end that may or may not be
// reachable. A proxy that reached a real host would make the test depend on that host's availability,
// so a network problem would look like a routing bug.
//
// WHAT IT DOES:
//
//	greeting        accept no-auth
//	UDP ASSOCIATE   answer with a relay address on the bind interface
//	one datagram    append "<destination>:<port>" to the log, then answer "<tag>:<payload>"
//
// THE TAG NAMES THE PATH. A workload that gets "A:..." back knows proxy A carried it; the log is the
// same fact from outside the container, so the workflow can assert on it even when the container is
// gone.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "TCP port for the SOCKS5 control connection")
	tag := flag.String("tag", "?", "prefixed to every reply, naming this proxy")
	logPath := flag.String("log", "", "file to append each destination to")
	bind := flag.String("bind", "0.0.0.0", "address to listen on; 0.0.0.0 so another namespace can reach it")
	flag.Parse()

	if *logPath == "" {
		log.Fatal("--log is required: the log IS the assertion")
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *bind, *port))
	if err != nil {
		log.Fatalf("listening on %s:%d: %v", *bind, *port, err)
	}
	fmt.Printf("socks[%s] listening on %s:%d\n", *tag, *bind, *port)
	os.Stdout.Sync()

	var mu sync.Mutex
	record := func(addr string) {
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		fmt.Fprintln(f, addr)
		_ = f.Close()
		fmt.Printf("socks[%s] carried %s\n", *tag, addr)
		os.Stdout.Sync()
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c, *tag, record)
	}
}

func handle(c net.Conn, tag string, record func(string)) {
	defer c.Close()

	// GREETING: VER NMETHODS METHODS -> VER METHOD
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

	// REQUEST: VER CMD RSV ATYP, then the address and port. Only UDP ASSOCIATE (3).
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 3 {
		// A CONNECT IS REFUSED, NOT IGNORED: this server carries datagrams, and a silent close would
		// make the caller wait for a timeout instead of learning why.
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
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

	// THE RELAY ADDRESS MUST BE ONE THE CALLER CAN REACH. It answers with the address it was reached
	// on, because the caller is in another container and 127.0.0.1 there is not this process.
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		return
	}
	defer udp.Close()

	rep := make([]byte, 10)
	rep[0], rep[1], rep[3] = 5, 0, 1
	copy(rep[4:8], local.IP.To4())
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
		addr, payload, ok := parseRequest(buf[:n])
		if !ok {
			continue
		}
		record(addr)

		// THE REPLY, tagged so the workload can tell which proxy answered.
		body := append([]byte(tag+":"), payload...)
		out := make([]byte, 10+len(body))
		out[3] = 1
		// THE SOURCE IS THE DESTINATION THE WORKLOAD ASKED FOR, which is what the relay puts in the
		// packet it writes back. Using the proxy's own address would make the workload discard it.
		copy(out[4:8], mustIPv4(addr))
		binary.BigEndian.PutUint16(out[8:10], mustPort(addr))
		copy(out[10:], body)
		_, _ = udp.WriteToUDP(out, from)
	}
}

// parseRequest reads RSV(2) FRAG(1) ATYP(1) ADDR PORT(2) DATA out of one SOCKS5 UDP frame.
func parseRequest(b []byte) (string, []byte, bool) {
	if len(b) < 10 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", nil, false
	}
	switch b[3] {
	case 1:
		return net.JoinHostPort(net.IP(b[4:8]).String(),
			fmt.Sprint(binary.BigEndian.Uint16(b[8:10]))), b[10:], true
	case 3:
		l := int(b[4])
		if len(b) < 5+l+2 {
			return "", nil, false
		}
		return net.JoinHostPort(string(b[5:5+l]),
			fmt.Sprint(binary.BigEndian.Uint16(b[5+l:5+l+2]))), b[5+l+2:], true
	}
	return "", nil, false
}

// mustIPv4 is the address part of an address it just produced, so a parse failure cannot happen here.
func mustIPv4(addr string) []byte {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.IPv4zero.To4()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return net.IPv4zero.To4()
	}
	return ip.To4()
}

func mustPort(addr string) uint16 {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var n uint16
	for _, c := range port {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint16(c-'0')
	}
	return n
}
