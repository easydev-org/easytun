// A SOCKS5 UDP SERVER THAT RECORDS THE DESTINATION IT WAS ASKED FOR.
//
// THIS IS THE UPSTREAM FOR THE EGRESS END-TO-END TEST, AND IT IS DELIBERATELY NOT A PROXY. Nothing is
// forwarded anywhere: the test's question is "WHICH upstream did this datagram go to", and the answer
// has to be a property of the upstream rather than of a far end that may or may not be reachable. A
// proxy that reached a real host would make the test depend on that host's availability, so a network
// problem would look like a routing bug.
//
// WHAT IT DOES, AND NO MORE:
//
//	greeting        accept no-auth
//	UDP ASSOCIATE   answer with a relay address on loopback
//	one datagram    append "<destination-ip>:<destination-port>" to the log, then answer with
//	                "<tag>:<payload>" so the reply ALSO carries the evidence
//
// THE LOG AND THE TAG ARE TWO RECORDS OF ONE FACT. The driver in the container compares the tag it
// received; the workflow reads the log from outside the container. A bug that forged one would have to
// forge the other in a different process.
//
// IT IS A SEPARATE MODULE (`go.mod` beside it) so the library's own `go build ./...` does not compile
// a program that exists only for this test.
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
	tag := flag.String("tag", "?", "prefixed to every reply, so the caller knows which proxy answered")
	logPath := flag.String("log", "", "file to append each destination to")
	flag.Parse()

	if *logPath == "" {
		log.Fatal("--log is required: the log IS the assertion")
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("listening on %d: %v", *port, err)
	}
	fmt.Printf("socks[%s] listening on %d, logging to %s\n", *tag, *port, *logPath)
	os.Stdout.Sync()

	var mu sync.Mutex
	record := func(ip string, port uint16) {
		line := fmt.Sprintf("%s:%d\n", ip, port)
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		_, _ = f.WriteString(line)
		_ = f.Close()
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c, *tag, record)
	}
}

func handle(c net.Conn, tag string, record func(string, uint16)) {
	defer c.Close()

	// GREETING: VER NMETHODS METHODS -> VER METHOD
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

	// REQUEST: VER CMD RSV ATYP, then the address and port. Only UDP ASSOCIATE (3) is handled.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 3 {
		// A CONNECT IS REFUSED, NOT IGNORED: this server exists to carry datagrams, and a silent
		// close would make the caller wait for a timeout instead of learning why.
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // rep 7 = command not supported
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
	_, _ = io.ReadFull(c, make([]byte, 2)) // the client's own address, unused

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
		ip, port, payload, ok := parseRequest(buf[:n])
		if !ok {
			continue
		}
		// THE RECORD: one line per datagram, naming the destination it was addressed to.
		record(ip, port)
		fmt.Printf("socks[%s] carried %s:%d\n", tag, ip, port)
		os.Stdout.Sync()

		// THE REPLY, tagged so the caller can tell which proxy answered.
		body := append([]byte(tag+":"), payload...)
		out := make([]byte, 10+len(body))
		out[3] = 1
		copy(out[4:8], net.ParseIP(ip).To4())
		binary.BigEndian.PutUint16(out[8:10], port)
		copy(out[10:], body)
		_, _ = udp.WriteToUDP(out, from)
	}
}

// parseRequest reads RSV(2) FRAG(1) ATYP(1) ADDR PORT(2) DATA out of one SOCKS5 UDP frame.
func parseRequest(b []byte) (string, uint16, []byte, bool) {
	if len(b) < 10 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", 0, nil, false
	}
	switch b[3] {
	case 1:
		return net.IP(b[4:8]).String(), binary.BigEndian.Uint16(b[8:10]), b[10:], true
	case 3:
		l := int(b[4])
		if len(b) < 5+l+2 {
			return "", 0, nil, false
		}
		// A DOMAIN DESTINATION IS RECORDED AS ITS NAME, because that is what the caller asked for and
		// it is what the egress test asserts on when a fake address is in play.
		return string(b[5 : 5+l]), binary.BigEndian.Uint16(b[5+l : 5+l+2]), b[5+l+2:], true
	}
	return "", 0, nil, false
}
