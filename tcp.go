//go:build linux

package easytun

// THE TRANSPARENT TCP PROXY: A CLIENT THAT KNOWS NOTHING ABOUT PROXIES STILL GOES THROUGH ONE.
//
// THE PROBLEM THIS SOLVES IS MEASURED RATHER THAN IMAGINED. A route from one cluster to a package
// mirror was 38-68 KB/s - the same rate whether the download ran in the client or behind it, so
// nothing about the client was wrong - while the same proxy answered the same file in under a second.
// A desktop image is four to six hundred megabytes, which is three hours on that route and two minutes
// through the proxy.
//
// SETTING `http_proxy` IN THE CLIENT DOES NOT WORK, AND THAT IS THE POINT OF THIS FILE. A program that
// downloads honours that variable only if its author used a library that reads it - a bundled libcurl,
// a static Go binary, a `fetch(8)` call, a git submodule each answer differently, and a setup that
// works only for the tools that happened to read the variable measures those tools rather than the
// system.
//
// SO THE REDIRECTION IS DONE WHERE THE CLIENT CANNOT SEE IT. Its outbound TCP lands on this listener
// instead of the internet:
//
//	iptables -t nat -A <chain> -p tcp -j DNAT --to-destination <bind>:<port>
//
// and the caller writes that rule with the port this package reports. THE PACKAGE DOES NOT TOUCH
// IPTABLES: the rule is about the caller's topology, and a library that guessed it would be wrong for
// the second caller.
//
// WHY A LISTENER AT ALL. `DNAT` rewrites the DESTINATION and delivers the socket; it does not speak a
// proxy protocol. An HTTP proxy expects a
//
//	CONNECT pkg.example.org:443 HTTP/1.1
//
// line before the bytes, so this listener accepts the redirected connection, recovers the original
// destination from `SO_ORIGINAL_DST`, says that line to the proxy, and then copies bytes both ways.
// The client sees an ordinary TCP connection and never learns anything happened.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// FAKE-IP AND NAME RESOLUTION ARE HOOKS, NOT IMPORTS.
//
// The `names` subpackage owns the pool and the resolver, and this package must not import it: a caller
// that wants TCP only should not compile a DNS server, and a caller that wants neither should compile
// no pool at all. So the two things the TCP proxy needs from that world are variables a caller wires
// up - and left nil, the proxy simply never sees a fake destination, which is correct for a caller
// that does not use fake-ip.
var (
	// NameForFakeIP answers "is this address one this caller invented, and for what name".
	NameForFakeIP = func(net.IP) (string, bool) { return "", false }
	// ResolveRealName answers a name against the caller's real resolver, ignoring any fake pool.
	ResolveRealName = func(string) (net.IP, error) { return nil, fmt.Errorf("no resolver configured") }
)

// TCPConfig is what StartTCP needs.
type TCPConfig struct {
	// Bind is the address the listener binds, e.g. "172.30.0.1:0". Required.
	//
	// IT IS NOT LOOPBACK, AND THAT IS THE WHOLE FIX. MEASURED: a listener on 127.0.0.1 accepted nothing
	// from a forwarded packet - the client's traffic is not addressed to this machine, it is FORWARDED
	// through it, and 127.0.0.1 belongs to the client's own stack once the packet is no longer local.
	// The counter said so exactly: the redirect rule matched 108 packets and FORWARD accepted 0.
	//
	// USE PORT 0 and read Port() back: the port is written into an iptables rule, so a second proxy on
	// one host must not collide with the first.
	Bind string
	// Upstream is the HTTP CONNECT proxy, host:port. An empty value makes every connection direct,
	// which is the right configuration for a machine with no proxy.
	Upstream string
	// Route decides where one connection goes. Nil means "everything through Upstream".
	Route func(dst net.IP, port uint16) Route
	// Logf receives one line per failure. Nil means no logging.
	Logf func(format string, args ...any)
}

// TCP is a running listener.
type TCP struct {
	// Port is the port the listener bound, for the caller's redirect rule.
	Port int
	// Upstream is the proxy this listener tunnels to, empty when none was configured.
	Upstream string

	listener net.Listener
	route    func(net.IP, uint16) Route
	logf     func(string, ...any)
	done     chan struct{}
	once     sync.Once
}

// StartTCP listens and tunnels every connection to where its Route says.
//
// IT RETURNS A NIL LISTENER AND NO ERROR WHEN Bind IS EMPTY, which is "no proxy configured" rather
// than a failure - the caller's equivalent of a machine with no proxy at all.
func StartTCP(cfg TCPConfig) (*TCP, error) {
	if cfg.Bind == "" {
		return nil, nil
	}
	// THE UPSTREAM IS RESOLVED ONCE, AT START, so a process whose DNS is briefly broken fails here -
	// at startup, with a sentence - rather than on the client's first request.
	if cfg.Upstream != "" {
		host, port, err := net.SplitHostPort(cfg.Upstream)
		if err != nil {
			return nil, fmt.Errorf("the CONNECT proxy %q is not host:port: %w", cfg.Upstream, err)
		}
		if _, err := strconv.Atoi(port); err != nil {
			return nil, fmt.Errorf("the CONNECT proxy %q has no numeric port: %w", cfg.Upstream, err)
		}
		if _, err := net.LookupHost(host); err != nil {
			return nil, fmt.Errorf("the CONNECT proxy %q does not resolve: %w", cfg.Upstream, err)
		}
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	l, err := net.Listen("tcp", cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("listening for the transparent proxy on %s: %w", cfg.Bind, err)
	}
	p := &TCP{
		Port:     l.Addr().(*net.TCPAddr).Port,
		Upstream: cfg.Upstream,
		listener: l,
		route:    cfg.Route,
		logf:     logf,
		done:     make(chan struct{}),
	}
	go p.serve()
	return p, nil
}

// Close stops the listener.
func (p *TCP) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		close(p.done)
		_ = p.listener.Close()
	})
	return nil
}

// log reports one line, and is safe on a TCP built without StartTCP - which is what a test does, and
// what a caller that constructed the struct literal would do. A nil Logf is "no logging", not a panic.
func (p *TCP) log(format string, args ...any) {
	if p.logf != nil {
		p.logf(format, args...)
	}
}

func (p *TCP) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
			}
			// A FAILED ACCEPT IS NOT FATAL: the listener stays up and the next connection is handled.
			// Returning would turn one transient error into a proxy that silently stopped.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go p.handle(conn)
	}
}

// handle turns one redirected connection into one CONNECT request.
func (p *TCP) handle(conn net.Conn) {
	// THE CLIENT THINKS IT OPENED A CONNECTION TO THE INTERNET; THE KERNEL REMEMBERS WHERE IT WAS
	// GOING. SO_ORIGINAL_DST is that memory, and without it the destination is this listener's own
	// address - which would make the proxy connect back to itself.
	dst, err := OriginalDestination(conn)
	if err != nil {
		p.log("easytun: reading the original destination: %v", err)
		_ = conn.Close()
		return
	}
	p.Tunnel(conn, dst)
}

// Tunnel is the part that can be tested without a redirected socket, and it is exported for exactly
// that reason: `handle` needs SO_ORIGINAL_DST, which only the kernel can supply, so a test that went
// through `handle` could assert nothing but "the connection closed".
//
// IT TAKES THE DESTINATION rather than reading it, which is the whole seam: production passes the
// kernel's answer, and a test passes whatever it wants to see on the wire.
func (p *TCP) Tunnel(conn net.Conn, dst string) {
	defer conn.Close()

	// THE CALLBACK IS CONSULTED WITH WHATEVER THE DESTINATION GIVES. SO_ORIGINAL_DST always yields an
	// address, so in production this is an IP and a port; a test may pass a name, and skipping the
	// callback then would silently take the default path - which is exactly the kind of quiet wrong
	// answer a rule is supposed to prevent. So a name destination calls the callback with a nil IP and
	// the port, and the callback decides from the port alone if that is all it has.
	var route Route
	if p.route != nil {
		ip, port, err := splitDst(dst)
		if err != nil {
			port = portOfInt(dst)
			ip = nil
		}
		route = p.route(ip, port)
	}

	// THE NAME, WHEN THE DESTINATION IS ONE THE CALLER INVENTED. In fake-ip mode `dst` is an address
	// that exists nowhere, so `CONNECT 198.18.7.3:443` would ask the proxy for a host no one can reach.
	// The name is what the client asked for, so it is what the proxy is told.
	connectTo := dst
	if name, ok := NameForFakeIP(parseHost(dst)); ok {
		connectTo = net.JoinHostPort(name, portOf(dst))
	}

	switch route.Kind {
	case RouteDrop:
		// A REFUSED CONNECTION IS THE HONEST ANSWER, and closing is how it is delivered: the client
		// sees what a firewall looks like from inside.
		return
	case RouteDirect:
		// A DIRECT CONNECTION CANNOT DIAL A FAKE ADDRESS, because it leads back here. The name is
		// resolved against the upstreams directly, and the connection is made unproxied.
		target := dst
		if route.Host != "" {
			if real, err := ResolveRealName(route.Host); err == nil {
				target = net.JoinHostPort(real.String(), portOf(dst))
			}
		}
		up, err := net.DialTimeout("tcp", target, 15*time.Second)
		if err != nil {
			p.log("easytun: direct connection to %s: %v", target, err)
			return
		}
		defer up.Close()
		_ = up.SetDeadline(time.Time{})
		copyBoth(conn, up, up, true)
		return
	}

	upstream := p.Upstream
	if route.Upstream != "" {
		upstream = route.Upstream
	}
	if upstream == "" {
		// NO PROXY CONFIGURED: direct is the honest answer.
		up, err := net.DialTimeout("tcp", connectTo, 15*time.Second)
		if err != nil {
			p.log("easytun: direct connection to %s: %v", connectTo, err)
			return
		}
		defer up.Close()
		_ = up.SetDeadline(time.Time{})
		copyBoth(conn, up, up, true)
		return
	}

	// `CONNECT host:port HTTP/1.1` IS THE WHOLE PROTOCOL. There is no TLS to negotiate here: the
	// client's TLS runs end to end THROUGH this tunnel, which is why the proxy needs no certificate
	// and cannot read the traffic.
	up, err := net.DialTimeout("tcp", upstream, 15*time.Second)
	if err != nil {
		p.log("easytun: connecting to the proxy %s: %v", upstream, err)
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Time{})

	// THE CONNECT GOES TO THE PROXY, AND THE 200 COMES BACK BEFORE ANY CLIENT BYTE IS FORWARDED. A
	// tunnel that started copying first would send the client's ClientHello into a socket the proxy is
	// still expecting a request line on.
	if _, err := fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectTo, connectTo); err != nil {
		return
	}
	br := bufio.NewReader(up)
	resp, err := br.ReadString('\n')
	if err != nil {
		return
	}
	// `200` IS THE ONLY SUCCESS THE PROTOCOL HAS, and a proxy that refuses says 403 or 502 here.
	// Nothing is reported to the client: it sees its connection close, which is what a refused
	// connection looks like from inside a program that never knew a proxy was involved.
	if len(resp) < 12 || resp[9:12] != "200" {
		p.log("easytun: the proxy refused %s: %s", connectTo, firstLine(resp))
		return
	}
	// THE REST OF THE HEADERS ARE DRAINED, because they belong to the CONNECT response and not to the
	// tunnelled bytes behind it. A leftover `Proxy-Agent:` line would arrive as garbage at the front of
	// the client's TLS stream.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	copyBoth(conn, up, br, false)
}

// copyBoth runs the two directions.
//
// THE TWO PATHS GENUINELY NEED DIFFERENT ANSWERS, AND TREATING THEM THE SAME WAS A BUG.
//
// A CONNECT TUNNEL IS A BYTE PIPE: when one end closes the other has nothing left to say, and waiting
// would hold a socket open on a peer that has gone. That is `<-done`.
//
// A DIRECT CONNECTION IS NOT. MEASURED: with `<-done`, a `curl` printed `Connected ... port 80` and
// then `Operation timed out with 0 bytes received` - because the client's direction finished the
// moment its request line was written, `<-done` returned, and the deferred Close tore down a socket
// whose reply was still in flight. So the direct path waits for the reply, bounded, so a peer that
// half-closed and went silent cannot hold it open forever.
func copyBoth(guest net.Conn, up net.Conn, from io.Reader, drainReply bool) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, guest)
		// HALF-CLOSE, NOT CLOSE: the other direction may still have a response to deliver.
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(guest, from)
		if tc, ok := guest.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	if !drainReply {
		return
	}
	// A SHORT GRACE, NOT A SECOND FULL COPY. The reply is usually already in the kernel buffer or
	// arrives within a round trip; this window is for that, not for streaming a large body.
	_ = up.SetReadDeadline(time.Now().Add(5 * time.Second))
	<-done
}

// splitDst turns "1.2.3.4:443" into its parts, for the rules lookup.
func splitDst(dst string) (net.IP, uint16, error) {
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, 0, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("%q is not an address", host)
	}
	return ip, uint16(p), nil
}

func parseHost(dst string) net.IP {
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func portOf(dst string) string {
	_, port, err := net.SplitHostPort(dst)
	if err != nil {
		return ""
	}
	return port
}

// --- SO_ORIGINAL_DST ---
//
// THE FOUR CONSTANTS, DECLARED HERE RATHER THAN IMPORTED. `golang.org/x/sys/unix` has them, and so does
// every proxy implementation, but they are a dependency for four numbers that do not change: Linux's
// own values from <linux/netfilter_ipv4.h> and <linux/netfilter_ipv6/ip6_tables.h>.
const (
	// solIP is SOL_IP - the level SO_ORIGINAL_DST is asked at for an IPv4 socket.
	solIP = 0
	// solIPv6 is SOL_IPV6, the same question for an IPv6 socket.
	solIPv6 = 41
	// soOriginalDst is SO_ORIGINAL_DST, whose value is 80 for both families.
	soOriginalDst = 80
)

// OriginalDestination reads SO_ORIGINAL_DST from a redirected socket.
//
// THE OPTION'S NUMBER DIFFERS BY FAMILY: `80` at SOL_IP for IPv4 and at SOL_IPV6 for IPv6. Both are
// tried, because a client may reach either family and a proxy that worked only for v4 would fail on the
// first AAAA answer.
//
// THE PARSING IS BY HAND RATHER THAN THROUGH A LIBRARY: the payload is a `sockaddr_in` - family, port
// (network byte order), address, padding - and there is no protocol here worth a dependency for
// sixteen bytes.
func OriginalDestination(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a tcp connection")
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}
	var addr string
	var sockErr error
	err = rc.Control(func(fd uintptr) {
		addr, sockErr = originalDstFromFD(int(fd))
	})
	if err != nil {
		return "", err
	}
	return addr, sockErr
}

func originalDstFromFD(fd int) (string, error) {
	// SOL_IP = 0, SO_ORIGINAL_DST = 80. The buffer holds `struct sockaddr_in`, which is 16 bytes, so
	// 128 is generous and keeps a kernel that returns more from being truncated.
	buf := make([]byte, 128)
	n := uint32(len(buf))
	if err := getsockopt(fd, solIP, soOriginalDst, buf, &n); err != nil {
		// IPv6 IS TRIED SECOND, because a v4 socket answers ENOENT for the v6 option and the failure of
		// the first is not the answer.
		if err6 := getsockopt(fd, solIPv6, soOriginalDst, buf, &n); err6 != nil {
			return "", fmt.Errorf("SO_ORIGINAL_DST: v4: %v; v6: %v", err, err6)
		}
	}
	if n < 8 {
		return "", fmt.Errorf("SO_ORIGINAL_DST returned %d bytes", n)
	}
	// THE PORT IS BIG-ENDIAN AND SITS AT OFFSET 2: family is two bytes at 0, then the port.
	port := binary.BigEndian.Uint16(buf[2:4])
	var host string
	// FAMILY 10 IS AF_INET6, WHOSE ADDRESS IS AT OFFSET 8 AND IS SIXTEEN BYTES.
	if binary.LittleEndian.Uint16(buf[0:2]) == 10 {
		host = net.IP(buf[8:24]).String()
	} else {
		host = net.IP(buf[4:8]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// getsockopt is the raw syscall, because Go's net package exposes no way to ask for a socket option it
// does not know about, and SO_ORIGINAL_DST is not one it knows.
func getsockopt(fd, level, opt int, buf []byte, n *uint32) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(n)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// portOfInt is the destination's port, or 0 when it cannot be read. Used for the callback when the
// host part is a name rather than an address.
func portOfInt(dst string) uint16 {
	_, port, err := net.SplitHostPort(dst)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return uint16(n)
}
