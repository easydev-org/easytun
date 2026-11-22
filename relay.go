package easytun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// THE RELAY: ONE TUN DEVICE, ONE SESSION TABLE, ONE SOCKS5 UPSTREAM.
//
// It is deliberately not a framework. A caller says "relay this guest's UDP" and gets a handle that
// forwards until it is closed. Anything a datagram needs beyond that - which destinations are
// allowed, which take a different path - is a callback, because a library that also decides policy
// is a library that has to guess what the caller's policy language is.

const (
	sessionIdle = 2 * time.Minute
	sweepEvery  = 30 * time.Second
)

// Config is what Start needs.
type Config struct {
	// GuestIP is the address whose UDP is relayed, e.g. "172.30.0.2". Required.
	GuestIP string
	// Upstream is the SOCKS5 address, "host:port". Empty means every flow is direct and no proxy is
	// used - which is the right configuration for a runner that already has a working route.
	Upstream string
	// Name is the tun device's name. Empty means "tun0". It must be unique per network namespace:
	// two relays in one namespace that share a name also share a device, and the second's reads
	// steal the first's packets.
	Name string
	// Table is the policy-routing table number. Zero means "pick one from the name", so two relays
	// in different namespaces do not collide and two in the same one do not either.
	Table int
	// Route decides where one flow goes. Nil means "everything through Upstream".
	Route func(dst net.IP, port uint16) Route
	// Logf receives one line per failure. Nil means no logging.
	Logf func(format string, args ...any)
}

// Route is what a callback returns for one flow.
type Route struct {
	// Direct sends the datagram from this host with no proxy.
	Direct bool
	// Drop discards it. There is no RST in UDP, so the guest's client times out - which is what a
	// filtered port looks like everywhere.
	Drop bool
	// Upstream overrides Config.Upstream for this flow. Empty means the configured one.
	Upstream string
	// Host is the NAME the guest asked for, when the destination is one this caller invented (a fake
	// address). It is sent to the proxy in place of the address, because a fake address exists nowhere
	// and `UDP ASSOCIATE 198.18.7.3` would be a request for a host that cannot be reached.
	//
	// EMPTY MEANS "DIAL THE ADDRESS", which is every flow that was not invented: a guest resolving a
	// real name gets a real address, and there is nothing to substitute.
	Host string
}

// tunDevice is what the relay needs from a tun: packets in, packets out, and a close.
//
// IT IS AN INTERFACE SO THE FORWARDING PATH CAN BE TESTED. The real device needs NET_ADMIN and a
// container that mounted /dev/net/tun, and a test that only ran there would be a test nobody runs -
// so the whole relay is driven in the test suite through a pipe.
type tunDevice interface {
	io.Reader
	io.Writer
	io.Closer
}

// openDevice is a variable so a test can hand the relay a pipe instead of a real tun.
var openDevice = func(name string) (tunDevice, error) { return openTun(name) }

// Relay forwards UDP until Close.
type Relay struct {
	tun      tunDevice
	upstream string
	route    func(net.IP, uint16) Route
	logf     func(string, ...any)

	name  string
	table int
	guest string

	mu       sync.Mutex
	sessions map[key]*session

	done chan struct{}
	once sync.Once
	// closed records the first Close's error, so a caller that runs it twice learns whether the
	// cleanup actually happened rather than getting a silent second success.
	closedErr error
}

// key identifies a flow by its two endpoints, so a reply can be addressed back to the guest.
type key struct {
	guestIP   [4]byte
	guestPort uint16
	dstIP     [4]byte
	dstPort   uint16
	// host is the name a fake address stands for, and it is PART OF THE KEY: two guests (or one
	// guest, twice) reaching the same fake address is one name, but a session must not be shared with
	// a flow to the same address carrying a different name - which cannot happen with one caller, and
	// is prevented here rather than assumed.
	host string
}

type session struct {
	ctl   net.Conn
	relay *net.UDPAddr
	sock  *net.UDPConn
	last  time.Time
	mu    sync.Mutex
	// direct says this flow bypasses the proxy: ctl is nil and sock is CONNECTED to the destination
	// rather than to a relay, so a reply from any other peer is filtered by the kernel.
	direct bool
	// upstream is the SOCKS5 address this session was opened against, so a rule change is noticed
	// when the same flow next uses it.
	upstream string
}

// Start brings up the tun device and begins forwarding.
//
// IT RETURNS A NIL RELAY AND NO ERROR WHEN GuestIP IS EMPTY, because that is "nothing to relay"
// rather than a failure: a caller whose guest has no address has not made a mistake.
func Start(cfg Config) (*Relay, error) {
	if cfg.GuestIP == "" {
		return nil, nil
	}
	ip := net.ParseIP(cfg.GuestIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("easytun: guest IP %q is not an IPv4 address", cfg.GuestIP)
	}
	name := cfg.Name
	if name == "" {
		name = "tun0"
	}
	table := chooseTable(name, cfg.Table)
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	tun, err := openDevice(name)
	if err != nil {
		return nil, err
	}

	// THE DEVICE IS ADDRESSED AND RAISED BEFORE ANY ROUTE POINTS AT IT. A route into a DOWN device is
	// accepted and then blackholes everything it captures - MEASURED as `default dev tunproto
	// linkdown` on the way to a relay that never saw a packet.
	//
	// THE ADDRESS IS DERIVED FROM THE TABLE THAT WAS CHOSEN, not a constant: two relays in one network
	// namespace - what `--network container:` produces - cannot both hold one /24 on two devices, and
	// the second `ip addr add` would fail with EEXIST and read as an unrelated network error. Deriving
	// it from the chosen table rather than the hash means a relay that was pushed off its bucket still
	// gets an address no other relay holds.
	cidr := fmt.Sprintf("%s/24", addrFor(table))
	if err := bringUp(name, cidr); err != nil {
		_ = tun.Close()
		_ = deleteTun(name)
		return nil, err
	}

	r := &Relay{
		tun:      tun,
		upstream: cfg.Upstream,
		route:    cfg.Route,
		logf:     logf,
		name:     name,
		table:    table,
		guest:    cfg.GuestIP,
		sessions: map[key]*session{},
		done:     make(chan struct{}),
	}

	if err := installPolicy(name, cfg.GuestIP, table); err != nil {
		_ = r.Close()
		return nil, err
	}

	go r.readTun()
	go r.sweep()
	return r, nil
}

// bringUp addresses the device and raises it.
//
// A ROUTE INTO A DOWN DEVICE IS ACCEPTED AND THEN BLACKHOLES EVERYTHING IT CAPTURES - MEASURED as
// `default dev tunproto linkdown` on the way to a relay that never saw a packet. So the address and
// the link state come before any route points here.
//
// IT IS A VARIABLE SO THE TEST CAN SKIP IT. The forwarding path - sessions, framing, the tun write -
// is what must be right, and a test that needed NET_ADMIN to reach it would be a test that only runs
// in one kind of container.
var bringUp = func(name, cidr string) error {
	for _, cmd := range [][]string{
		{"addr", "add", cidr, "dev", name},
		{"link", "set", name, "up"},
	} {
		if out, err := run("ip", cmd...); err != nil {
			return fmt.Errorf("`ip %v`: %v (%s)", cmd, err, firstLine(out))
		}
	}
	return nil
}

// installPolicy sends only this guest's UDP into table `table`.
//
// `ipproto udp` IS WHAT KEEPS TCP OUT. Without it every connection the guest makes would arrive here
// instead of at the CONNECT proxy that carries them today.
var installPolicy = func(name, guestIP string, table int) error {
	spec := guestIP + "/32"
	for _, step := range [][]string{
		{"route", "replace", "default", "dev", name, "table", strconv.Itoa(table)},
		{"rule", "add", "from", spec, "ipproto", "udp", "lookup", strconv.Itoa(table)},
	} {
		if out, err := run("ip", step...); err != nil {
			// A RULE THAT ALREADY EXISTS IS NOT A FAILURE: Start can be called twice on a daemon that
			// was restarted without its network being torn down, and EEXIST is the same state.
			if !contains(out, "File exists") {
				return fmt.Errorf("`ip %v`: %v (%s)", step, err, firstLine(out))
			}
		}
	}
	return nil
}

// removePolicy undoes installPolicy, and reports what it could not remove.
//
// THE RULE GOES BEFORE THE ROUTE, AND BOTH ARE REPORTED. The previous version discarded these errors,
// so a second Start in the same namespace accumulated stale rules - which send the guest's UDP into a
// table with no default route, failing closed and silently.
var removePolicy = func(guestIP string, table int) error {
	spec := guestIP + "/32"
	var problems []string
	if out, err := run("ip", "rule", "del", "from", spec, "ipproto", "udp",
		"lookup", strconv.Itoa(table)); err != nil && !contains(out, "No such file") {
		problems = append(problems, fmt.Sprintf("rule: %v (%s)", err, firstLine(out)))
	}
	if out, err := run("ip", "route", "flush", "table", strconv.Itoa(table)); err != nil {
		problems = append(problems, fmt.Sprintf("route: %v (%s)", err, firstLine(out)))
	}
	if len(problems) > 0 {
		return fmt.Errorf("easytun: cleanup left state behind: %v", problems)
	}
	return nil
}

// removeDevice deletes the tun device, treating "already gone" as success.
var removeDevice = deleteTun

// tableFor derives a STARTING policy-routing table from the device name.
//
// IT IS NOT A GUARANTEE, because 100 buckets cannot hold an unbounded set of names without a
// collision - two relays in one namespace that hash to the same bucket would install their rules
// into one table and each would see the other's traffic. `chooseTable` probes from here until it
// finds one that is empty, so this only has to spread names out well.
//
// The range is the one `ip rule` accepts without colliding with the kernel's reserved tables (0,
// 253, 254, 255).
func tableFor(name string) int {
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= 16777619
	}
	return 100 + int(h%100)
}

// chooseTable returns the table this relay will use: the caller's if it named one, otherwise the
// first empty table at or after the name's hash.
//
// THE HASH ALONE IS NOT ENOUGH. Two devices in one namespace whose names collide would share a
// table, and the second `ip rule add` is not distinguishable from the first - so traffic for one
// guest would be routed into the other's relay. Probing makes the promise true; the hash only
// decides where to start looking.
func chooseTable(name string, explicit int) int {
	if explicit != 0 {
		return explicit
	}
	start := tableFor(name)
	for i := 0; i < 100; i++ {
		n := 100 + (start-100+i)%100
		if !tableInUse(n) {
			return n
		}
	}
	return start
}

// tableInUse answers whether a policy table already holds a route in this namespace.
//
// IT IS A VARIABLE SO THE TEST CAN ANSWER WITHOUT `ip`, because the probing logic is what must be
// right and a runner without NET_ADMIN cannot show it a populated table.
var tableInUse = func(n int) bool {
	out, err := run("ip", "route", "show", "table", strconv.Itoa(n))
	if err != nil {
		// A TABLE THAT CANNOT BE READ IS ONE THIS RELAY WILL FAIL TO WRITE TO ANYWAY, and Start
		// reports that with the command's own message. Treating it as empty here keeps the loop from
		// silently skipping every table on a permission problem.
		return false
	}
	return strings.TrimSpace(out) != ""
}

// addrFor derives the device's own address from its chosen routing table, so two relays in one
// namespace cannot claim the same /24.
//
// 10.99.0.0/16 is the range this package owns for relay devices, and the third octet comes from the
// table number so the address and the routing table move together - a reader who sees table 137 can
// predict 10.99.37.1.
func addrFor(table int) string {
	// A THIRD OCTET FROM THE TABLE'S LAST TWO DIGITS, so the default range (100..199) maps to
	// 0..99 and an explicit table outside it still yields a valid octet instead of 10.99.400.1.
	octet := ((table % 100) + 100) % 100
	return fmt.Sprintf("10.99.%d.1", octet)
}

// ---------------------------------------------------------------- the tun side

func (r *Relay) readTun() {
	buf := make([]byte, 65535)
	for {
		n, err := r.tun.Read(buf)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			// A READ ERROR ON A TUN DEVICE IS NOT ALWAYS FATAL - EINTR arrives when the process
			// handles a signal - but a closed device must not spin.
			if errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		srcIP, dstIP, srcPort, dstPort, payload, ok := parseIPv4UDP(buf[:n])
		if !ok {
			continue
		}
		var k key
		copy(k.guestIP[:], srcIP.To4())
		copy(k.dstIP[:], dstIP.To4())
		k.guestPort, k.dstPort = srcPort, dstPort
		// THE IP CHECKSUM IS NOT VERIFIED. A malformed packet is one the far end will drop; the cost
		// of checking it is a per-packet pass over data that has already crossed a hypervisor.
		if err := r.forward(k, payload); err != nil {
			r.logf("easytun: %v", err)
		}
	}
}

func (r *Relay) forward(k key, payload []byte) error {
	dstIP := net.IP(k.dstIP[:])
	var route Route
	if r.route != nil {
		route = r.route(dstIP, k.dstPort)
	}
	if route.Drop {
		return nil
	}
	// THE NAME, WHEN THE CALLER NAMED ONE. A fake destination is an address this caller invented, so
	// the only thing that can reach the real host is the name - and that name is also what the SOCKS5
	// request sends.
	if route.Host != "" {
		k.host = route.Host
	}

	if route.Direct {
		// A DIRECT FLOW WITH A NAME DIALS THE NAME, because a fake address leads nowhere and the
		// caller told us what it stands for.
		return r.forwardDirect(k, dstIP, payload)
	}

	target := r.upstream
	if route.Upstream != "" {
		target = route.Upstream
	}
	if target == "" {
		// NO PROXY CONFIGURED: direct is the honest answer, and it is what a runner whose route
		// already works needs.
		return r.forwardDirect(k, dstIP, payload)
	}

	s, err := r.sessionFor(k, target)
	if err != nil {
		return err
	}
	framed := socksUDPTarget(k.dstIP, k.dstPort, k.host, payload)
	s.mu.Lock()
	_, err = s.sock.WriteToUDP(framed, s.relay)
	s.mu.Unlock()
	return err
}

// forwardDirect sends a datagram without the proxy, and arranges for the reply.
//
// A DIRECT FLOW NEEDS ITS OWN SOCKET, because a reply must be matched to the guest's endpoint. The
// session table holds it under the same key as a proxied flow, so a flow cannot be both.
func (r *Relay) forwardDirect(k key, dstIP net.IP, payload []byte) error {
	r.mu.Lock()
	existing, ok := r.sessions[k]
	if !ok {
		// A NAMED DIRECT FLOW DIALS THE NAME. The address in the packet is one the caller invented, so
		// dialling it would send the datagram to an address that belongs to nothing.
		addr := &net.UDPAddr{IP: dstIP, Port: int(k.dstPort)}
		if k.host != "" {
			resolved, err := net.ResolveUDPAddr("udp",
				net.JoinHostPort(k.host, strconv.Itoa(int(k.dstPort))))
			if err != nil {
				r.mu.Unlock()
				return err
			}
			addr = resolved
		}
		sock, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		existing = &session{sock: sock, last: time.Now(), direct: true}
		r.sessions[k] = existing
		go r.drainDirect(k, existing)
	}
	existing.last = time.Now()
	r.mu.Unlock()

	_, err := existing.sock.Write(payload)
	return err
}

// drainDirect reads replies on a direct socket and writes them into the tun.
func (r *Relay) drainDirect(k key, s *session) {
	buf := make([]byte, 65535)
	for {
		n, err := s.sock.Read(buf)
		if err != nil {
			return
		}
		// THE SOURCE IS THE DESTINATION THE GUEST ASKED FOR. A connected UDP socket answers only for
		// that peer, so the address in the packet is always k.dst - stated rather than re-read.
		pkt := buildIPv4UDP(net.IP(k.dstIP[:]), k.dstPort, k.guestIP[:], k.guestPort, buf[:n])
		if _, err := r.tun.Write(pkt); err != nil {
			return
		}
	}
}

// sessionFor returns the session for a flow, creating one on first use.
func (r *Relay) sessionFor(k key, upstream string) (*session, error) {
	r.mu.Lock()
	if s, ok := r.sessions[k]; ok {
		s.last = time.Now()
		r.mu.Unlock()
		return s, nil
	}
	r.mu.Unlock()

	s, err := newSession(upstream)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	// A SECOND GOROUTINE MAY HAVE CREATED ONE WHILE THE DIAL WAS IN FLIGHT. Keeping the newer one
	// would leak the older session's socket and its control connection.
	if existing, ok := r.sessions[k]; ok {
		r.mu.Unlock()
		s.close()
		return existing, nil
	}
	r.sessions[k] = s
	r.mu.Unlock()

	go r.drainReplies(k, s)
	return s, nil
}

// drainReplies turns one SOCKS5 UDP reply into one packet written into the tun.
//
// THE REPLY MUST LOOK LIKE IT CAME FROM WHERE THE GUEST SENT IT. That is the whole illusion: the
// guest asked 104.18.27.14:443 and would discard a datagram from 10.99.0.1.
func (r *Relay) drainReplies(k key, s *session) {
	buf := make([]byte, 65535)
	for {
		n, err := s.sock.Read(buf)
		if err != nil {
			return
		}
		srcIP, srcPort, payload, ok := socksUDPReply(buf[:n])
		if !ok {
			continue
		}
		pkt := buildIPv4UDP(srcIP, srcPort, k.guestIP[:], k.guestPort, payload)
		if _, err := r.tun.Write(pkt); err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			return
		}
	}
}

// sweep closes sessions that have seen no traffic, because UDP has no close and a QUIC flow that is
// finished leaves nothing behind to tell us.
func (r *Relay) sweep() {
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			cut := time.Now().Add(-sessionIdle)
			r.mu.Lock()
			for k, s := range r.sessions {
				if s.last.Before(cut) {
					delete(r.sessions, k)
					s.close()
				}
			}
			r.mu.Unlock()
		}
	}
}

// Close stops the relay and removes every trace of it from this namespace.
//
// IT REPORTS WHAT IT COULD NOT REMOVE. The old version discarded those errors, so a second Start in
// the same namespace accumulated stale rules - which send the guest's UDP into a table with no
// default route, failing closed and silently.
func (r *Relay) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		close(r.done)
		_ = r.tun.Close()

		r.mu.Lock()
		for k, s := range r.sessions {
			delete(r.sessions, k)
			s.close()
		}
		r.mu.Unlock()

		var problems []string
		if err := removePolicy(r.guest, r.table); err != nil {
			problems = append(problems, err.Error())
		}
		if err := removeDevice(r.name); err != nil {
			problems = append(problems, err.Error())
		}
		if len(problems) > 0 {
			r.closedErr = fmt.Errorf("easytun: cleanup left state behind: %v", problems)
		}
	})
	return r.closedErr
}

// ---------------------------------------------------------------- SOCKS5

func newSession(upstream string) (*session, error) {
	ctl, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("easytun: control connection to %s: %w", upstream, err)
	}
	if _, err := ctl.Write([]byte{5, 1, 0}); err != nil { // SOCKS5, one method, no auth
		ctl.Close()
		return nil, err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(ctl, greeting); err != nil {
		ctl.Close()
		return nil, err
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		ctl.Close()
		return nil, fmt.Errorf("easytun: %s refused no-auth (%v)", upstream, greeting)
	}
	// UDP ASSOCIATE, with 0.0.0.0:0 meaning "the address this connection came from".
	if _, err := ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		ctl.Close()
		return nil, err
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(ctl, hdr); err != nil {
		ctl.Close()
		return nil, err
	}
	if hdr[1] != 0 {
		ctl.Close()
		return nil, fmt.Errorf("easytun: %s refused UDP ASSOCIATE (rep=%d)", upstream, hdr[1])
	}
	relayIP := net.IP(hdr[4:8])
	relayPort := binary.BigEndian.Uint16(hdr[8:10])

	// AN UNSPECIFIED RELAY ADDRESS MEANS THE PROXY ITSELF - a common answer, and the only one where
	// the port alone is meaningful.
	relayAddr := &net.UDPAddr{IP: relayIP, Port: int(relayPort)}
	if relayIP.IsUnspecified() {
		host, _, _ := net.SplitHostPort(upstream)
		if a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(relayPort)))); err == nil {
			relayAddr = a
		}
	}
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		ctl.Close()
		return nil, err
	}
	return &session{ctl: ctl, relay: relayAddr, sock: sock, last: time.Now(), upstream: upstream}, nil
}

func (s *session) close() {
	if s.sock != nil {
		_ = s.sock.Close()
	}
	// A DIRECT SESSION HAS NO CONTROL CONNECTION; closing a nil interface would panic.
	if s.ctl != nil {
		_ = s.ctl.Close()
	}
}

// contains reports whether a command's output names a substring, for the "already gone" cases where
// the exit status is the same but the state is the one we wanted.
func contains(s, sub string) bool {
	return sub != "" && strings.Contains(s, sub)
}
