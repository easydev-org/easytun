// Package names answers DNS and remembers what it learned, so a rule about a NAME can be enforced on
// a connection that carries only an ADDRESS.
//
// THE PROBLEM THIS EXISTS FOR. A policy rule can say "block .doubleclick.net", but a connection is
// addressed to `142.250.1.1:443` - the name is gone by then. So somebody has to have watched the DNS
// answer that produced that address and kept it. This package is that somebody: it answers the
// client's queries, records the A and AAAA answers with the query's own TTL, and offers two lookups -
// "what names does this address have" and, optionally, the reverse via invented addresses.
//
// TWO MODES, AND THE DIFFERENCE IS WHERE THE NAME LIVES:
//
//	real-ip   forwards the query and records what came back. A rule matches for the addresses the
//	          client actually resolved, and misses for any it reached another way.
//
//	fake-ip   answers with an address out of a private pool and records the mapping. Every connection
//	          to that address carries the name because this package put it there, so a rule cannot
//	          miss - at the cost that an address this package cannot name cannot be reached at all.
//
// IT KNOWS NOTHING ABOUT THE CALLER. No interfaces, no bridge, no guest: it binds an address it is
// given and answers whoever asks. That is what makes it usable outside the virtual machine it was
// written for.
package names

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// --- the name table ---

// table maps an address back to the names it was resolved for.
//
// IT IS KEYED BY ADDRESS BECAUSE THAT IS THE LOOKUP A CONNECTION PERFORMS: the proxy has an address
// and asks "what was this called". The reverse would be a map per name, which answers a question
// nothing asks at connection time.
type table struct {
	mu sync.RWMutex
	// byIP holds every name an address has been seen for. A single address can serve many names (a
	// CDN), and a rule matching ANY of them should match the connection.
	byIP map[string]*entry
}

type entry struct {
	names []string
	// exp is when the LAST name in this entry expires. Entries are evicted whole, which is coarser
	// than per-name expiry and much simpler: a stale name on a shared address can only cause a rule
	// to match that would not have, and the TTL it was recorded with is the upstream's own.
	exp time.Time
}

var known = &table{byIP: map[string]*entry{}}

// Remember records that ip answered for name until the given expiry.
func Remember(ip, name string, ttl time.Duration) {
	known.remember(ip, name, ttl)
}

func (t *table) remember(ip, name string, ttl time.Duration) {
	if ttl <= 0 {
		// A ZERO TTL MEANS "DO NOT CACHE", and honouring it is what keeps a rule that depends on a
		// load balancer's short answers from matching an address the name no longer has.
		return
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	e := time.Now().Add(ttl)

	t.mu.Lock()
	defer t.mu.Unlock()
	ent := t.byIP[ip]
	if ent == nil {
		ent = &entry{}
		t.byIP[ip] = ent
	}
	for _, n := range ent.names {
		if n == name {
			if e.After(ent.exp) {
				ent.exp = e
			}
			return
		}
	}
	ent.names = append(ent.names, name)
	if e.After(ent.exp) {
		ent.exp = e
	}
}

func (t *table) namesFor(ip string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e := t.byIP[ip]
	if e == nil || time.Now().After(e.exp) {
		return nil
	}
	return append([]string(nil), e.names...)
}

func (t *table) sweep() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, e := range t.byIP {
		if now.After(e.exp) {
			delete(t.byIP, ip)
		}
	}
}

// For returns the names an address was resolved for.
//
// IT RETURNS AN EMPTY SLICE FOR AN UNKNOWN ADDRESS, and every caller must treat that as "no name rule
// can match" rather than as an error - a connection to a literal address is a legitimate thing for a
// program to make, and it is exactly the case a name rule cannot cover.
func For(ip net.IP) []string {
	if ip == nil {
		return nil
	}
	return known.namesFor(ip.String())
}

// --- the server ---

// Server answers one client's queries on one address.
type Server struct {
	upstreams []string
	conn      *net.UDPConn
	done      chan struct{}
	once      sync.Once
	fake      bool
}

// Config is what Start needs.
type Config struct {
	// Bind is the address to answer on, e.g. "172.30.0.1:53". Required.
	Bind string
	// Upstreams are the resolvers to forward to, host or host:port. A bare address means port 53.
	Upstreams []string
	// FakeIP answers with invented addresses from the pool instead of forwarding. See the package
	// comment for what that buys and what it costs.
	FakeIP bool
}

// Start binds the resolver.
//
// IT BINDS THE ADDRESS IT IS GIVEN AND NOT 0.0.0.0, because the caller decides who may ask: in the
// virtual machine this was written for, the answer is the bridge and nothing else.
func Start(cfg Config) (*Server, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("no upstream resolvers: DNS that answers nothing is worse than none")
	}
	addr, err := net.ResolveUDPAddr("udp", cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("%s is not an address to bind: %w", cfg.Bind, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", cfg.Bind, err)
	}
	s := &Server{upstreams: cfg.Upstreams, conn: conn, done: make(chan struct{}), fake: cfg.FakeIP}
	go s.serve()
	go s.sweep()
	return s, nil
}

// Close stops the listener.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}

// Addr is the address the server is bound to, for a caller that asked for ":0".
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

func (s *Server) sweep() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			known.sweep()
			pool.sweep()
		}
	}
}

func (s *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		query := append([]byte(nil), buf[:n]...)
		go s.handle(query, from)
	}
}

// handle answers one query.
//
// TWO MODES, AND THEY ANSWER THE SAME QUESTION DIFFERENTLY:
//
//	real-ip   forward it, record what came back, return the upstream's answer.
//	fake-ip   invent an address for the name and return that, without forwarding.
//
// A MALFORMED QUERY IS STILL FORWARDED IN REAL-IP MODE. This is a resolver, not a validator: the
// upstream's own answer (or refusal) is more informative than silence, and refusing here would make a
// broken client look like a broken network.
func (s *Server) handle(query []byte, from *net.UDPAddr) {
	name, qtype, ok := parseQuestion(query)

	if s.fake && ok {
		// AAAA IS ANSWERED EMPTY ON PURPOSE: the proxy and the relay carry IPv4 only, so a client told
		// an IPv6 address would connect where this cannot follow. An empty NOERROR makes it fall back
		// to the A record, which is what it should have done anyway.
		if qtype == 1 || qtype == 28 {
			if reply := fakeAnswer(query, name, qtype); reply != nil {
				_, _ = s.conn.WriteToUDP(reply, from)
				return
			}
		}
		// ANY OTHER TYPE IS FORWARDED, because it is not a connection destination: MX, TXT and SRV are
		// read by mail clients and service discovery, and inventing an address for them would be a lie
		// no rule needs.
	}

	reply := s.forward(query)
	if reply == nil {
		return
	}
	_, _ = s.conn.WriteToUDP(reply, from)

	if !ok || (qtype != 1 && qtype != 28) {
		return
	}
	for _, rr := range parseAnswers(reply) {
		known.remember(rr.ip, name, time.Duration(rr.ttl)*time.Second)
	}
}

// forward asks each upstream in turn and returns the first answer.
//
// AN UPSTREAM MAY CARRY A PORT - "127.0.0.1:5353" - AND A BARE ADDRESS MEANS 53. The port exists for a
// caller that runs its own fake resolver on whatever port is free, which is the only way the
// forwarding path can be tested without a real upstream.
func (s *Server) forward(query []byte) []byte {
	for _, up := range s.upstreams {
		host, port, err := net.SplitHostPort(up)
		if err != nil {
			host, port = up, "53"
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		if err != nil {
			continue
		}
		c, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(query); err != nil {
			c.Close()
			continue
		}
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			continue
		}
		return append([]byte(nil), buf[:n]...)
	}
	return nil
}

// ForwardTo sends an A query for a name and returns the reply, bypassing this server entirely.
//
// IT IS FOR A CALLER THAT MUST SEE THROUGH ITS OWN FAKE POOL: in fake-ip mode asking this package for
// a name returns an invented address, so a `direct` rule that then dialled it would connect back to
// the caller. This asks the upstreams the way a real answer would have been produced.
func ForwardTo(upstreams []string, name string) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], uint16(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(q[4:6], 1) // QDCOUNT
	for _, label := range splitName(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // end of name, QTYPE A, QCLASS IN

	s := &Server{upstreams: upstreams}
	return s.forward(q)
}

// --- DNS wire format ---
//
// ONLY THE PARTS THIS NEEDS: the question's name and type, and the A/AAAA records in the answer. A full
// parser is a library; this is sixty lines because a resolver that records addresses does not need
// EDNS, DNSSEC or compression on the way back out.

// parseQuestion returns the queried name (lowercased, no trailing dot) and QTYPE.
func parseQuestion(msg []byte) (string, uint16, bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount == 0 {
		return "", 0, false
	}
	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		// COMPRESSION POINTERS IN A QUESTION ARE LEGAL BUT RARE; a name that points elsewhere would
		// need the full decoder, so it is treated as unparseable rather than mis-parsed.
		if l&0xc0 != 0 {
			return "", 0, false
		}
		if off+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	if off+4 > len(msg) {
		return "", 0, false
	}
	qtype := binary.BigEndian.Uint16(msg[off : off+2])
	return strings.ToLower(strings.Join(labels, ".")), qtype, true
}

type answerRR struct {
	ip  string
	ttl uint32
}

// parseAnswers walks the answer section and returns its A and AAAA records.
func parseAnswers(msg []byte) []answerRR {
	if len(msg) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	if an == 0 {
		return nil
	}
	off := 12
	// SKIP THE QUESTIONS, WITH COMPRESSION SUPPORT ON THE WAY, because an answer's name is almost
	// always a pointer into one of them.
	for i := 0; i < qd; i++ {
		off = skipName(msg, off)
		if off < 0 || off+4 > len(msg) {
			return nil
		}
		off += 4
	}
	var out []answerRR
	for i := 0; i < an; i++ {
		off = skipName(msg, off)
		if off < 0 || off+10 > len(msg) {
			return out
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return out
		}
		switch {
		case rtype == 1 && rdlen == 4:
			out = append(out, answerRR{ip: net.IP(msg[off : off+4]).String(), ttl: ttl})
		case rtype == 28 && rdlen == 16:
			out = append(out, answerRR{ip: net.IP(msg[off : off+16]).String(), ttl: ttl})
		}
		off += rdlen
	}
	return out
}

// skipName advances past a possibly-compressed name and returns the offset after it.
func skipName(msg []byte, off int) int {
	for {
		if off >= len(msg) {
			return -1
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1
		}
		if l&0xc0 == 0xc0 {
			// A POINTER IS TWO BYTES AND ENDS THE NAME, whatever it points at.
			if off+2 > len(msg) {
				return -1
			}
			return off + 2
		}
		off += 1 + l
	}
}

// splitName breaks a dotted name into its labels, tolerating a trailing dot.
func splitName(name string) []string {
	name = trimDot(name)
	if name == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
