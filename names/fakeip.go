package names

// FAKE-IP: ANSWER A NAME WITH AN ADDRESS THIS PACKAGE INVENTED, SO THE CONNECTION THAT FOLLOWS STILL
// CARRIES THE NAME.
//
// THE PROBLEM REAL-IP MODE CANNOT SOLVE. A rule is written about a name, and a connection carries an
// address. The table records `address -> name`, so the rule matches - but only for the addresses the
// client actually resolved, and only until the TTL runs out:
//
//	one name, many addresses   a CDN answers with four; the client connects to a fifth that another
//	                           resolver gave it, and that address was never recorded
//	stale addresses            the name moved, the client cached the old answer
//	the client's own resolver   a query that went out before the redirect, or through a path unseen
//
// Each is a rule that silently matches nothing.
//
// WHAT FAKE-IP DOES INSTEAD. It does not record the real answer - it REPLACES it. `www.youtube.com` is
// answered with an address out of a range that belongs to nothing (198.18.0.0/15, RFC 2544's benchmark
// range), and the mapping is remembered. When the client connects to it, the destination still carries
// the name, because this package put the name there. There is no lookup that can miss: the mapping is
// the only reason that address exists.
//
// THE COST, STATED PLAINLY: a connection this package cannot name cannot be made at all. A program that
// dials a literal address never enters the pool and works normally, but one that resolves a name
// through a resolver this package does not see, and then connects to the real address, bypasses the
// pool entirely - it is not blocked, it is simply not subject to a name rule.

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// THE POOL IS RFC 2544's BENCHMARK RANGE, 198.18.0.0/15.
//
// IT IS PRIVATE IN THE ONLY SENSE THAT MATTERS: reserved for network equipment testing, so no real
// host is at one of these addresses, and a connection to one can only be to this package. A public
// range would risk a real destination behind a broken lookup; a 10/8 or 192.168/16 address could
// collide with the caller's own network. 131072 addresses is far more than one client's working set.
const (
	fakeBase  = uint32(198)<<24 | uint32(18)<<16
	fakeCount = 1 << 17 // a /15 is 131072 addresses
	// fakeTTL IS SHORT ON PURPOSE: a client re-asks, which keeps the pool's notion of "in use" fresh.
	fakeTTL = 10
	// fakeKeep is how long an allocation is remembered past its last use.
	fakeKeep = 5 * time.Minute
)

// Pool maps between names and the addresses this package invented for them.
//
// BOTH DIRECTIONS ARE KEPT because both are asked for, at different times: the resolver asks "what
// address does this name get", and the proxy asks "what name is this address". Deriving one from the
// other each time would be a search on every packet.
type Pool struct {
	mu     sync.Mutex
	byName map[string]*alloc
	byIP   map[uint32]string
}

type alloc struct {
	idx  uint32
	name string
	exp  time.Time
}

// NewPool returns an empty pool.
func NewPool() *Pool {
	return &Pool{byName: map[string]*alloc{}, byIP: map[uint32]string{}}
}

// pool is the process-wide instance the Server uses, so a query and a lookup see one table.
var pool = NewPool()

// Allocate returns the address this name is answered with, allocating one on first use.
//
// THE ALLOCATION IS A HASH AND THEN A LINEAR PROBE, and the reason is that a name should keep its
// address across re-queries. A client that asks twice and gets two addresses is a client making two
// connections that look like different flows; stable allocation makes them the same flow, which is
// what a keep-alive connection expects. The probe is what makes it correct when two names hash to one
// slot - a pure hash would give them the same address and the second would take the first name's rule.
func (p *Pool) Allocate(name string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	if a, ok := p.byName[name]; ok {
		a.exp = time.Now().Add(fakeKeep)
		return ipOfIndex(a.idx)
	}

	start := fnvIndex(name)
	for probe := uint32(0); probe < fakeCount; probe++ {
		idx := (start + probe) % fakeCount
		holder, taken := p.byIP[idx]
		if taken && !p.expired(holder) {
			continue
		}
		// FREE OR EXPIRED. An expired holder's forward entry must go too, or the name would be
		// answered with the address a second name now owns.
		if taken {
			if old, ok := p.byName[holder]; ok && old.idx == idx {
				delete(p.byName, holder)
			}
		}
		p.byIP[idx] = name
		p.byName[name] = &alloc{idx: idx, name: name, exp: time.Now().Add(fakeKeep)}
		// AND THE NAME GOES IN THE REAL TABLE TOO, so a policy rule matches it with no change to the
		// engine: a fake address is looked up exactly like a resolved one.
		known.remember(ipOfIndex(idx).String(), name, fakeKeep)
		return ipOfIndex(idx)
	}
	// THE POOL IS FULL, which for one client means 131072 live names - not a state that happens. Nil
	// rather than an arbitrary address, because a wrong answer would route to another name's host.
	return nil
}

// expired reports whether an allocation's name has outlived its last use. The caller holds the lock.
func (p *Pool) expired(name string) bool {
	a, ok := p.byName[name]
	return !ok || time.Now().After(a.exp)
}

// NameFor returns the name an address was invented for, and whether it is in the pool at all.
//
// THE POOL CHECK COMES FIRST: a real address is not in `byIP`, so this is also how a caller tells a
// fake destination from a real one without a second function.
func (p *Pool) NameFor(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	idx, ok := indexOfIP(v4)
	if !ok {
		return "", false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	name, ok := p.byIP[idx]
	if !ok || p.expired(name) {
		return "", false
	}
	return name, true
}

// sweep drops allocations nobody has used recently, so a long-lived process does not fill the pool
// with names from machines that are gone.
func (p *Pool) sweep() {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, a := range p.byName {
		if now.After(a.exp) {
			delete(p.byName, name)
			if holder, ok := p.byIP[a.idx]; ok && holder == name {
				delete(p.byIP, a.idx)
			}
		}
	}
}

// NameForFakeIP answers "is this address one of ours, and for what name", on the process-wide pool.
//
// IT IS THE ONE FUNCTION A PROXY AND A RELAY NEED, and it folds the pool check into the lookup so a
// caller cannot accidentally treat a real address as a fake one - the bool is false for anything
// outside the range, whatever is in the table.
func NameForFakeIP(ip net.IP) (string, bool) { return pool.NameFor(ip) }

// Len reports how many names the pool holds, for a test or a status page.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byName)
}

// --- the range arithmetic ---

func ipOfIndex(idx uint32) net.IP {
	v := fakeBase + idx
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func indexOfIP(ip net.IP) (uint32, bool) {
	v := binary.BigEndian.Uint32(ip.To4())
	if v < fakeBase || v >= fakeBase+fakeCount {
		return 0, false
	}
	return v - fakeBase, true
}

// fnvIndex spreads names across the pool, so a small working set does not cluster at the front.
func fnvIndex(name string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= 16777619
	}
	return h % fakeCount
}

// InPool reports whether an address is inside the invented range, whether or not it is allocated.
func InPool(ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	_, ok := indexOfIP(ip)
	return ok
}

// fakeAnswer builds a DNS response naming this package's address for the query, or nil when the query
// is not one this can answer.
func fakeAnswer(query []byte, name string, qtype uint16) []byte {
	// THE QUESTION MUST END WHERE THE ANSWER BEGINS, and skipName is how that offset is found - a
	// compressed question would otherwise make every offset after it wrong.
	if len(query) < 12 {
		return nil
	}
	end := skipName(query, 12)
	if end < 0 || end+4 > len(query) {
		return nil
	}
	qEnd := end + 4 // QTYPE + QCLASS

	// THE RESPONSE HEADER, WITH THE QUERY'S OWN ID AND QUESTION COPIED VERBATIM. `0x81 0x80` is QR=1
	// (a response), RD=1 (recursion desired, echoed), RA=1 (recursion available).
	msg := make([]byte, 12)
	copy(msg[0:2], query[0:2]) // ID
	msg[2], msg[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT
	if qtype == 1 {
		binary.BigEndian.PutUint16(msg[6:8], 1) // ANCOUNT
	}
	msg = append(msg, query[12:qEnd]...)

	if qtype != 1 {
		// AAAA AND EVERYTHING ELSE: NOERROR WITH NO RECORDS, which is an answer a client accepts.
		return msg
	}

	ip := pool.Allocate(name)
	if ip == nil {
		// THE POOL IS FULL. SERVFAIL rather than a wrong address: a client that gets SERVFAIL retries
		// or falls back, where one given another name's address would connect to the wrong host.
		msg[3] = 0x82 // RCODE 2 = SERVFAIL
		binary.BigEndian.PutUint16(msg[6:8], 0)
		return msg
	}

	// THE ANSWER'S NAME IS A POINTER TO THE QUESTION'S (0xc00c), which is what every resolver emits and
	// what keeps the message small.
	rr := make([]byte, 16)
	copy(rr[0:2], []byte{0xc0, 0x0c})
	binary.BigEndian.PutUint16(rr[2:4], 1)                // TYPE A
	binary.BigEndian.PutUint16(rr[4:6], 1)                // CLASS IN
	binary.BigEndian.PutUint32(rr[6:10], uint32(fakeTTL)) // TTL
	binary.BigEndian.PutUint16(rr[10:12], 4)              // RDLENGTH
	copy(rr[12:16], ip.To4())
	return append(msg, rr...)
}

// ResolveReal answers a name the way an upstream would, ignoring the fake pool.
//
// IT IS FOR A CALLER THAT MUST SEE THROUGH ITS OWN POOL: a `direct` rule cannot dial an invented
// address, so it resolves the name against the upstreams directly. The pool is the point of fake-ip;
// the caller is the one thing that must look past it.
func ResolveReal(upstreams []string, name string) (net.IP, error) {
	reply := ForwardTo(upstreams, name)
	if reply == nil {
		return nil, fmt.Errorf("could not resolve %s against any upstream", name)
	}
	for _, rr := range parseAnswers(reply) {
		if ip := net.ParseIP(rr.ip); ip != nil && ip.To4() != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("%s resolved to no IPv4 address", name)
}
