// Package egress decides WHERE a connection goes: refused, direct, or through one of several proxies.
//
// IT IS A POLICY ENGINE AND NOTHING ELSE. It does not know what a guest is, what an address means, or
// how traffic reaches it - it answers one question, "what should happen to a connection to this
// address on this port", and a caller acts on the answer. The two callers in practice are a TCP
// listener and a UDP relay, and because they ask the same table, a rule means the same thing to both.
//
// TWO QUESTIONS, ONE TABLE. A person configuring a network has two independent things to say about a
// destination:
//
//	MAY it be reached at all?        block
//	BY WHICH PATH?                   direct / proxy / proxy:NAME
//
// WHY THIS IS NOT A FIREWALL AND MUST NOT BE MARKETED AS ONE. It matches on what a connection is
// addressed to, and a connection is addressed to an address. A rule for `github.com` works because
// the caller's resolver ALSO saw that name and recorded the answer - so a program that dials
// `140.82.121.4` without asking that resolver is matched only if the address happens to be in the
// table, and one that uses its own resolver is matched not at all. That boundary is stated here
// because a UI that implies otherwise is promising something this cannot keep.
package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind is the three things that can happen to a connection.
type Kind int

const (
	// Proxy sends the connection through an upstream.
	Proxy Kind = iota
	// Direct leaves this host with no proxy in the path.
	Direct
	// Block closes the connection. There is no refusal in UDP, so a blocked datagram is dropped and
	// the sender times out - which is what a filtered port looks like everywhere.
	Block
)

// Verdict is what happens to one connection, and - when it is proxied - through which upstream.
//
// IT USED TO BE AN ENUM AND THAT WAS ONE FIELD TOO FEW. "proxy" answered "yes" and left "through
// what" to a single environment variable, so a caller could not send one destination through a fast
// node and another through a different one. The upstream name is that missing field.
type Verdict struct {
	Kind Kind
	// Upstream names an entry in the upstream table. Empty means the default upstream.
	Upstream string
}

func (v Verdict) String() string {
	switch v.Kind {
	case Direct:
		return "direct"
	case Block:
		return "block"
	}
	if v.Upstream != "" {
		return "proxy:" + v.Upstream
	}
	return "proxy"
}

// Equal is used by tests and by a UI's "did anything change" check.
func (v Verdict) Equal(o Verdict) bool { return v.Kind == o.Kind && v.Upstream == o.Upstream }

// ---------------------------------------------------------------- upstreams

// Upstream is one proxy traffic may be sent through.
//
// TWO ADDRESSES PER ENTRY, AND THEY ARE NOT INTERCHANGEABLE. TCP goes through an HTTP CONNECT proxy;
// UDP goes through a SOCKS5 relay, because CONNECT cannot carry a datagram. A named upstream that
// omits UDP still works for TCP and leaves UDP on the default - a choice a person can make rather than
// an error.
type Upstream struct {
	Name string
	// HTTP is the CONNECT proxy, host:port.
	HTTP string
	// SOCKS5 is the UDP relay, host:port. Empty means this upstream carries no UDP.
	SOCKS5 string
}

var (
	upstreamsMu sync.RWMutex
	upstreams   []Upstream
)

// SetUpstreams installs the upstream table.
//
// AN EMPTY TABLE IS LEGAL and means "everything is direct", which is what a machine with no proxy
// needs. It is the caller's job to decide that from its own configuration.
func SetUpstreams(list []Upstream) error {
	seen := map[string]bool{}
	for _, u := range list {
		if u.Name == "" {
			return fmt.Errorf("an upstream needs a name")
		}
		if seen[u.Name] {
			return fmt.Errorf("two upstreams are named %q", u.Name)
		}
		seen[u.Name] = true
		if u.HTTP == "" && u.SOCKS5 == "" {
			return fmt.Errorf("upstream %q has no address", u.Name)
		}
		for _, a := range []string{u.HTTP, u.SOCKS5} {
			if a == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(a); err != nil {
				return fmt.Errorf("upstream %q: %q is not host:port", u.Name, a)
			}
		}
	}
	upstreamsMu.Lock()
	upstreams = list
	upstreamsMu.Unlock()
	return nil
}

// Upstreams returns the current table.
func Upstreams() []Upstream {
	upstreamsMu.RLock()
	defer upstreamsMu.RUnlock()
	return append([]Upstream(nil), upstreams...)
}

// HTTPFor returns the CONNECT proxy an upstream name refers to.
func HTTPFor(name string) (string, bool) {
	upstreamsMu.RLock()
	defer upstreamsMu.RUnlock()
	for _, u := range upstreams {
		if u.Name == name && u.HTTP != "" {
			return u.HTTP, true
		}
	}
	return "", false
}

// SOCKSFor returns the SOCKS5 relay an upstream name refers to.
//
// AN UNNAMED VERDICT THAT NAMES AN UPSTREAM WITH NO SOCKS5 ADDRESS FALLS BACK TO THE DEFAULT, so UDP
// keeps working for a rule written for TCP only.
func SOCKSFor(name string) (string, bool) {
	upstreamsMu.RLock()
	defer upstreamsMu.RUnlock()
	for _, u := range upstreams {
		if u.Name == name && u.SOCKS5 != "" {
			return u.SOCKS5, true
		}
	}
	for _, u := range upstreams {
		if u.Name == "default" && u.SOCKS5 != "" {
			return u.SOCKS5, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------- policy

// Policy is the whole configuration: a default for unmatched traffic, plus rules.
type Policy struct {
	// Default is what an unmatched destination gets.
	Default Verdict
	// Rules are evaluated in order, first match wins.
	Rules []Rule
}

// Rule is one line of the table as a person wrote it.
//
// TWO KINDS, AND THE DIFFERENCE IS WHAT THEY CAN SEE. `address` rules match the connection's
// destination address and need no DNS. `name` rules match the names that address was resolved for,
// which the caller's resolver records - so a `suffix:` rule covers every subdomain that resolved
// through it, and nothing that did not.
type Rule struct {
	// ID identifies this rule across requests, and it is DERIVED rather than assigned.
	//
	// AN ID THAT COMES FROM THE POSITION IN THE LIST WOULD MOVE WHEN A RULE ABOVE IT IS DELETED, so
	// `DELETE /rules/{id}` would sometimes remove the wrong line - the one failure mode a REST API must
	// not have. A hash of the rule's own content is stable under reordering and under concurrent
	// edits, and two identical rules cannot both exist.
	ID string `json:"id,omitempty"`
	// Match is the thing to match: a name for `name` rules, an address or CIDR for `address` ones.
	Match string `json:"match"`
	// Verdict is what to do when this rule matches.
	Verdict Verdict `json:"-"`
	// Action is the wire form: "proxy", "proxy:NAME", "direct" or "block".
	Action string `json:"action"`
	// Ports limits the rule to specific destination ports. Empty means every port.
	Ports []int `json:"ports,omitempty"`
}

// RuleID derives the identifier from what the rule says.
//
// THE ACTION WORD IS PART OF IT, not just the match: `github.com direct` and `github.com block` are
// different rules, and an ID that ignored that would make editing one a delete of the other.
func RuleID(r Rule) string {
	ports := make([]string, 0, len(r.Ports))
	for _, p := range r.Ports {
		ports = append(ports, strconv.Itoa(p))
	}
	sort.Strings(ports)
	seed := r.Match + "\x00" + r.Verdict.String() + "\x00" + strings.Join(ports, ",")
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:6])
}

// ParseAction turns the wire form into a Verdict.
func ParseAction(s string) (Verdict, error) {
	switch {
	case s == "proxy":
		return Verdict{Kind: Proxy}, nil
	case s == "direct":
		return Verdict{Kind: Direct}, nil
	case s == "block":
		return Verdict{Kind: Block}, nil
	case strings.HasPrefix(s, "proxy:"):
		name := strings.TrimPrefix(s, "proxy:")
		if name == "" {
			return Verdict{}, fmt.Errorf("`proxy:` names no upstream")
		}
		return Verdict{Kind: Proxy, Upstream: name}, nil
	}
	return Verdict{}, fmt.Errorf("action %q is not proxy, proxy:NAME, direct or block", s)
}

// ---------------------------------------------------------------- the resolver hook

// NamesFor is how the engine asks "what names was this address resolved for".
//
// IT IS A FUNCTION THE CALLER SETS, not a table this package owns, because the table belongs to
// whatever answers DNS on the caller's behalf. A caller with no resolver leaves it nil, and then only
// address rules can match - which is the honest boundary, not a failure.
var NamesFor = func(net.IP) []string { return nil }

// ---------------------------------------------------------------- the resolved table

type resolvedRule struct {
	Kind    string // "name", "address", or "name+address"
	Name    string
	Nets    []*net.IPNet
	Verdict Verdict
	Ports   []int
	Match   string
}

type resolvedPolicy struct {
	policy Policy
	rules  []resolvedRule
	errs   []string
	at     time.Time
}

var (
	egressMu  sync.RWMutex
	egress    = &resolvedPolicy{policy: Policy{Default: Verdict{Kind: Proxy}}}
	egressGen uint64
)

// SetEgress installs a policy and resolves it.
//
// IT RESOLVES SYNCHRONOUSLY, because a caller applies a policy from an HTTP handler whose response is
// the answer to "did this work" - and returning before the names resolved would report success for a
// rule that matches nothing.
func SetEgress(p Policy) error {
	if p.Default.Kind != Proxy && p.Default.Kind != Direct && p.Default.Kind != Block {
		return fmt.Errorf("default must be proxy, direct or block")
	}
	if p.Default.Kind == Proxy && p.Default.Upstream != "" {
		if _, ok := HTTPFor(p.Default.Upstream); !ok {
			return fmt.Errorf("the default names upstream %q, which has no http address", p.Default.Upstream)
		}
	}
	rp := resolvePolicy(p)
	egressMu.Lock()
	egress = rp
	egressGen++
	egressMu.Unlock()
	return nil
}

// Egress returns the policy in force, with the resolution outcome for each name.
func Egress() (Policy, []string, time.Time) {
	egressMu.RLock()
	defer egressMu.RUnlock()
	return egress.policy, append([]string(nil), egress.errs...), egress.at
}

// Rules returns the rules in force, each with its derived ID.
//
// IT IS A SEPARATE ACCESSOR because the policy a caller edits and the policy the data path reads are
// different shapes: `Egress` returns what `resolvePolicy` kept, this returns what a REST client
// addresses.
func Rules() []Rule {
	policy, _, _ := Egress()
	out := make([]Rule, len(policy.Rules))
	for i, r := range policy.Rules {
		r.ID = RuleID(r)
		out[i] = r
	}
	return out
}

// AddRule appends one rule and resolves the table again.
//
// A DUPLICATE IS REFUSED RATHER THAN ADDED, because two rules with the same content have the same ID -
// `DELETE /rules/{id}` would then have two candidates and the answer would depend on order.
func AddRule(r Rule) (Rule, error) {
	policy, _, _ := Egress()
	r.ID = RuleID(r)
	for _, existing := range policy.Rules {
		if RuleID(existing) == r.ID {
			return r, fmt.Errorf("a rule with this match, action and ports already exists (id %s)", r.ID)
		}
	}
	policy.Rules = append(policy.Rules, r)
	if err := SetEgress(policy); err != nil {
		return r, err
	}
	return r, nil
}

// ReplaceRule swaps the rule with this ID for a new one, and returns what is now stored.
//
// THE ID COMES FROM THE OLD RULE, SO CHANGING THE MATCH CHANGES THE IDENTIFIER. That is the cost of
// deriving it from content: a caller that patches a rule must read the new ID from the response rather
// than assume the old one still addresses it.
func ReplaceRule(id string, r Rule) (Rule, error) {
	policy, _, _ := Egress()
	for i, existing := range policy.Rules {
		if RuleID(existing) != id {
			continue
		}
		r.ID = RuleID(r)
		for j, other := range policy.Rules {
			if j != i && RuleID(other) == r.ID {
				return r, fmt.Errorf("editing this rule would duplicate id %s", r.ID)
			}
		}
		policy.Rules[i] = r
		if err := SetEgress(policy); err != nil {
			return r, err
		}
		return r, nil
	}
	return r, fmt.Errorf("no rule with id %q", id)
}

// DeleteRule removes the rule with this ID and reports whether it existed.
func DeleteRule(id string) (bool, error) {
	policy, _, _ := Egress()
	for i, existing := range policy.Rules {
		if RuleID(existing) != id {
			continue
		}
		policy.Rules = append(policy.Rules[:i], policy.Rules[i+1:]...)
		if err := SetEgress(policy); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// SetDefault changes what an unmatched destination gets, leaving the rules alone.
func SetDefault(v Verdict) error {
	policy, _, _ := Egress()
	policy.Default = v
	return SetEgress(policy)
}

// Default returns the current default verdict.
func Default() Verdict {
	policy, _, _ := Egress()
	return policy.Default
}

// ---------------------------------------------------------------- the lookup

// For answers what to do with a connection to ip:port.
//
// THE LOOKUP IS UNDER A READ LOCK AND IS DELIBERATELY CHEAP: it runs once per connection, and a
// connection can arrive thousands of times a second. Keeping the resolved table immutable between
// applies is what makes that safe.
func For(ip net.IP, port int) Verdict {
	// THE NAMES COME FROM THE CALLER'S TABLE, read outside the policy lock so a slow resolution
	// cannot delay a connection.
	var names []string
	if ip != nil {
		names = NamesFor(ip)
	}

	egressMu.RLock()
	defer egressMu.RUnlock()
	for i := range egress.rules {
		r := &egress.rules[i]
		if len(r.Ports) > 0 && !containsPort(r.Ports, port) {
			continue
		}
		if r.Kind == "name" {
			for _, n := range names {
				if NameMatches(r.Name, n) {
					return r.Verdict
				}
			}
			continue
		}
		// "address" AND "name+address" BOTH CARRY NETS, and a name+address rule also matches by name
		// so a connection whose address moved still matches what was asked for.
		for _, n := range r.Nets {
			if n.Contains(ip) {
				return r.Verdict
			}
		}
		if r.Kind == "name+address" {
			for _, n := range names {
				if NameMatches(r.Name, n) {
					return r.Verdict
				}
			}
		}
	}
	return egress.policy.Default
}

// NameMatches applies one rule pattern to one observed name.
//
// THE THREE SHAPES AND NOTHING ELSE - no globs, no regex. A rule language that can express anything is
// a rule language somebody will get subtly wrong, and the three cases below are what "block this
// domain" means in practice:
//
//	.example.com    the domain and every subdomain
//	example.com     exactly this host
//	ads             any name containing it (stored without the asterisks a person typed)
func NameMatches(pattern, name string) bool {
	if pattern == "" || name == "" {
		return false
	}
	switch {
	case strings.HasPrefix(pattern, "."):
		base := pattern[1:]
		return name == base || strings.HasSuffix(name, pattern)
	case strings.Contains(pattern, "."):
		return name == pattern
	default:
		return strings.Contains(name, pattern)
	}
}

func containsPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- resolution

// RefreshInterval is how often the names are resolved again.
//
// A NAME WHOSE ADDRESSES ALL CHANGE AND ARE NOT RE-RESOLVED STOPS MATCHING, and that is the failure
// mode this interval exists to make small.
const RefreshInterval = 5 * time.Minute

// StartRefresh re-resolves the names on a timer until done is closed, so a rule that names a host
// with a short TTL keeps matching after the address moves.
func StartRefresh(done <-chan struct{}) {
	go func() {
		t := time.NewTicker(RefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				policy, _, _ := Egress()
				rp := resolvePolicy(policy)
				egressMu.Lock()
				egress = rp
				egressGen++
				egressMu.Unlock()
			}
		}
	}()
}

// resolvePolicy classifies each rule and, for the ones that name a host, resolves it.
func resolvePolicy(p Policy) *resolvedPolicy {
	rp := &resolvedPolicy{policy: p, at: time.Now()}
	for _, rule := range p.Rules {
		match := strings.TrimSpace(rule.Match)
		if match == "" {
			continue
		}
		rr := resolvedRule{Verdict: rule.Verdict, Ports: rule.Ports, Match: match, Kind: "address"}

		// THE PATTERN DECIDES THE KIND, AND THE PATTERN IS WHAT A PERSON TYPES:
		//
		//	.example.com    every subdomain, and the domain itself
		//	*ads*           any name containing ads
		//	example.com     exactly that name (and, because it is also a host, its addresses)
		//	10.0.0.0/8      an address range
		switch {
		case strings.HasPrefix(match, "."):
			rr.Kind = "name"
			rr.Name = strings.ToLower(match)
			rp.rules = append(rp.rules, rr)
			continue
		case strings.HasPrefix(match, "*") || strings.HasSuffix(match, "*"):
			rr.Kind = "name"
			rr.Name = strings.ToLower(strings.Trim(match, "*"))
			if rr.Name == "" {
				rp.errs = append(rp.errs, match+": empty keyword")
				continue
			}
			rp.rules = append(rp.rules, rr)
			continue
		}

		// A CIDR OR A BARE ADDRESS IS USED AS GIVEN. `net.ParseCIDR` accepts both `10.0.0.0/8` and,
		// with a full mask, a single address.
		if strings.Contains(match, "/") {
			if _, n, err := net.ParseCIDR(match); err == nil {
				rr.Nets = []*net.IPNet{n}
			} else {
				rp.errs = append(rp.errs, fmt.Sprintf("%s: not a CIDR", match))
			}
		} else if ip := net.ParseIP(match); ip != nil {
			rr.Nets = []*net.IPNet{{IP: ip, Mask: net.CIDRMask(32, 32)}}
			if ip.To4() == nil {
				rr.Nets[0].Mask = net.CIDRMask(128, 128)
			}
		} else {
			addrs, err := net.LookupIP(match)
			if err != nil || len(addrs) == 0 {
				rp.errs = append(rp.errs, match+": did not resolve")
				rp.rules = append(rp.rules, rr) // kept, so a UI can show it
				continue
			}
			for _, a := range addrs {
				bits := 32
				if a.To4() == nil {
					// IPv6 IS SKIPPED, AND THE REASON IS THE CALLER'S OWN STACK: the proxy and the
					// relay both work in IPv4, so a v6 address here would be a rule that can never
					// match - worse than an absent one because it looks like coverage.
					continue
				}
				rr.Nets = append(rr.Nets, &net.IPNet{IP: a, Mask: net.CIDRMask(bits, bits)})
			}
			// AND IT IS ALSO AN EXACT NAME RULE, because a connection made after the resolver has seen
			// the answer has a name attached and should match by that name rather than by an address
			// that may already be stale.
			rr.Kind = "name+address"
			rr.Name = strings.ToLower(match)
		}
		rp.rules = append(rp.rules, rr)
	}
	return rp
}
