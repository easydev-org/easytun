package egress

// THE RULE ENGINE'S OWN BEHAVIOUR, PORTED FROM THE PACKAGE IT CAME FROM AND EXTENDED where the
// extraction made a new case visible.
//
// The three properties that matter are: a rule matches what a person meant, first-match-wins is real,
// and the ID is derived from content so a REST client cannot address the wrong line.

import (
	"net"
	"testing"
)

// reset clears the process-wide tables, since they are the engine's whole state.
func reset(t *testing.T) {
	t.Helper()
	if err := SetUpstreams([]Upstream{
		{Name: "default", HTTP: "d:1", SOCKS5: "d:2"},
		{Name: "fast", HTTP: "fast:1", SOCKS5: "fast:2"},
	}); err != nil {
		t.Fatal(err)
	}
	oldNames := NamesFor
	NamesFor = func(net.IP) []string { return nil }
	t.Cleanup(func() {
		NamesFor = oldNames
		_ = SetUpstreams(nil)
		_ = SetEgress(Policy{Default: Verdict{Kind: Proxy}})
	})
}

// --- the three shapes of a name pattern ---

func TestNameMatchesTheThreeShapes(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
		why           string
	}{
		{".youtube.com", "youtube.com", true, "a suffix rule matches the domain itself too"},
		{".youtube.com", "www.youtube.com", true, "and every subdomain"},
		{".youtube.com", "notyoutube.com", false, "an unrelated name that merely ends similarly"},
		{"example.com", "example.com", true, "a bare name is exact"},
		{"example.com", "www.example.com", false, "and does NOT cover subdomains - that is what the dot means"},
		{"ads", "ads.example.com", true, "a keyword matches anywhere in the name"},
		{"ads", "example.com", false, "and only where it appears"},
		{"", "example.com", false, "an empty pattern matches nothing, rather than everything"},
	}
	for _, c := range cases {
		if got := NameMatches(c.pattern, c.name); got != c.want {
			t.Errorf("NameMatches(%q, %q) = %v, want %v (%s)", c.pattern, c.name, got, c.want, c.why)
		}
	}
}

// --- address rules ---

func TestAddressRulesMatchWithoutDNS(t *testing.T) {
	reset(t)
	if err := SetEgress(Policy{
		Default: Verdict{Kind: Proxy},
		Rules: []Rule{
			{Match: "10.0.0.0/8", Verdict: Verdict{Kind: Direct}, Action: "direct"},
			{Match: "203.0.113.7", Verdict: Verdict{Kind: Block}, Action: "block"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if v := For(net.IPv4(10, 1, 2, 3), 443); v.Kind != Direct {
		t.Errorf("10.1.2.3 = %v, want direct", v)
	}
	if v := For(net.IPv4(203, 0, 113, 7), 443); v.Kind != Block {
		t.Errorf("203.0.113.7 = %v, want block", v)
	}
	if v := For(net.IPv4(198, 51, 100, 1), 443); v.Kind != Proxy {
		t.Errorf("an unmatched address = %v, want the default proxy", v)
	}
}

// --- first match wins ---

func TestTheFirstMatchingRuleWins(t *testing.T) {
	reset(t)
	if err := SetEgress(Policy{
		Default: Verdict{Kind: Proxy},
		Rules: []Rule{
			{Match: "203.0.113.0/24", Verdict: Verdict{Kind: Direct}, Action: "direct"},
			{Match: "203.0.113.7", Verdict: Verdict{Kind: Block}, Action: "block"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	// The narrower rule is second, so it never applies - which is what "first match wins" means and
	// what a person reordering rules depends on.
	if v := For(net.IPv4(203, 0, 113, 7), 443); v.Kind != Direct {
		t.Fatalf("203.0.113.7 = %v, want direct from the FIRST rule", v)
	}
}

// --- ports ---

func TestAPortRestrictedRuleOnlyMatchesItsPorts(t *testing.T) {
	reset(t)
	if err := SetEgress(Policy{
		Default: Verdict{Kind: Proxy},
		Rules: []Rule{
			{Match: "203.0.113.50", Verdict: Verdict{Kind: Block}, Action: "block", Ports: []int{25}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if v := For(net.IPv4(203, 0, 113, 50), 25); v.Kind != Block {
		t.Errorf("port 25 = %v, want block", v)
	}
	if v := For(net.IPv4(203, 0, 113, 50), 443); v.Kind != Proxy {
		t.Errorf("port 443 = %v, want the default - the rule names only 25", v)
	}
}

// --- name rules, through the caller's table ---

func TestANameRuleMatchesThroughTheCallersTable(t *testing.T) {
	reset(t)
	NamesFor = func(ip net.IP) []string {
		if ip.Equal(net.IPv4(203, 0, 113, 9)) {
			return []string{"www.youtube.com"}
		}
		return nil
	}
	if err := SetEgress(Policy{
		Default: Verdict{Kind: Proxy},
		Rules: []Rule{
			{Match: ".youtube.com", Verdict: Verdict{Kind: Proxy, Upstream: "fast"}, Action: "proxy:fast"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if v := For(net.IPv4(203, 0, 113, 9), 443); v.Upstream != "fast" {
		t.Fatalf("a named address = %v, want proxy:fast", v)
	}
	// AND AN ADDRESS THE TABLE DOES NOT KNOW HAS NO NAME, so a name rule cannot match it.
	if v := For(net.IPv4(203, 0, 113, 10), 443); v.Upstream != "" {
		t.Fatalf("an unnamed address = %v, want the default", v)
	}
}

// --- upstreams ---

func TestAnUnnamedUpstreamFallsBackToTheDefaultForUDP(t *testing.T) {
	reset(t)
	if err := SetUpstreams([]Upstream{
		{Name: "default", HTTP: "d:1", SOCKS5: "d:2"},
		{Name: "httponly", HTTP: "h:1"}, // no SOCKS5: it cannot carry UDP
	}); err != nil {
		t.Fatal(err)
	}
	if addr, ok := HTTPFor("httponly"); !ok || addr != "h:1" {
		t.Errorf("HTTPFor(httponly) = %q, %v", addr, ok)
	}
	// THE FALLBACK: a rule written for TCP only still gets UDP through the default.
	if addr, ok := SOCKSFor("httponly"); !ok || addr != "d:2" {
		t.Errorf("SOCKSFor(httponly) = %q, %v, want the default's socks address", addr, ok)
	}
}

func TestSetUpstreamsRefusesAmbiguity(t *testing.T) {
	for _, c := range []struct {
		name string
		list []Upstream
	}{{
		"two with one name",
		[]Upstream{{Name: "a", HTTP: "a:1"}, {Name: "a", HTTP: "a:2"}},
	}, {
		"no address",
		[]Upstream{{Name: "a"}},
	}, {
		"not host:port",
		[]Upstream{{Name: "a", HTTP: "nonsense"}},
	}} {
		if err := SetUpstreams(c.list); err == nil {
			t.Errorf("%s: SetUpstreams accepted it", c.name)
		}
	}
}

// AN EMPTY TABLE IS LEGAL and means direct, which is what a machine with no proxy needs.
func TestAnEmptyUpstreamTableIsLegal(t *testing.T) {
	if err := SetUpstreams(nil); err != nil {
		t.Fatalf("an empty table: %v", err)
	}
	if _, ok := HTTPFor("default"); ok {
		t.Fatal("an empty table answered for `default`")
	}
}

// --- the CRUD surface, which a REST client addresses ---

func TestARulesIDIsDerivedFromItsContent(t *testing.T) {
	a := Rule{Match: "example.com", Verdict: Verdict{Kind: Direct}, Action: "direct"}
	b := Rule{Match: "example.com", Verdict: Verdict{Kind: Block}, Action: "block"}
	if RuleID(a) == RuleID(b) {
		t.Fatal("two rules that differ only in action share an id, so editing one would delete the other")
	}
	// REORDERING THE PORTS MUST NOT CHANGE IT: a client that sorts its list and a client that does not
	// are describing the same rule.
	c := Rule{Match: "x", Ports: []int{80, 443}, Action: "direct"}
	d := Rule{Match: "x", Ports: []int{443, 80}, Action: "direct"}
	if RuleID(c) != RuleID(d) {
		t.Fatal("port order changed the id")
	}
}

func TestAddReplaceAndDelete(t *testing.T) {
	reset(t)
	if err := SetEgress(Policy{Default: Verdict{Kind: Proxy}}); err != nil {
		t.Fatal(err)
	}

	added, err := AddRule(Rule{Match: "203.0.113.44", Verdict: Verdict{Kind: Direct}, Action: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	if added.ID == "" {
		t.Fatal("a stored rule has no id")
	}
	// A DUPLICATE IS REFUSED, because two rules with one id make DELETE ambiguous.
	if _, err := AddRule(Rule{Match: "203.0.113.44", Verdict: Verdict{Kind: Direct}, Action: "direct"}); err == nil {
		t.Fatal("a duplicate rule was accepted")
	}

	updated, err := ReplaceRule(added.ID, Rule{Match: "203.0.113.44", Verdict: Verdict{Kind: Block}, Action: "block"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID == added.ID {
		t.Error("the id did not change with the content, so a client would address the wrong rule")
	}
	if v := For(net.IPv4(203, 0, 113, 44), 443); v.Kind != Block {
		t.Errorf("after replace, the matcher says %v", v)
	}

	if found, err := DeleteRule(updated.ID); err != nil || !found {
		t.Fatalf("delete: found=%v err=%v", found, err)
	}
	if found, _ := DeleteRule(updated.ID); found {
		t.Error("deleting it twice reported it existed")
	}
}

// A POLICY THAT NAMES AN UPSTREAM WITH NO HTTP ADDRESS IS REFUSED AT APPLY TIME, which is the one
// moment a person can be told - a connection later would just be refused with no explanation.
func TestAPolicyCannotNameAnUpstreamThatCannotCarryTCP(t *testing.T) {
	reset(t)
	err := SetEgress(Policy{
		Default: Verdict{Kind: Proxy, Upstream: "nosuch"},
	})
	if err == nil {
		t.Fatal("a default naming an unknown upstream was accepted")
	}
}

// --- the wiring between a rule and a verdict ---

func TestParseActionRoundTrips(t *testing.T) {
	for _, s := range []string{"proxy", "direct", "block", "proxy:fast"} {
		v, err := ParseAction(s)
		if err != nil {
			t.Errorf("ParseAction(%q): %v", s, err)
			continue
		}
		if v.String() != s {
			t.Errorf("ParseAction(%q) round-tripped to %q", s, v.String())
		}
	}
	for _, bad := range []string{"", "proxxy", "proxy:", "allow"} {
		if _, err := ParseAction(bad); err == nil {
			t.Errorf("ParseAction(%q) was accepted", bad)
		}
	}
}
