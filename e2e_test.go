//go:build linux

package easytun

// THE END-TO-END TEST: A REAL TUN DEVICE, A REAL SOCKS5 SERVER, A REAL DATAGRAM.
//
// THIS IS THE MIGRATION OF THE ASSERTIONS THAT USED TO LIVE IN easyvm's `alpine-microvm.yml`. That
// workflow built a whole virtual machine to get a `/dev/net/tun` and then read the kernel's own view
// of the device - `ip link show`, `ip -4 addr`, `ip rule`, `ip route show table N` - because those are
// the only place the claims can be checked. None of that needed the virtual machine; it needed a tun
// device and the capability to make one. So the device is the fixture now, and the guest is not
// booted at all.
//
// WHAT IT PROVES, ONE LINE PER ASSERTION THE OLD JOB MADE:
//
//	Preflight succeeds                     the container has the device and the capability
//	ip link show <name>                    the device exists and is UP
//	ip -4 addr shows 10.99.<n>.1/24        it is addressed, so the route cannot blackhole
//	ip rule names `ipproto udp`            only this guest's UDP is taken, not its TCP
//	ip route show table <n> has a default   the table the rule points at is populated
//	a datagram goes out and comes back      the framing, the proxy and the reply rewrite all work
//	Close removes the device and the rule   a route outliving its device breaks every later run
//
// HOW TO RUN IT. It needs `--device /dev/net/tun --cap-add NET_ADMIN`, which is the same two flags
// the README asks a caller for. Without them it SKIPS with the reason, so `go test ./...` is still
// green on a runner that has neither - and the CI job that does have them will run it.
//
//	A USER NAMESPACE IS ENOUGH, WITHOUT ROOT: `unshare -Urn --keep-caps go test ./... -run E2E`
//	grants CAP_NET_ADMIN inside an isolated network namespace, and the whole test - including the
//	policy routing it installs and removes - stays inside it. That is how this was developed, and it
//	is what the workflow does too, so the test cannot leak a route onto a host.

import (
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// canMakeATun answers whether this process can create a tun device, and why not when it cannot.
//
// IT CREATES ONE AND DESTROYS IT, because the only honest test of the capability is the ioctl the
// relay itself performs - reading CapEff would report the capability set and not whether the kernel
// allows the operation in this namespace.
func canMakeATun(t *testing.T) (string, bool) {
	t.Helper()
	const probe = "easytun-probe0"
	tun, err := openTun(probe)
	if err != nil {
		return err.Error(), false
	}
	_ = tun.Close()
	_ = deleteTun(probe)
	return "", true
}

// skipWithoutATun is the guard every test in this file opens with.
func skipWithoutATun(t *testing.T) {
	t.Helper()
	if why, ok := canMakeATun(t); !ok {
		t.Skipf("no tun device in this process, so the kernel half cannot be tested: %s\n"+
			"run it with `unshare -Urn --keep-caps go test ./... -run E2E`, or a container with "+
			"`--device /dev/net/tun --cap-add NET_ADMIN`", why)
	}
}

// ip runs `ip` and returns its output, failing the test when it does.
func ip(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v (%s)", strings.Join(args, " "), err, firstLine(string(out)))
	}
	return string(out)
}

// THE WHOLE THING, IN ONE TEST, BECAUSE THE ASSERTIONS ARE ABOUT ONE DEVICE'S LIFETIME and each is
// cheaper to read next to the state it depends on than in a helper's signature.
func TestE2ETheDeviceIsRealAndTheDatagramComesBack(t *testing.T) {
	skipWithoutATun(t)

	// A REAL SOCKS5 SERVER ON LOOPBACK. The `unshare -Urn` namespace has `lo` and nothing else, which
	// is exactly enough: the relay's upstream is 127.0.0.1 and its datagram never leaves the host.
	proxy := startSocksUDPEcho(t)

	const (
		guest = "172.30.0.2"
		name  = "e2etun0"
	)
	if out, err := exec.Command("ip", "link", "show", name).CombinedOutput(); err == nil && out != nil {
		// A leftover from a killed run would make the address and rule assertions pass for the wrong
		// reason, so refuse rather than adopt it.
		t.Fatalf("%s already exists before the test starts:\n%s", name, out)
	}

	r, err := Start(Config{
		GuestIP:  guest,
		Upstream: proxy.addr(),
		Name:     name,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// EVERY CLEANUP IS ASSERTED, INCLUDING ON FAILURE, so a broken Close cannot pass by leaving the
	// device behind and a later run believing it was cleaned up.
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		if out, err := exec.Command("ip", "link", "show", name).CombinedOutput(); err == nil {
			t.Errorf("the tun device outlived Close:\n%s", out)
		}
		if out := ip(t, "rule", "show"); strings.Contains(out, "lookup "+itoa(r.table)) {
			t.Errorf("the policy rule outlived Close:\n%s", out)
		}
	}()

	// --- the device, as the kernel reports it ---
	link := ip(t, "link", "show", name)
	if !strings.Contains(link, "state UP") && !strings.Contains(link, ",UP") {
		t.Errorf("the device is not UP:\n%s", link)
	}

	addr := ip(t, "-4", "addr", "show", name)
	want := addrFor(r.table) + "/24"
	if !strings.Contains(addr, want) {
		t.Errorf("the device does not hold %s:\n%s", want, addr)
	}

	// --- the policy, as the kernel reports it ---
	rules := ip(t, "rule", "show")
	expectedRule := "from " + guest + " ipproto udp lookup " + itoa(r.table)
	if !strings.Contains(rules, expectedRule) {
		t.Errorf("the policy rule is not installed; wanted %q in:\n%s", expectedRule, rules)
	}
	// AND NOTHING BROADER. A rule without `ipproto udp` sends the guest's TCP into the tun as well,
	// which would steal it from the CONNECT proxy that carries it today.
	if strings.Contains(rules, "from "+guest+" lookup "+itoa(r.table)) {
		t.Errorf("a rule sends ALL of the guest's traffic to the udp relay, not just its UDP:\n%s", rules)
	}

	routes := ip(t, "route", "show", "table", itoa(r.table))
	if !strings.Contains(routes, "default dev "+name) {
		t.Errorf("table %d has no default route into the device:\n%s", r.table, routes)
	}

	// --- the datagram, through the proxy and back ---
	//
	// THE GUEST IS A SOCKET, NOT A WRITE INTO THE DEVICE. Writing a packet into a tun injects it
	// OUTBOUND into the kernel - it does not appear on the read side the relay reads. The real path is
	// the other way round: a packet whose source is the guest's address is matched by the policy rule,
	// routed into the tun by the kernel, and read by the relay. So the guest's address is put on lo and
	// a real UDP socket sends from it.
	//
	// A TEST-ONLY DESTINATION: 203.0.113.10 is TEST-NET-3 (RFC 5737), reserved for documentation and
	// guaranteed not to be a real host, so this cannot accidentally reach anything.
	// `lo` IS DOWN IN A FRESH NETWORK NAMESPACE, and an address on a down interface accepts a bind and
	// then drops every packet - which is a ten-second timeout with no clue in it.
	ip(t, "link", "set", "lo", "up")
	ip(t, "addr", "add", guest+"/32", "dev", "lo")
	defer func() { _ = exec.Command("ip", "addr", "del", guest+"/32", "dev", "lo").Run() }()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(guest), Port: 51234})
	if err != nil {
		t.Fatalf("binding the guest's socket to %s: %v", guest, err)
	}
	defer conn.Close()
	if _, err := conn.WriteToUDP([]byte("a datagram"),
		&net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 443}); err != nil {
		t.Fatalf("the guest's datagram: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	read := make([]byte, 65535)
	n, from, err := conn.ReadFromUDP(read)
	if err != nil {
		t.Fatalf("the reply never reached the guest's socket: %v", err)
	}
	// THE REPLY COMES FROM WHERE THE GUEST SENT IT. A datagram from 10.99.<n>.1 would be discarded by
	// the guest's stack, so this source address is the whole illusion - and ReadFromUDP is where a
	// wrong source becomes visible, because the socket is connected to nothing.
	if !from.IP.Equal(net.IPv4(203, 0, 113, 10)) || from.Port != 443 {
		t.Errorf("reply source %v, want 203.0.113.10:443", from)
	}
	if string(read[:n]) != "echo:a datagram" {
		t.Errorf("payload %q, want %q", read[:n], "echo:a datagram")
	}
}

// Preflight MUST PASS HERE. The guard above already proved the ioctl works, so a Preflight that
// disagreed would be a Preflight with a different idea of "usable" than the relay itself.
func TestE2EPreflightAgreesWithTheDevice(t *testing.T) {
	skipWithoutATun(t)
	if err := Preflight(); err != nil {
		t.Fatalf("Preflight refused a device this process just created: %v", err)
	}
}

// TWO RELAYS IN ONE NAMESPACE MUST NOT COLLIDE, and this is the case the old constant table number
// could not survive: `--network container:` puts two services in one namespace, and a shared table
// means each reads the other's datagrams. The hash may collide, so this proves the PROBE works.
func TestE2ETwoRelaysGetDifferentTablesAndAddresses(t *testing.T) {
	skipWithoutATun(t)
	proxy := startSocksUDPEcho(t)

	first, err := Start(Config{GuestIP: "172.31.0.2", Upstream: proxy.addr(), Name: "e2etwoA"})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Errorf("first Close: %v", err)
		}
	}()

	second, err := Start(Config{GuestIP: "172.31.0.3", Upstream: proxy.addr(), Name: "e2etwoB"})
	if err != nil {
		t.Fatalf("second Start: %v", err)
	}
	defer func() {
		if err := second.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	}()

	if first.table == second.table {
		t.Fatalf("both relays installed into table %d; each would read the other's datagrams", first.table)
	}
	if addrFor(first.table) == addrFor(second.table) {
		t.Fatalf("both relays claimed %s/24", addrFor(first.table))
	}

	// AND BOTH RULES ARE REAL AND SEPARATE, which is the thing the collision would break.
	rules := ip(t, "rule", "show")
	for _, r := range []*Relay{first, second} {
		want := "from " + r.guest + " ipproto udp lookup " + itoa(r.table)
		if !strings.Contains(rules, want) {
			t.Errorf("missing rule %q in:\n%s", want, rules)
		}
	}
}
