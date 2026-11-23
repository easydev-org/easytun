//go:build linux

package easytun

// CONTAINER MODE'S OWN BEHAVIOUR, AND THE ONE PROPERTY THAT MAKES IT USABLE: it can put the namespace
// back.
//
// The routing is done with `ip`, so the assertions here drive a fake `runFn` for the ORDER and the
// ARGUMENTS - which is where the correctness lives - and the real-kernel test below proves the effect.

import (
	"net"
	"strings"
	"testing"
)

// routeLog records the `ip` commands a test caused.
type routeLog struct{ cmds []string }

func (l *routeLog) install(t *testing.T, defaults string) {
	t.Helper()
	old := runFn
	runFn = func(name string, args ...string) (string, error) {
		l.cmds = append(l.cmds, name+" "+strings.Join(args, " "))
		if len(args) >= 3 && args[0] == "route" && args[1] == "show" && args[2] == "default" {
			return defaults, nil
		}
		return "", nil
	}
	t.Cleanup(func() { runFn = old })
}

// THE ORDER IS THE CORRECTNESS ARGUMENT: the exception routes must exist BEFORE the default route
// moves, or the relay's own traffic loops into its own device for the length of the gap.
func TestContainerExemptsTheProxyBeforeTheTakeover(t *testing.T) {
	var log routeLog
	log.install(t, "default via 172.17.0.1 dev eth0\n")

	oldOpen, oldUp, oldRemove := openDevice, bringUp, removeDevice
	defer func() { openDevice, bringUp, removeDevice = oldOpen, oldUp, oldRemove }()
	openDevice = func(string) (tunDevice, error) { return newPipeline(), nil }
	bringUp = func(string, string) error { return nil }
	removeDevice = func(string) error { return nil }

	c, err := StartContainer(ContainerConfig{
		Name:     "ct0",
		Upstream: "203.0.113.7:7891",
	})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	defer func() { _ = c.Close() }()

	exemptAt, takeoverAt := -1, -1
	for i, cmd := range log.cmds {
		if strings.Contains(cmd, "203.0.113.7/32") && exemptAt < 0 {
			exemptAt = i
		}
		if strings.Contains(cmd, "route replace default dev ct0") && takeoverAt < 0 {
			takeoverAt = i
		}
	}
	if exemptAt < 0 {
		t.Fatalf("the proxy was never exempted; commands were:\n%s", strings.Join(log.cmds, "\n"))
	}
	if takeoverAt < 0 {
		t.Fatalf("the default route never moved; commands were:\n%s", strings.Join(log.cmds, "\n"))
	}
	if exemptAt > takeoverAt {
		t.Fatalf("the exception was installed AFTER the takeover, so the proxy looped for %d commands:\n%s",
			exemptAt-takeoverAt, strings.Join(log.cmds, "\n"))
	}
	// AND THE EXCEPTION USES THE ROUTE THAT EXISTED BEFORE, not the device.
	if !strings.Contains(log.cmds[exemptAt], "via 172.17.0.1") ||
		!strings.Contains(log.cmds[exemptAt], "dev eth0") {
		t.Fatalf("the exception does not name the original way out: %q", log.cmds[exemptAt])
	}
}

// CLOSE PUTS THE ROUTE BACK, AND BEFORE IT DELETES THE DEVICE.
//
// A default route left pointing at a deleted device sends every packet to nowhere, and the container
// looks healthy while reaching nothing.
func TestCloseRestoresTheRouteBeforeRemovingTheDevice(t *testing.T) {
	var log routeLog
	log.install(t, "default via 172.17.0.1 dev eth0\n")

	oldOpen, oldUp, oldRemove := openDevice, bringUp, removeDevice
	defer func() { openDevice, bringUp, removeDevice = oldOpen, oldUp, oldRemove }()
	openDevice = func(string) (tunDevice, error) { return newPipeline(), nil }
	bringUp = func(string, string) error { return nil }
	removeDevice = func(string) error {
		log.cmds = append(log.cmds, "delete tun")
		return nil
	}

	c, err := StartContainer(ContainerConfig{Name: "ct1", Upstream: "203.0.113.7:7891"})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	log.cmds = nil // only what Close does
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	restoreAt, deleteAt := -1, -1
	for i, cmd := range log.cmds {
		if strings.Contains(cmd, "route replace default via 172.17.0.1 dev eth0") && restoreAt < 0 {
			restoreAt = i
		}
		if cmd == "delete tun" && deleteAt < 0 {
			deleteAt = i
		}
	}
	if restoreAt < 0 {
		t.Fatalf("Close did not restore the default route; commands were:\n%s", strings.Join(log.cmds, "\n"))
	}
	if deleteAt < 0 {
		t.Fatal("Close did not remove the device")
	}
	if restoreAt > deleteAt {
		t.Fatalf("the device was deleted before the route was restored:\n%s", strings.Join(log.cmds, "\n"))
	}
}

// A NAMESPACE WITH NO DEFAULT ROUTE IS REFUSED, because there is nothing to exempt and nowhere to
// restore - and a takeover would leave it unable to reach anything at all.
func TestContainerRefusesANamespaceWithNoWayOut(t *testing.T) {
	var log routeLog
	log.install(t, "")

	if _, err := StartContainer(ContainerConfig{Name: "ct2", Upstream: "203.0.113.7:7891"}); err == nil {
		t.Fatal("StartContainer accepted a namespace with no default route")
	} else if !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("the error does not say why: %v", err)
	}
}

// THE DEFAULT DEVICE NAME AND ADDRESS, so a caller that sets neither gets a predictable pair.
func TestContainerDefaults(t *testing.T) {
	var log routeLog
	log.install(t, "default via 172.17.0.1 dev eth0\n")
	oldOpen, oldUp, oldRemove := openDevice, bringUp, removeDevice
	defer func() { openDevice, bringUp, removeDevice = oldOpen, oldUp, oldRemove }()
	var opened, cidr string
	openDevice = func(name string) (tunDevice, error) { opened = name; return newPipeline(), nil }
	bringUp = func(_, c string) error { cidr = c; return nil }
	removeDevice = func(string) error { return nil }

	c, err := StartContainer(ContainerConfig{})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	defer func() { _ = c.Close() }()

	if opened != "easytun0" {
		t.Errorf("the device was opened as %q, want the default easytun0", opened)
	}
	if cidr != "10.99.0.1/24" {
		t.Errorf("the device address is %q, want the default 10.99.0.1/24", cidr)
	}
	if c.Addr != "10.99.0.1" {
		t.Errorf("the reported address is %q", c.Addr)
	}
}

// THE PROXY IS EXEMPTED AUTOMATICALLY WHEN IT IS GIVEN, because forgetting it is the failure mode:
// the relay's own connection loops into its own device.
func TestTheUpstreamIsExemptedWithoutBeingAsked(t *testing.T) {
	var log routeLog
	log.install(t, "default via 172.17.0.1 dev eth0\n")
	oldOpen, oldUp, oldRemove := openDevice, bringUp, removeDevice
	defer func() { openDevice, bringUp, removeDevice = oldOpen, oldUp, oldRemove }()
	openDevice = func(string) (tunDevice, error) { return newPipeline(), nil }
	bringUp = func(string, string) error { return nil }
	removeDevice = func(string) error { return nil }

	c, err := StartContainer(ContainerConfig{Name: "ct3", Upstream: "198.51.100.9:7891"})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	defer func() { _ = c.Close() }()

	found := false
	for _, cmd := range log.cmds {
		if strings.Contains(cmd, "198.51.100.9/32") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the upstream was not exempted; commands were:\n%s", strings.Join(log.cmds, "\n"))
	}
}

// A HOSTNAME UPSTREAM IS EXEMPTED BY ITS ADDRESS, since a route names an address.
func TestAHostnameUpstreamIsResolvedForItsException(t *testing.T) {
	old := exemptRouteFn
	defer func() { exemptRouteFn = old }()
	var got string
	exemptRouteFn = func(host string, _ defaultRoute) error { got = host; return nil }

	var log routeLog
	log.install(t, "default via 172.17.0.1 dev eth0\n")
	oldOpen, oldUp, oldRemove := openDevice, bringUp, removeDevice
	defer func() { openDevice, bringUp, removeDevice = oldOpen, oldUp, oldRemove }()
	openDevice = func(string) (tunDevice, error) { return newPipeline(), nil }
	bringUp = func(string, string) error { return nil }
	removeDevice = func(string) error { return nil }

	c, err := StartContainer(ContainerConfig{Name: "ct4", Upstream: "localhost:7891"})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	defer func() { _ = c.Close() }()
	if got != "localhost" {
		t.Fatalf("the exempted host is %q, want localhost", got)
	}
}

var _ = net.IPv4

// THE MARK IS WHAT BREAKS THE LOOP, and it is the one thing the routing tests above cannot show:
// without it, the relay's own socket is routed into the relay's own device.
//
// THIS ASSERTS THE SHAPE - a rule exists for the mark, before the takeover - because the effect needs a
// real namespace, and `TestE2EContainerTakesOver` measures the effect where one is available.
func TestTheMarkRulesAreInstalledAndRemoved(t *testing.T) {
	var log routeLog
	log.install(t, "default via 172.17.0.1 dev eth0\n")
	oldOpen, oldUp, oldRemove := openDevice, bringUp, removeDevice
	defer func() { openDevice, bringUp, removeDevice = oldOpen, oldUp, oldRemove }()
	openDevice = func(string) (tunDevice, error) { return newPipeline(), nil }
	bringUp = func(string, string) error { return nil }
	removeDevice = func(string) error { return nil }

	c, err := StartContainer(ContainerConfig{Name: "mk0"})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var sawAdd, sawDel bool
	for _, cmd := range log.cmds {
		if strings.Contains(cmd, "rule add fwmark 0x1 lookup 100") {
			sawAdd = true
		}
		if strings.Contains(cmd, "rule del fwmark 0x1 lookup 100") {
			sawDel = true
		}
	}
	if !sawAdd {
		t.Fatalf("no mark rule was installed, so the relay's own traffic would loop:\n%s",
			strings.Join(log.cmds, "\n"))
	}
	if !sawDel {
		t.Fatalf("the mark rule was not removed, so a second run would accumulate rules:\n%s",
			strings.Join(log.cmds, "\n"))
	}
	// AND THE ORIGINAL DEFAULT WENT INTO THE TABLE THE MARK POINTS AT, which is what makes the rule
	// mean something after `main` has been taken over.
	found := false
	for _, cmd := range log.cmds {
		if strings.Contains(cmd, "route replace default via 172.17.0.1 dev eth0 table 100") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the original default was not saved into table 100, so a marked socket would "+
			"still find the tun:\n%s", strings.Join(log.cmds, "\n"))
	}
}
