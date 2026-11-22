//go:build linux

package easytun

// LOOPBACK IS DOWN IN A FRESH NETWORK NAMESPACE, and every test that opens a socket to 127.0.0.1
// depends on it being up.
//
// MEASURED: `unshare -Urn` starts a namespace where `lo` is `<LOOPBACK> state DOWN`, so a listener
// bound to 127.0.0.1 accepts a connect attempt and never completes it - the symptom is a five-second
// read timeout in every test that uses a local server, which reads as "the relay is broken".
//
// A MACHINE'S OWN NAMESPACE HAS IT UP ALREADY, so this is a no-op there. It is attempted only when a
// test needs a socket, and its failure is not fatal: on a machine without `ip` the tests that do not
// need loopback still run, and the ones that do fail with their own message rather than a skip that
// hides a real defect.

import (
	"os/exec"
	"sync"
	"testing"
)

var devOnce sync.Once

// ensureLoopbackUp raises `lo` if it is down. Safe to call from every test.
func ensureLoopbackUp(t *testing.T) {
	t.Helper()
	devOnce.Do(func() {
		// `ip link set lo up` IS IDEMPOTENT: on a namespace that already has it up it succeeds and
		// changes nothing. The error is not fatal - see the file comment.
		_ = exec.Command("ip", "link", "set", "lo", "up").Run()
	})
}
