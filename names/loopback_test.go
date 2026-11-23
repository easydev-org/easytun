package names

// LOOPBACK IS DOWN IN A FRESH NETWORK NAMESPACE, and every test that opens a socket to 127.0.0.1
// depends on it being up.
//
// MEASURED: `unshare -Urn` starts a namespace where `lo` is `<LOOPBACK> state DOWN`, so a listener bound
// to 127.0.0.1 accepts a connect attempt and never completes it - or, for UDP, the bind succeeds and the
// send reports "network is unreachable". A machine's own namespace has it up already, so this is a
// no-op there.

import (
	"os/exec"
	"sync"
	"testing"
)

var loOnce sync.Once

func ensureLoopbackUp(t *testing.T) {
	t.Helper()
	loOnce.Do(func() {
		_ = exec.Command("ip", "link", "set", "lo", "up").Run()
	})
}
