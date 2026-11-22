//go:build !linux

package easytun

// THIS PACKAGE IS LINUX-ONLY, AND SAYS SO ONCE RATHER THAN FAILING IN A SYSCALL.
//
// `openTun` is a `TUNSETIFF` ioctl and `Preflight` is a netlink socket and `ip link`; none of that
// exists anywhere else. The alternative is a build that compiles on darwin and fails at the first
// packet with a message about `unsafe`, so the refusal is here, named, at the call.

import (
	"fmt"
	"os"
	"runtime"
)

func notLinux() error {
	return fmt.Errorf("easytun: %s is not supported; this package drives /dev/net/tun with a "+
		"Linux ioctl and manages policy routing with `ip`, neither of which exists here. "+
		"Build for linux/amd64 or linux/arm64", runtime.GOOS)
}

func openTun(string) (*os.File, error) { return nil, notLinux() }

func deleteTun(string) error { return notLinux() }

// Preflight is the same refusal, so a caller's first line compiles and reports the platform rather
// than the absence of a symbol.
func Preflight() error { return notLinux() }
