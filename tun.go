//go:build linux

package easytun

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// THE TUN DEVICE, AND THE ONE FLAG THAT MATTERS.
//
// `IFF_NO_PI` IS WHAT MAKES EVERY READ A BARE IP PACKET. Without it the kernel prefixes four bytes
// of flags and protocol, and a parser that assumed offset zero reads the flags word as the IP
// version - MEASURED as `ipversion=6 proto=128` on a device that was working correctly.
const (
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	tunSetIFF = 0x400454ca
)

// ifreq is the struct `TUNSETIFF` takes: a 16-byte name and a 16-bit flag word.
type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// buildIfreq is the request this package sends, split out so a test can assert the flags without a
// tun device - which is the only way the `IFF_NO_PI` measurement gets protected on a CI runner.
//
// THE NAME IS CLIPPED TO 15 BYTES AND THE 16TH STAYS ZERO. `ifr_name` is `IFNAMSIZ` (16) bytes and the
// kernel requires a NUL terminator inside it; `copy` alone fills all 16 for a longer name and the
// kernel then reads past the field. MEASURED as a device name the kernel reported as garbage.
func buildIfreq(name string) ifreq {
	var req ifreq
	copy(req.name[:len(req.name)-1], name)
	req.flags = iffTun | iffNoPI
	return req
}

// openTun creates (or attaches to) a tun device.
func openTun(name string) (*os.File, error) {
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		if os.IsPermission(err) || err == syscall.EPERM {
			return nil, fmt.Errorf("%w: %v", ErrNoTun, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrNoTun, err)
	}
	req := buildIfreq(name)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunSetIFF),
		uintptr(unsafe.Pointer(&req))); e != 0 {
		syscall.Close(fd)
		// EPERM HERE IS THE CAPABILITY, NOT THE DEVICE: the fd opened and the ioctl was refused.
		if e == syscall.EPERM {
			return nil, fmt.Errorf("%w: TUNSETIFF on %q was refused", ErrNoNetAdmin, name)
		}
		return nil, fmt.Errorf("TUNSETIFF on %q: %v", name, e)
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

// deleteTun removes the device, treating "already gone" as success.
func deleteTun(name string) error {
	out, err := run("ip", "link", "del", name)
	if err != nil && !strings.Contains(out, "Cannot find device") {
		return fmt.Errorf("removing %s: %v (%s)", name, err, firstLine(out))
	}
	return nil
}
