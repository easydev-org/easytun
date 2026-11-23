//go:build linux

package easytun

// THE TWO CONSTANTS SO_MARK NEEDS, declared rather than imported: they are Linux's own values from
// <linux/socket.h> and <asm-generic/socket.h>, and a dependency for two numbers is not worth it.
const (
	// soMark is SO_MARK, which tags a socket so `ip rule fwmark` can match it.
	soMark = 36
)

// errNotUDP is returned when a listen that should produce a UDP socket does not.
type constErr string

func (e constErr) Error() string { return string(e) }

const errNotUDP = constErr("easytun: a UDP listen produced a non-UDP socket")
