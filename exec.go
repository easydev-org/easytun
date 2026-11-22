package easytun

// THE PORTABLE PART: the one place this package shells out, and the error formatting that reads a
// command's answer. Kept out of tun.go so that the Linux-only file below is the only one that must be
// built on Linux - and a caller on another platform gets a clear refusal instead of a syscall error
// that names `unsafe`.

import (
	"os/exec"
	"strings"
)

// execCommand is a variable so a test can run the argument-building without a shell, and so the one
// place this package shells out is named.
var execCommand = exec.Command

// run executes a command and returns its combined output.
func run(name string, args ...string) (string, error) {
	cmd := execCommand(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// firstLine is the part of a command's output that says why, for a one-line error.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
