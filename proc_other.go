//go:build !unix

package main

// yagni: without kill(pid, 0) a status file is trusted until devmux removes
// it; a crash leaves it behind. Windows is not a target.
func processAlive(pid int) bool { return pid > 0 }
