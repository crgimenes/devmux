//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// lockFile holds an exclusive flock on name, created if missing, until the
// returned func runs. The lock file is never replaced, unlike the config.
func lockFile(name string) (func(), error) {
	f, err := os.OpenFile(filepath.Clean(name), os.O_CREATE|os.O_RDWR, 0600) // #nosec G304 G703 -- beside the config file devmux loaded
	if err != nil {
		return nil, err
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX) // #nosec G115 -- a file descriptor fits an int
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil // closing drops the lock
}
