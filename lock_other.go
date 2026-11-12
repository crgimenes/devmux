//go:build !unix

package main

// yagni: no flock here; two writers at once fall back on the re-read before
// the rename. Windows is not a target.
func lockFile(string) (func(), error) { return func() {}, nil }
