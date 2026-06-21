package main

import "testing"

// TestRunFiloFile verifies that the bundled sample config (devmux_init.filo) is
// parsed by the Filo interpreter into the expected globals.
func TestRunFiloFile(t *testing.T) {
	// Reset package-level config to defaults before loading.
	host = ""
	remotePort = "10000"
	routes = map[string]string{}

	runFiloFile("./devmux_init.filo")

	if host != "util.crg.eti.br" {
		t.Fatalf("Host = %q, want %q", host, "util.crg.eti.br")
	}
	if remotePort != "10000" {
		t.Fatalf("RemotePort = %q, want %q", remotePort, "10000")
	}

	want := map[string]string{"ip": "8001", "dump": "8080", "bbs": "2020"}
	if len(routes) != len(want) {
		t.Fatalf("Routes has %d entries, want %d: %v", len(routes), len(want), routes)
	}
	for k, v := range want {
		if routes[k] != v {
			t.Fatalf("Routes[%q] = %q, want %q", k, routes[k], v)
		}
	}
}
