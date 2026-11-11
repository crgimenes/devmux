package main

import (
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestRunFiloFile verifies that the bundled sample config (devmux_init.filo) is
// parsed by the Filo interpreter into the expected globals.
func TestRunFiloFile(t *testing.T) {
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

func TestRouterLongestPrefix(t *testing.T) {
	t.Chdir(t.TempDir())

	backend := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			_, _ = io.WriteString(w, name+" "+r.URL.Path+" "+string(body))
		}))
	}
	api, v1 := backend("api"), backend("v1")
	defer api.Close()
	defer v1.Close()
	port := func(s *httptest.Server) string {
		u, _ := url.Parse(s.URL)
		return u.Port()
	}

	router, err := newRouter(map[string]string{"api": port(api), "/api/v1/": port(v1)})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(router)
	defer front.Close()

	big := strings.Repeat("x", maxLoggedBody+10)
	cases := []struct{ path, body, want string }{
		{"/api/users", "", "api /users "},
		{"/api/v1/users", "", "v1 /users "},
		{"/api/v1", "", "v1 / "},
		{"/api/v2", big, "api /v2 " + big},
	}
	for _, c := range cases {
		resp, err := http.Post(front.URL+c.path, "text/plain", strings.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(got) != c.want {
			t.Errorf("%s: got %.40q, want %.40q (len %d vs %d)", c.path, got, c.want, len(got), len(c.want))
		}
	}

	resp, err := http.Get(front.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/nope: status %d, want 404", resp.StatusCode)
	}

	_, err = newRouter(map[string]string{"bad": "http"})
	if err == nil {
		t.Error("invalid port accepted")
	}
}

func TestKnownHostAlgorithms(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"h"}, key) + "\n"
	err = os.WriteFile(path, []byte(line), 0600)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}

	got := knownHostAlgorithms(cb, "h:22")
	if !slices.Equal(got, []string{ssh.KeyAlgoED25519}) {
		t.Errorf("known host: got %v", got)
	}
	got = knownHostAlgorithms(cb, "other:22")
	if got != nil {
		t.Errorf("unknown host: got %v, want nil", got)
	}
}
