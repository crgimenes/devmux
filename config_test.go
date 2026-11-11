package main

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/crgimenes/filo-term-go/screen"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "init.filo")
	err := os.WriteFile(name, []byte(text), 0600)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestLoadConfigSample(t *testing.T) {
	confs, err := loadConfig("devmux_init.filo")
	if err != nil {
		t.Fatal(err)
	}
	if len(confs) != 2 || confs[0].Name != "util" || confs[1].Name != "gauss" {
		t.Fatalf("tunnels = %+v", confs)
	}
	want := []route{{"api", "3000"}, {"api/v1", "3001"}}
	if confs[1].Host != "gauss" || confs[1].RemotePort != "10100" || !slices.Equal(confs[1].Routes, want) {
		t.Fatalf("gauss = %+v", confs[1])
	}
}

func TestLoadConfigLegacyGlobals(t *testing.T) {
	name := writeConfig(t, "\uFEFF"+`(set Host "vps")
(set Routes (list (tuple "web" "8080") (tuple "/api/" "3000")))`)
	confs, err := loadConfig(name)
	if err != nil {
		t.Fatal(err)
	}
	want := tunnelConf{Name: "vps", Host: "vps", RemotePort: "10000", Routes: []route{{"api", "3000"}, {"web", "8080"}}}
	if len(confs) != 1 || confs[0].Name != want.Name || confs[0].RemotePort != want.RemotePort || !slices.Equal(confs[0].Routes, want.Routes) {
		t.Fatalf("got %+v, want %+v", confs, want)
	}
}

func TestLoadConfigRefuses(t *testing.T) {
	for _, text := range []string{
		``,
		`(tunnel "a" "h" "10000")`,
		`(tunnel "a" "h" "0" (list))`,
		`(tunnel "a/b" "h" "10000" (list))`,
		`(tunnel "a" "h" "10000" (list (tuple "x" "99999")))`,
		`(tunnel "a" "h" "10000" (list (tuple "x" "1") (tuple "/x" "2")))`,
		`(tunnel "a" "h" "10000" (list)) (tunnel "a" "h" "10001" (list))`,
	} {
		_, err := loadConfig(writeConfig(t, text))
		if err == nil {
			t.Errorf("accepted %q", text)
		}
	}
}

func TestRouterLongestPrefix(t *testing.T) {
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

	c := tunnelConf{Name: "t", Host: "h", RemotePort: "10000", Routes: []route{{"api", port(api)}, {"api/v1", port(v1)}}}
	off := map[string]bool{}
	rec := &recorder{dir: t.TempDir()}
	front := httptest.NewServer(newRouter(c, func(p string) bool { return !off[p] }, rec))
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

	off["api/v1"] = true
	for path, want := range map[string]int{"/nope": http.StatusNotFound, "/api/v1/x": http.StatusServiceUnavailable} {
		resp, err := http.Get(front.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
	}

	got := rec.list("")
	if len(got) != 6 {
		t.Fatalf("recorded %d exchanges, want 6", len(got))
	}
	big4 := got[2] // newest first: 503, 404, then this one
	if big4.URL != "/api/v2" || len(big4.ReqBody) != maxLoggedBody || !big4.ReqTruncated || big4.Route != "api" {
		t.Errorf("big request recorded as %s %s body=%d truncated=%v", big4.Route, big4.URL, len(big4.ReqBody), big4.ReqTruncated)
	}
}

func TestPayloadJSON(t *testing.T) {
	for _, p := range []payload{payload(`{"a":"ç"}`), {0xff, 0x00, 0xfe}} {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var back payload
		err = json.Unmarshal(b, &back)
		if err != nil || string(back) != string(p) {
			t.Errorf("%q -> %s -> %q (%v)", p, b, back, err)
		}
	}
	b, _ := json.Marshal(payload(`{"a":1}`))
	if string(b) != `"{\"a\":1}"` {
		t.Errorf("text body marshals as %s", b)
	}
}

func TestRecentExchangesAndFind(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{dir: dir}
	base := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	for i := range 6 {
		tunnel := "a"
		if i%2 == 1 {
			tunnel = "b"
		}
		rec.add(exchange{Time: base.Add(time.Duration(i) * time.Minute), Tunnel: tunnel, Method: "GET", URL: "/" + string(rune('0'+i))})
	}

	got, err := recentExchanges(dir, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	for _, ex := range got {
		urls = append(urls, ex.URL)
	}
	if !slices.Equal(urls, []string{"/5", "/4", "/3"}) {
		t.Errorf("all: %v", urls)
	}

	got, err = recentExchanges(dir, "a", 10)
	if err != nil || len(got) != 3 || got[0].URL != "/4" {
		t.Errorf("tunnel a: %v %v", got, err)
	}

	ex, err := findExchange(dir, got[1].ID)
	if err != nil || ex.URL != "/2" {
		t.Errorf("find: %+v %v", ex, err)
	}
	_, err = findExchange(dir, "nope")
	if err == nil {
		t.Error("found a request that was never made")
	}
}

func TestScreenDraws(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	confs, err := loadConfig("devmux_init.filo")
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("screen", "devmux_init.filo", confs, false)
	s.rec.add(exchange{Time: time.Now(), Tunnel: "gauss", Method: "POST", URL: "/api/hook", Status: 200,
		ReqHeader: http.Header{"Content-Type": {"application/json"}}, ReqBody: payload(`{"event":"paid"}`)})
	a := &app{s: s}
	a.push(&tunnelsView{})

	draw := func() string {
		c := screen.New(100, 20)
		a.drawOn(c, 100, 20)
		return c.String()
	}
	out := draw()
	for _, want := range []string{"util", "gauss:10100", "api→3000", "off"} {
		if !strings.Contains(out, want) {
			t.Errorf("tunnels screen lacks %q:\n%s", want, out)
		}
	}

	a.handle(screen.KeyDown)
	a.handle(screen.KeyEnter)
	s.tunnels[1].toggleRoute("api/v1")
	out = draw()
	if !strings.Contains(out, "/api/v1") || !strings.Contains(out, "off") {
		t.Errorf("routes screen:\n%s", out)
	}

	a.handle('r')
	a.handle(screen.KeyEnter)
	out = draw()
	if !strings.Contains(out, `"event": "paid"`) {
		t.Errorf("detail screen lacks the indented body:\n%s", out)
	}
	a.handle(screen.KeyEsc)
	a.handle(screen.KeyEsc)
	a.handle(screen.KeyEsc)
	a.handle('q')
	if !a.quit {
		t.Error("q on the tunnels screen did not quit")
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
