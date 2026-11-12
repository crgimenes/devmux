package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/crgimenes/filo-term-go/kit"
	"github.com/crgimenes/filo-term-go/screen"
)

const editSample = `;;; header comment (tunnel "b" stays)
(tunnel "a" "host-a" "10000"
  ;; a comment inside a, lost on save
  (list (tuple "x" "1")))

(set Note "a ) in a string (tunnel \"b\" ...")
(tunnel "b" "host-b" "10001" (list (tuple "y" "2")))  ;; trailing
`

func TestTunnelForm(t *testing.T) {
	start, end, ok := tunnelForm(editSample, "b")
	if !ok || editSample[start:end] != `(tunnel "b" "host-b" "10001" (list (tuple "y" "2")))` {
		t.Fatalf("b: %v %q", ok, editSample[start:end])
	}
	_, _, ok = tunnelForm(editSample, "c")
	if ok {
		t.Error("found a tunnel that is not there")
	}
}

func TestSaveTunnelKeepsTheRest(t *testing.T) {
	name := writeConfig(t, editSample)
	err := os.Chmod(name, 0640)
	if err != nil {
		t.Fatal(err)
	}
	c := tunnelConf{Name: "b", Host: "host-b", RemotePort: "10001", Routes: []route{{"y", "2"}, {"api/v1", "3001"}}}
	_, err = editRoutes(name, c.Name, setRoutesTo(c.Routes))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(name)
	got := string(b)
	want := strings.Replace(editSample, `(tunnel "b" "host-b" "10001" (list (tuple "y" "2")))`, `(tunnel "b" "host-b" "10001"
  (list
    (tuple "y"      "2")
    (tuple "api/v1" "3001")))`, 1)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	info, _ := os.Stat(name)
	if info.Mode().Perm() != 0640 {
		t.Errorf("mode %v, want 0640", info.Mode().Perm())
	}

	c.Routes = nil
	_, err = editRoutes(name, c.Name, setRoutesTo(c.Routes))
	if err != nil {
		t.Fatal(err)
	}
	confs, err := loadConfig(name)
	if err != nil || len(confs[1].Routes) != 0 || len(confs[0].Routes) != 1 {
		t.Fatalf("after emptying b: %+v %v", confs, err)
	}

	legacy := writeConfig(t, `(set Host "vps") (set Routes (list (tuple "w" "80")))`)
	_, err = editRoutes(legacy, "vps", setRoutesTo(nil))
	if err == nil {
		t.Error("saved into a config with no (tunnel ...) form")
	}
}

func TestFitCols(t *testing.T) {
	cells := [][]string{{"gauss", "gauss:10100", "api→3000", "off"}}
	cols := fitCols([]kit.Col{{Header: "tunnel", Width: 16}, {Header: "remote", Width: 28}, {Header: "routes"}, {Header: "state", Width: 28}}, cells, 2, 100)
	widths := []int{cols[0].Width, cols[1].Width, cols[2].Width, cols[3].Width}
	if !slices.Equal(widths, []int{6, 11, 100 - 3 - 6 - 11 - 5, 5}) {
		t.Errorf("widths %v", widths)
	}
}

func TestScreenEditsRoutes(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	name := writeConfig(t, editSample)
	confs, err := loadConfig(name)
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("screen", name, confs, false)
	a := &app{s: s}
	a.push(&tunnelsView{})
	typeIn := func(keys ...screen.Key) {
		for _, k := range keys {
			a.handle(k)
		}
	}
	text := func(s string) []screen.Key {
		var ks []screen.Key
		for _, r := range s {
			ks = append(ks, screen.Key(r))
		}
		return ks
	}
	routesOf := func() []route {
		confs, err := loadConfig(name)
		if err != nil {
			t.Fatal(err)
		}
		return confs[0].Routes
	}

	typeIn(screen.KeyEnter, 'a')
	typeIn(text("/hook/")...)
	typeIn(screen.KeyEnter)
	typeIn(text("80800")...)
	typeIn(screen.Ctrl('w'))
	if a.views[len(a.views)-1].(*routeForm).form.Note == "" || len(routesOf()) != 1 {
		t.Fatalf("a bad port was saved: %v", routesOf())
	}
	typeIn(screen.KeyBackspace, screen.Ctrl('w'))
	if got := routesOf(); !slices.Equal(got, []route{{"x", "1"}, {"hook", "8080"}}) {
		t.Fatalf("after add: %v", got)
	}
	if _, ok := a.views[len(a.views)-1].(*routesView); !ok {
		t.Fatal("save did not go back to the routes")
	}

	s.tunnels[0].toggleRoute("x")
	typeIn(screen.KeyHome, 'e')
	typeIn(screen.Ctrl('u'))
	typeIn(text("xx")...)
	typeIn(screen.Ctrl('w'))
	if got := routesOf(); !slices.Equal(got, []route{{"xx", "1"}, {"hook", "8080"}}) {
		t.Fatalf("after edit: %v", got)
	}
	if s.tunnels[0].routeOn("xx") {
		t.Error("the renamed route lost its off state")
	}

	typeIn(screen.KeyEnd, 'd', 'n')
	if len(routesOf()) != 2 {
		t.Fatal("n deleted the route")
	}
	typeIn('d', 'y')
	if got := routesOf(); !slices.Equal(got, []route{{"xx", "1"}}) || !slices.Equal(s.tunnels[0].routes(), got) {
		t.Fatalf("after delete: file %v, tunnel %v", got, s.tunnels[0].routes())
	}
}

func TestRouteCommand(t *testing.T) {
	name := writeConfig(t, editSample)
	run := func(args ...string) int {
		return runCommand("route", append([]string{"-config", name}, args...))
	}
	routesOf := func() []route {
		confs, err := loadConfig(name)
		if err != nil {
			t.Fatal(err)
		}
		return confs[1].Routes
	}

	cases := []struct {
		args []string
		want int
	}{
		{[]string{"add", "b", "/hook/", "8080"}, 0},
		{[]string{"add", "b", "hook", "9090"}, 1},
		{[]string{"add", "b", "a b", "1"}, 2},
		{[]string{"add", "b", "x", "70000"}, 2},
		{[]string{"add", "nope", "x", "1"}, 2},
		{[]string{"add", "b", "x"}, 2},
		{[]string{"rm", "b", "nope"}, 1},
		{[]string{"rm", "b", "y"}, 0},
		{[]string{"mv", "b", "y"}, 2},
	}
	for _, c := range cases {
		got := run(c.args...)
		if got != c.want {
			t.Errorf("route %v: exit %d, want %d", c.args, got, c.want)
		}
	}
	if got := routesOf(); !slices.Equal(got, []route{{"hook", "8080"}}) {
		t.Errorf("routes of b: %v", got)
	}
}

func TestSessionReloadsRoutes(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	name := writeConfig(t, editSample)
	confs, err := loadConfig(name)
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("screen", name, confs, false)
	s.tunnels[1].toggleRoute("y")

	if runCommand("route", []string{"-config", name, "add", "b", "z", "3"}) != 0 {
		t.Fatal("route add failed")
	}
	s.reload()
	if got := s.tunnels[1].routes(); !slices.Equal(got, []route{{"y", "2"}, {"z", "3"}}) {
		t.Errorf("reloaded routes: %v", got)
	}
	if s.tunnels[1].routeOn("y") {
		t.Error("reload switched an off route back on")
	}
	w := s.warning.Load()
	if w == nil || !strings.Contains(*w, "routes of b reloaded") {
		t.Errorf("no note about the reload: %v", w)
	}
}

func setRoutesTo(rs []route) func([]route) ([]route, error) {
	return func([]route) ([]route, error) { return rs, nil }
}
