package main

// Regressions for the adversarial review of 2026-11-11 (Codex); the
// numbers are the review's.

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crgimenes/filo-term-go/screen"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// noDeadlineConn behaves as an SSH forwarded channel: no deadlines.
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return errors.New("deadline not supported") }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errors.New("deadline not supported") }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errors.New("deadline not supported") }

type noDeadlineListener struct{ net.Listener }

func (l noDeadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return noDeadlineConn{c}, nil
}

// serveLikeTunnel serves h as tunnel.serve does, over connections that
// refuse deadlines.
func serveLikeTunnel(t *testing.T, h http.Handler, headerTimeout time.Duration) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: headerTimeout}
	go func() { _ = srv.Serve(pipeListener{noDeadlineListener{ln}}) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func on(string) bool { return true }

// 1
func TestWebSocketUpgradeOverSSHChannel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		line, _ := brw.ReadString('\n')
		_, _ = c.Write([]byte("echo " + line))
	}))
	defer backend.Close()
	c := tunnelConf{Name: "t", Routes: []route{{"ws", portOf(t, backend)}}}
	rec := &recorder{}
	addr := serveLikeTunnel(t, newRouter(c, on, rec), time.Second)

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprint(conn, "GET /ws/x HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("upgrade: %q %v", status, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	_, _ = fmt.Fprint(conn, "hi\n")
	got, err := br.ReadString('\n')
	if err != nil || got != "echo hi\n" {
		t.Fatalf("after upgrade: %q %v", got, err)
	}

	_ = conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(rec.list("")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	l := rec.list("")
	if len(l) != 1 || l[0].Status != http.StatusSwitchingProtocols || l[0].RespHeader.Get("Upgrade") != "websocket" {
		t.Fatalf("recorded %+v", l)
	}
}

// 1
func TestSlowHeadersTimeOutOverSSHChannel(t *testing.T) {
	addr := serveLikeTunnel(t, http.NotFoundHandler(), 300*time.Millisecond)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprint(conn, "GET / HTTP/1.1\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadAll(conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("unfinished headers kept the connection past ReadHeaderTimeout")
	}
}

// 2
func TestLongPathIsCheap(t *testing.T) {
	h := newRouter(tunnelConf{Name: "t", Routes: []route{{"a/b", "1"}}}, on, &recorder{})
	start := time.Now()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", strings.Repeat("/x", 20000), nil))
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("a 40 KB path took %v to route", d)
	}
}

// 3
func TestLogFileIsCapped(t *testing.T) {
	old := maxLogFile
	maxLogFile = 2000
	defer func() { maxLogFile = old }()
	var fails []error
	rec := &recorder{dir: t.TempDir(), fail: func(err error) { fails = append(fails, err) }}
	for range 50 {
		rec.add(exchange{Time: time.Now(), Tunnel: "a", URL: "/" + strings.Repeat("u", 200)})
	}
	files, _ := filepath.Glob(filepath.Join(rec.dir, "*.jsonl"))
	info, err := os.Stat(files[0])
	if err != nil || info.Size() > 2000+400 {
		t.Fatalf("log grew to %d bytes", info.Size())
	}
	if len(fails) != 1 {
		t.Errorf("reported %d times, want once: %v", len(fails), fails)
	}
}

// 3
func TestPruneLogs(t *testing.T) {
	dir := t.TempDir()
	oldf, newf := filepath.Join(dir, "a-old.jsonl"), filepath.Join(dir, "a-new.jsonl")
	for _, f := range []string{oldf, newf} {
		_ = os.WriteFile(f, []byte("{}\n"), 0600)
	}
	past := time.Now().Add(-logKeep - time.Hour)
	_ = os.Chtimes(oldf, past, past)
	err := pruneLogs(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, errOld := os.Stat(oldf)
	_, errNew := os.Stat(newf)
	if errOld == nil || errNew != nil {
		t.Errorf("old kept: %v, new removed: %v", errOld == nil, errNew != nil)
	}
}

// 4
func TestRecentExchangesFromABigFile(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{dir: dir}
	base := time.Now().Add(-time.Hour)
	for i := range 300 {
		rec.add(exchange{Time: base.Add(time.Duration(i) * time.Second), Tunnel: "a", URL: fmt.Sprint("/", i)})
	}
	got, err := recentExchanges(dir, "", 3)
	if err != nil || len(got) != 3 || got[0].URL != "/299" || got[2].URL != "/297" || cap(got) != 3 {
		t.Fatalf("%v %v cap %d", got, err, cap(got))
	}
}

// 6
func TestRouteSwapsEndConsistent(t *testing.T) {
	tn := newTunnel(tunnelConf{Name: "t", Routes: []route{{"a", "1"}}}, &recorder{}, func() {})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() { tn.setRoutes([]route{{fmt.Sprint("r", i), "1"}}, "", "") })
	}
	wg.Wait()
	want := tn.routes()[0].Prefix
	w := httptest.NewRecorder()
	tn.ServeHTTP(w, httptest.NewRequest("GET", "/"+want+"/x", nil))
	if w.Code == http.StatusNotFound {
		t.Fatalf("routes say /%s, the handler does not route it", want)
	}
}

// 7
func TestFailedDeleteKeepsRouteOff(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	name := writeConfig(t, `(set Host "vps") (set Routes (list (tuple "x" "1") (tuple "y" "2")))`)
	confs, err := loadConfig(name)
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("screen", name, confs, false)
	tn := s.tunnels[0]
	tn.toggleRoute("x")
	err = s.saveRoutes(tn, []route{{"y", "2"}}, "", "")
	if err == nil {
		t.Fatal("saved into a legacy config")
	}
	if tn.routeOn("x") || len(tn.routes()) != 2 {
		t.Errorf("after the failed delete: x on=%v, routes %v", tn.routeOn("x"), tn.routes())
	}
}

// 8
func TestReplaceIfUnchanged(t *testing.T) {
	name := writeConfig(t, "theirs")
	again, err := replaceIfUnchanged(name, []byte("mine"), "new")
	b, _ := os.ReadFile(name)
	if !again || err != nil || string(b) != "theirs" {
		t.Fatalf("again=%v err=%v file=%q", again, err, b)
	}
	again, err = replaceIfUnchanged(name, []byte("theirs"), "new")
	b, _ = os.ReadFile(name)
	if again || err != nil || string(b) != "new" {
		t.Fatalf("again=%v err=%v file=%q", again, err, b)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(name), ".*devmux-*"))
	if len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

// 10
func TestOldStopDoesNotTurnNewGenerationOff(t *testing.T) {
	tn := newTunnel(tunnelConf{Name: "t"}, &recorder{}, func() {})
	oldDone, cancelled := make(chan struct{}), make(chan struct{})
	tn.mu.Lock()
	tn.cancel, tn.done = func() { close(cancelled) }, oldDone // the old generation
	tn.mu.Unlock()
	stopped := make(chan struct{})
	go func() {
		tn.stop()
		close(stopped)
	}()
	<-cancelled // stop took the old generation and waits for it to finish
	tn.mu.Lock()
	tn.cancel, tn.state = func() {}, stUp // the new generation is up
	tn.mu.Unlock()
	close(oldDone)
	<-stopped
	if tn.status().State != stUp {
		t.Fatalf("state %s, want up", tn.status().State)
	}
}

// 11
func TestEncodedSlashSurvivesStrip(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.RequestURI)
	}))
	defer backend.Close()
	front := httptest.NewServer(newRouter(tunnelConf{Name: "t", Routes: []route{{"api", portOf(t, backend)}}}, on, &recorder{}))
	defer front.Close()
	for path, want := range map[string]string{"/api/files/a%2Fb?q=1": "/files/a%2Fb?q=1", "/api": "/", "/api/x%20y": "/x%20y"} {
		resp, err := http.Get(front.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(got) != want {
			t.Errorf("%s: backend got %q, want %q", path, got, want)
		}
	}
}

// 12
func TestBodyStreamsToBackend(t *testing.T) {
	got := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 5)
		_, _ = io.ReadFull(r.Body, buf)
		got <- string(buf)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer backend.Close()
	rec := &recorder{}
	front := httptest.NewServer(newRouter(tunnelConf{Name: "t", Routes: []route{{"up", portOf(t, backend)}}}, on, rec))
	defer front.Close()

	pr, pw := io.Pipe()
	go func() {
		resp, err := http.Post(front.URL+"/up", "text/plain", pr)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	_, _ = pw.Write([]byte("hello"))
	select {
	case s := <-got:
		if s != "hello" {
			t.Fatalf("backend read %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first bytes did not reach the backend while the client kept the body open")
	}
	_, _ = pw.Write([]byte(" world"))
	_ = pw.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(rec.list("")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l := rec.list(""); len(l) != 1 || string(l[0].ReqBody) != "hello world" {
		t.Fatalf("recorded %+v", l)
	}
}

// 13
func TestCutResponseIsRecorded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 64<<10))
		for range 400 {
			_, err := w.Write(chunk)
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer backend.Close()
	rec := &recorder{}
	front := httptest.NewServer(newRouter(tunnelConf{Name: "t", Routes: []route{{"s", portOf(t, backend)}}}, on, rec))
	defer front.Close()
	resp, err := http.Get(front.URL + "/s")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadFull(resp.Body, make([]byte, 1000))
	_ = resp.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(rec.list("")) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	l := rec.list("")
	if len(l) != 1 || !strings.Contains(l[0].Note, "cut short") {
		t.Fatalf("recorded %+v", l)
	}
}

// 14
func TestPrintable(t *testing.T) {
	in := "ok\ttab\nline \x1b[2J\x1b]52;c;ZXZpbA==\x07 \u009b end"
	got := printable(in)
	if strings.ContainsAny(got, "\x1b\x07\u009b") || !strings.Contains(got, `\x1b[2J`) || !strings.Contains(got, "\t") || !strings.Contains(got, "\n") {
		t.Fatalf("%q", got)
	}
	ex := exchange{Method: "POST", URL: "/x", ReqHeader: http.Header{"Content-Type": {"text/plain"}}, ReqBody: payload("\x1b[2J")}
	if strings.Contains(formatExchange(ex, false), "\x1b") {
		t.Error("formatExchange let an ESC through")
	}
}

// 15
func TestRequestsCursorAfterEviction(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	s := newSession("screen", "devmux_init.filo", nil, false)
	s.rec.dir = ""
	for range 3 {
		s.rec.add(exchange{Time: time.Now(), Tunnel: "a"})
	}
	a := &app{s: s}
	v := &requestsView{tunnel: "a"}
	a.push(v)
	v.refresh(a)
	v.tab.Cursor = 2
	v.at = v.shown[2].ID
	for range ringMax {
		s.rec.add(exchange{Time: time.Now(), Tunnel: "b"})
	}
	a.handle(screen.KeyEnter) // panicked: index out of range
}

// 16
func TestCertAuthorityLeavesNegotiationOpen(t *testing.T) {
	pub, _, _ := ed25519Key(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := "@cert-authority *.example " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + "\n"
	err := os.WriteFile(path, []byte(line), 0600)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	got := knownHostAlgorithms(cb, "h.example:22")
	if got != nil {
		t.Fatalf("restricted to %v under a CA", got)
	}
}

// 17
func TestListMatchesHostToo(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	err := writeStatus(processStatus{PID: pid, Mode: "run", Tunnels: []tunnelStatus{{Name: "b", Host: "elsewhere", RemotePort: "10001", State: stUp}}})
	if err != nil {
		t.Fatal(err)
	}
	defer removeStatus()
	out := captureStdout(t, func() { runCommand("ls", []string{"-config", writeConfig(t, editSample), "-json"}) })
	var rows []lsRow
	err = json.Unmarshal([]byte(out), &rows)
	if err != nil {
		t.Fatal(err, out)
	}
	if rows[1].Name != "b" || rows[1].State != stOff {
		t.Fatalf("b took another config's state: %+v", rows[1])
	}
}

// 19
func TestRequestsRefusesBadN(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	(&recorder{dir: logsDir()}).add(exchange{Time: time.Now(), Tunnel: "a"})
	for _, n := range []string{"0", "-1"} {
		if code := runCommand("requests", []string{"-n", n}); code != 2 {
			t.Errorf("-n %s: exit %d, want 2", n, code)
		}
	}
}

// 20
func TestTunnelFormWithCommentAndNumber(t *testing.T) {
	src := "(tunnel ; the name\n  \"dev\" \"h\" \"10000\" (list))\n(tunnel 7 \"h\" \"10001\" (list))\n(tunnel \"tab\\tname\" \"h\" \"10002\" (list))"
	for _, name := range []string{"dev", "7", "tab\tname"} {
		_, _, ok := tunnelForm(src, name)
		if !ok {
			t.Errorf("%q not found", name)
		}
	}
	if quote("a\"b\\c\nd\te") != `"a\"b\\c\nd\te"` {
		t.Errorf("quote: %s", quote("a\"b\\c\nd\te"))
	}
}

func ed25519Key(t *testing.T) (ssh.PublicKey, any, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k, priv, nil
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = old
	_ = w.Close()
	return <-done
}

func portOf(t *testing.T, s *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}
