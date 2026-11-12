package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	stOff        = "off"
	stConnecting = "connecting"
	stUp         = "up"
	stRetry      = "retry"
)

const (
	keepAliveEvery    = 30 * time.Second
	keepAliveTimeout  = 15 * time.Second
	retryMax          = 30 * time.Second
	configPoll        = 2 * time.Second
	readHeaderTimeout = 10 * time.Second
	drainTimeout      = 5 * time.Second
	idleTimeout       = 2 * time.Minute
	maxHeaderBytes    = 64 << 10
	maxConns          = 256 // per tunnel: what one remote client can hold open
	pruneEvery        = time.Hour
)

type tunnelStatus struct {
	Name       string    `json:"name"`
	Host       string    `json:"host"`
	RemotePort string    `json:"remote_port"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`
	Since      time.Time `json:"since"`
	Retries    int       `json:"retries,omitempty"`
	Off        []string  `json:"routes_off,omitempty"`
}

// tunnel is one SSH session that opens RemotePort on the far side's
// loopback and serves the routes there. Once started it reconnects on its
// own until stopped.
type tunnel struct {
	conf    tunnelConf // Routes changes under mu, from setRoutes
	rec     *recorder
	handler atomic.Pointer[http.Handler]
	changed func()

	mu      sync.Mutex
	state   string
	lastErr string
	since   time.Time
	retries int
	off     map[string]bool
	cancel  context.CancelFunc
	done    chan struct{}
	gen     int // the generation whose loop may report state; start bumps it
}

func newTunnel(c tunnelConf, rec *recorder, changed func()) *tunnel {
	t := &tunnel{conf: c, rec: rec, changed: changed, state: stOff, since: time.Now(), off: map[string]bool{}}
	h := newRouter(c, t.routeOn, rec)
	t.handler.Store(&h)
	return t
}

func (t *tunnel) routes() []route {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.conf.Routes)
}

// setRoutes swaps the routes of a running tunnel: requests already in a
// proxy finish there, the next ones see the new table. from and to carry a
// renamed route's on/off state over ("" when nothing was renamed).
func (t *tunnel) setRoutes(routes []route, from, to string) {
	t.mu.Lock()
	t.conf.Routes = slices.Clone(routes)
	if from != "" && from != to {
		t.off[to] = t.off[from]
		delete(t.off, from)
	}
	for p := range t.off {
		if !slices.ContainsFunc(routes, func(r route) bool { return r.Prefix == p }) {
			delete(t.off, p)
		}
	}
	h := newRouter(t.conf, t.routeOn, t.rec)
	t.handler.Store(&h) // under mu: a slower swap cannot land after a newer one
	t.mu.Unlock()
	t.changed()
}

func (t *tunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*t.handler.Load()).ServeHTTP(w, r)
}

func (t *tunnel) status() tunnelStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := tunnelStatus{
		Name:       t.conf.Name,
		Host:       t.conf.Host,
		RemotePort: t.conf.RemotePort,
		State:      t.state,
		Error:      t.lastErr,
		Since:      t.since,
		Retries:    t.retries,
	}
	for _, r := range t.conf.Routes {
		if t.off[r.Prefix] {
			st.Off = append(st.Off, r.Prefix)
		}
	}
	return st
}

// report is a loop's word on the state; one from a generation that was
// stopped (and maybe started again) is dropped.
func (t *tunnel) report(gen int, state, errText string) {
	t.mu.Lock()
	if gen != t.gen || t.cancel == nil {
		t.mu.Unlock()
		return
	}
	t.state, t.lastErr, t.since = state, errText, time.Now()
	if state == stRetry {
		t.retries++
	}
	if state == stUp || state == stOff {
		t.retries = 0
	}
	t.mu.Unlock()
	t.changed()
}

func (t *tunnel) running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cancel != nil
}

func (t *tunnel) start() {
	t.mu.Lock()
	if t.cancel != nil {
		t.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel, t.done = cancel, make(chan struct{})
	t.gen++
	done, gen := t.done, t.gen
	t.mu.Unlock()
	go t.loop(ctx, done, gen)
}

// stop closes the session and waits for the requests in flight, at most
// drainTimeout. A stop while another is under way waits for that one.
func (t *tunnel) stop() {
	t.mu.Lock()
	cancel, done := t.cancel, t.done
	t.cancel = nil
	t.mu.Unlock()
	if done == nil {
		return
	}
	if cancel != nil {
		cancel()
	}
	<-done

	t.mu.Lock()
	if t.cancel != nil {
		t.mu.Unlock()
		return // started again meanwhile: that generation owns the state
	}
	t.state, t.lastErr, t.since, t.retries = stOff, "", time.Now(), 0
	t.mu.Unlock()
	t.changed()
}

func (t *tunnel) toggleRoute(prefix string) {
	t.mu.Lock()
	t.off[prefix] = !t.off[prefix]
	t.mu.Unlock()
	t.changed()
}

func (t *tunnel) routeOn(prefix string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.off[prefix]
}

func (t *tunnel) loop(ctx context.Context, done chan struct{}, gen int) {
	defer close(done)
	wait := time.Second
	for {
		t.report(gen, stConnecting, "")
		up, err := t.serve(ctx, gen)
		if ctx.Err() != nil {
			return
		}
		if up {
			wait = time.Second
		}
		t.report(gen, stRetry, err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, retryMax)
	}
}

// serve holds one SSH session until it breaks or ctx ends; up says the
// remote port was opened, which resets the backoff.
func (t *tunnel) serve(ctx context.Context, gen int) (up bool, err error) {
	client, err := dialSSH(ctx, t.conf.Host)
	if err != nil {
		return false, err
	}
	defer func() { _ = client.Close() }()

	var ln net.Listener
	closeOnCancel := context.AfterFunc(ctx, func() { _ = client.Close() })
	err = bounded(client, sshTimeout, func() (err error) {
		ln, err = client.Listen("tcp", net.JoinHostPort("127.0.0.1", t.conf.RemotePort))
		return err
	})
	closeOnCancel()
	if err != nil {
		return false, fmt.Errorf("remote listen %s: %w", t.conf.RemotePort, err)
	}
	t.report(gen, stUp, "")

	// The far end of the tunnel is a port open on the VPS: ReadHeaderTimeout
	// bounds a client that dribbles headers (Slowloris), MaxHeaderBytes what
	// each request keeps in the ring, maxConns how many it can hold open;
	// a stalled body is cut by bodyTap.
	server := &http.Server{
		Handler:           t,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	served := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		tick := time.NewTicker(keepAliveEvery)
		defer tick.Stop()
		for {
			select {
			case <-served:
				return
			case <-tick.C:
			}
			err := bounded(client, keepAliveTimeout, func() error {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				return err
			})
			if err != nil {
				_ = client.Close()
				return
			}
		}
	}()
	// #nosec G118 -- ctx is already cancelled when the drain runs; it needs
	// a deadline of its own.
	go func() {
		defer close(drained)
		select {
		case <-served:
		case <-ctx.Done():
			// Shutdown first closes the remote listener, which waits for the
			// SSH server's reply: on a silent link the client is closed at
			// the drain deadline, which ends that wait.
			timer := time.AfterFunc(drainTimeout, func() { _ = client.Close() })
			sctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
			_ = server.Shutdown(sctx)
			cancel()
			timer.Stop()
		}
	}()
	err = server.Serve(pipeListener{Listener: ln, slots: make(chan struct{}, maxConns)})
	close(served)
	<-drained // Shutdown returns Serve at once; the requests still need the client
	// Whatever outlived the drain (a body stalled against a backend that
	// stopped reading) is cut, pipes included: nothing outlives serve.
	_ = server.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return true, nil
	}
	return true, fmt.Errorf("session lost: %w", err)
}

// bounded runs fn, a request that waits for the SSH server's reply with no
// deadline of its own, and closes the client if no reply comes within d: on
// a link gone silent that is what ends the wait.
func bounded(client io.Closer, d time.Duration, fn func() error) error {
	timer := time.AfterFunc(d, func() { _ = client.Close() })
	err := fn()
	if !timer.Stop() {
		return fmt.Errorf("no reply from the SSH server in %v", d)
	}
	return err
}

// pipeListener serves each SSH channel through a net.Pipe. The channel
// (x/crypto/ssh chanConn) refuses deadlines and net/http needs them: for
// ReadHeaderTimeout, and to stop its background read when a handler
// hijacks the connection, without which a WebSocket upgrade hangs.
// Past maxConns open at once, a new channel is closed at once.
type pipeListener struct {
	net.Listener
	slots chan struct{}
}

func (l pipeListener) Accept() (net.Conn, error) {
	for {
		ch, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return l.pipe(ch), nil
		default:
			_ = ch.Close()
		}
	}
}

func (l pipeListener) pipe(ch net.Conn) net.Conn {
	inner, outer := net.Pipe()
	go func() {
		_, _ = io.Copy(outer, ch)
		_ = outer.Close()
	}()
	go func() {
		_, _ = io.Copy(ch, outer)
		_ = ch.Close()
		<-l.slots
	}()
	return pipeConn{Conn: inner, ch: ch}
}

// pipeConn keeps the channel's addresses: X-Forwarded-For comes from them.
type pipeConn struct {
	net.Conn
	ch net.Conn
}

func (c pipeConn) LocalAddr() net.Addr  { return c.ch.LocalAddr() }
func (c pipeConn) RemoteAddr() net.Addr { return c.ch.RemoteAddr() }

// session owns the tunnels of one devmux process and publishes their state
// in its status file.
type session struct {
	mode      string
	config    string
	started   time.Time
	tunnels   []*tunnel
	rec       *recorder
	wake      chan struct{}
	quit      chan struct{}
	closeOnce sync.Once
	editMu    sync.Mutex             // a route save and a reload, one at a time
	pubMu     sync.Mutex             // one status write at a time: they share the temp file
	warning   atomic.Pointer[string] // the screen's next note; run prints instead
}

func newSession(mode, config string, confs []tunnelConf, echo bool) *session {
	s := &session{mode: mode, config: config, started: time.Now(), wake: make(chan struct{}, 1), quit: make(chan struct{})}
	s.rec = &recorder{dir: logsDir(), wake: s.notify, fail: s.warn}
	for _, c := range confs {
		s.tunnels = append(s.tunnels, newTunnel(c, s.rec, s.changed))
	}
	s.rec.echo = echo
	go s.pruneLoop(s.rec.dir)
	return s
}

// pruneLoop removes old logs now and every pruneEvery until close: a devmux
// left running for weeks must not keep them all.
func (s *session) pruneLoop(dir string) {
	tick := time.NewTicker(pruneEvery)
	defer tick.Stop()
	for {
		err := pruneLogs(dir)
		if err != nil {
			s.warn(fmt.Errorf("removing old logs: %w", err))
		}
		select {
		case <-s.quit:
			return
		case <-tick.C:
		}
	}
}

// notify wakes whoever draws; a wake already pending covers this one.
func (s *session) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *session) changed() {
	s.publish()
	s.notify()
}

// editRoutes applies edit to t's routes in the config file and, once that
// worked, gives the result to the running tunnel. editMu keeps the config
// watcher from reloading in between, which would lose a renamed route's
// on/off state.
func (s *session) editRoutes(t *tunnel, edit func([]route) ([]route, error), from, to string) error {
	s.editMu.Lock()
	defer s.editMu.Unlock()
	routes, err := editRoutes(s.config, t.conf.Name, edit)
	if err != nil {
		return err
	}
	t.setRoutes(routes, from, to)
	return nil
}

// watchConfig reloads the routes when the config file changes on disk
// (devmux route, another devmux, an editor), until close. Tunnels added or
// removed there need a restart.
func (s *session) watchConfig() {
	stamp := func() string {
		info, err := os.Stat(s.config) // #nosec G703 -- the config file this devmux loaded
		if err != nil {
			return ""
		}
		return fmt.Sprint(info.ModTime().UnixNano(), info.Size())
	}
	last := stamp()
	tick := time.NewTicker(configPoll)
	defer tick.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-tick.C:
		}
		now := stamp()
		if now == last || now == "" {
			continue
		}
		last = now
		s.reload()
	}
}

func (s *session) reload() {
	s.editMu.Lock()
	defer s.editMu.Unlock()
	confs, err := loadConfig(s.config)
	if err != nil {
		s.warn(fmt.Errorf("config changed but does not load, routes kept: %w", err))
		return
	}
	for _, t := range s.tunnels {
		i := slices.IndexFunc(confs, func(c tunnelConf) bool { return c.Name == t.conf.Name })
		if i < 0 || slices.Equal(confs[i].Routes, t.routes()) {
			continue
		}
		t.setRoutes(confs[i].Routes, "", "")
		s.warn(fmt.Errorf("config changed: routes of %s reloaded", t.conf.Name))
	}
}

func (s *session) publish() {
	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	st := processStatus{PID: pid, Mode: s.mode, Config: s.config, Started: s.started}
	for _, t := range s.tunnels {
		st.Tunnels = append(st.Tunnels, t.status())
	}
	err := writeStatus(st)
	if err != nil {
		s.warn(fmt.Errorf("status: %w", err))
	}
}

// warn reports a failure that costs a log line or the status file, not the
// tunnel: on stderr in run, as a note on the screen (stderr is the screen).
func (s *session) warn(err error) {
	if s.mode == "run" {
		warnf("%v", err)
		return
	}
	text := err.Error()
	s.warning.Store(&text)
	s.notify()
}

// close stops every tunnel at once and removes the status file.
func (s *session) close() {
	s.closeOnce.Do(func() { close(s.quit) })
	var wg sync.WaitGroup
	for _, t := range s.tunnels {
		wg.Go(t.stop)
	}
	wg.Wait()
	removeStatus()
}
