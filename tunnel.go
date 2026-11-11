package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	keepAliveEvery = 30 * time.Second
	retryMax       = 30 * time.Second
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
	conf    tunnelConf
	handler http.Handler
	changed func()

	mu      sync.Mutex
	state   string
	lastErr string
	since   time.Time
	retries int
	off     map[string]bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func newTunnel(c tunnelConf, rec *recorder, changed func()) *tunnel {
	t := &tunnel{conf: c, changed: changed, state: stOff, since: time.Now(), off: map[string]bool{}}
	t.handler = newRouter(c, t.routeOn, rec)
	return t
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

func (t *tunnel) set(state, errText string) {
	t.mu.Lock()
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
	done := t.done
	t.mu.Unlock()
	go t.loop(ctx, done)
}

// stop closes the session and waits for the requests in flight, at most a
// few seconds.
func (t *tunnel) stop() {
	t.mu.Lock()
	cancel, done := t.cancel, t.done
	t.cancel = nil
	t.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
	t.set(stOff, "")
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

func (t *tunnel) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	wait := time.Second
	for {
		t.set(stConnecting, "")
		up, err := t.serve(ctx)
		if ctx.Err() != nil {
			return
		}
		if up {
			wait = time.Second
		}
		t.set(stRetry, err.Error())
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
func (t *tunnel) serve(ctx context.Context) (up bool, err error) {
	client, err := dialSSH(ctx, t.conf.Host)
	if err != nil {
		return false, err
	}
	defer func() { _ = client.Close() }()

	ln, err := client.Listen("tcp", net.JoinHostPort("127.0.0.1", t.conf.RemotePort))
	if err != nil {
		return false, fmt.Errorf("remote listen %s: %w", t.conf.RemotePort, err)
	}
	t.set(stUp, "")

	// ReadHeaderTimeout bounds a client that opens a connection and dribbles
	// headers forever (Slowloris): the far end of the tunnel is a port open
	// on the VPS.
	server := &http.Server{Handler: t.handler, ReadHeaderTimeout: 10 * time.Second}
	served := make(chan struct{})
	// #nosec G118 -- ctx is already cancelled when the drain runs; it needs
	// a deadline of its own.
	go func() {
		tick := time.NewTicker(keepAliveEvery)
		defer tick.Stop()
		for {
			select {
			case <-served:
				return
			case <-ctx.Done():
				sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = server.Shutdown(sctx)
				cancel()
				return
			case <-tick.C:
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					_ = client.Close()
					return
				}
			}
		}
	}()
	err = server.Serve(ln)
	close(served)
	if errors.Is(err, http.ErrServerClosed) {
		return true, nil
	}
	return true, fmt.Errorf("session lost: %w", err)
}

// session owns the tunnels of one devmux process and publishes their state
// in its status file.
type session struct {
	mode    string
	config  string
	started time.Time
	tunnels []*tunnel
	rec     *recorder
	wake    chan struct{}
	pubMu   sync.Mutex             // one status write at a time: they share the temp file
	warning atomic.Pointer[string] // the screen's next note; run prints instead
}

func newSession(mode, config string, confs []tunnelConf, echo bool) *session {
	s := &session{mode: mode, config: config, started: time.Now(), wake: make(chan struct{}, 1)}
	s.rec = &recorder{dir: logsDir(), wake: s.notify, fail: s.warn}
	for _, c := range confs {
		s.tunnels = append(s.tunnels, newTunnel(c, s.rec, s.changed))
	}
	s.rec.echo = echo
	return s
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
	var wg sync.WaitGroup
	for _, t := range s.tunnels {
		wg.Go(t.stop)
	}
	wg.Wait()
	removeStatus()
}
