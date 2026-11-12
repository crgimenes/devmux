package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// exchange is one request and its response, as the TUI, the log files and
// `devmux requests` see it.
type exchange struct {
	ID            string      `json:"id"`
	Time          time.Time   `json:"time"`
	Tunnel        string      `json:"tunnel"`
	Route         string      `json:"route,omitempty"`
	Target        string      `json:"target,omitempty"`
	Method        string      `json:"method"`
	Host          string      `json:"host"`
	URL           string      `json:"url"`
	ReqHeader     http.Header `json:"request_headers"`
	ReqBody       payload     `json:"request_body,omitzero"`
	ReqTruncated  bool        `json:"request_truncated,omitempty"`
	Status        int         `json:"status"`
	Size          int         `json:"size"`
	MS            float64     `json:"ms"`
	RespHeader    http.Header `json:"response_headers"`
	RespBody      payload     `json:"response_body,omitzero"`
	RespTruncated bool        `json:"response_truncated,omitempty"`
	Note          string      `json:"note,omitempty"`
}

// payload is a body in JSON: a string when it is UTF-8 text, else
// {"base64": "..."}, so an agent reads a webhook's JSON as it came.
type payload []byte

func (p payload) MarshalJSON() ([]byte, error) {
	if utf8.Valid(p) {
		return json.Marshal(string(p))
	}
	return json.Marshal(map[string]string{"base64": base64.StdEncoding.EncodeToString(p)})
}

func (p *payload) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err == nil {
		*p = payload(s)
		return nil
	}
	var m map[string]string
	err = json.Unmarshal(b, &m)
	if err != nil {
		return err
	}
	*p, err = base64.StdEncoding.DecodeString(m["base64"])
	return err
}

const ringMax = 500

// recorder keeps the last ringMax exchanges for the TUI and appends every
// one to dir/<tunnel>-<date>.jsonl for the CLI. echo prints each one on
// stdout (devmux run).
type recorder struct {
	dir  string
	echo bool
	wake func()
	fail func(error)

	mu   sync.Mutex
	ring []exchange
	last int64
	full map[string]bool // files past maxLogFile, reported once
}

// Whoever reaches the remote port writes these logs, so they are bounded:
// per tunnel and day, and in age.
const (
	maxLogFileDefault = 256 << 20
	logKeep           = 14 * 24 * time.Hour
)

var maxLogFile int64 = maxLogFileDefault // a var so a test can make it small

func (r *recorder) add(ex exchange) {
	r.mu.Lock()
	id := max(ex.Time.UnixNano(), r.last+1)
	r.last = id
	ex.ID = strconv.FormatInt(id, 36)
	r.ring = append(r.ring, ex)
	if len(r.ring) > ringMax {
		r.ring = slices.Delete(r.ring, 0, len(r.ring)-ringMax)
	}
	err := r.write(ex)
	r.mu.Unlock()

	if err != nil && r.fail != nil {
		r.fail(fmt.Errorf("log: %w", err))
	}
	if r.echo {
		fmt.Println(formatExchange(ex, true))
	}
	if r.wake != nil {
		r.wake()
	}
}

func (r *recorder) write(ex exchange) error {
	if r.dir == "" {
		return nil
	}
	err := os.MkdirAll(r.dir, 0700) // #nosec G703 -- devmux's state dir
	if err != nil {
		return err
	}
	b, err := json.Marshal(ex)
	if err != nil {
		return err
	}
	name := filepath.Join(r.dir, ex.Tunnel+"-"+ex.Time.Format(time.DateOnly)+".jsonl")
	// #nosec G304 G703 -- dir is devmux's state dir and the tunnel name comes
	// from the config, where check refuses a slash.
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil && info.Size() >= maxLogFile {
		_ = f.Close()
		if r.full[name] {
			return nil
		}
		if r.full == nil {
			r.full = map[string]bool{}
		}
		r.full[name] = true
		return fmt.Errorf("%s reached %d MiB; requests to %s are not logged until tomorrow", name, maxLogFile>>20, ex.Tunnel)
	}
	_, err = f.Write(append(b, '\n'))
	return errors.Join(err, f.Close())
}

// pruneLogs removes the logs older than logKeep.
func pruneLogs(dir string) error {
	files, err := logFiles(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, fi := range files {
		if time.Since(fi.ModTime()) > logKeep {
			errs = append(errs, os.Remove(filepath.Join(dir, fi.Name())))
		}
	}
	return errors.Join(errs...)
}

// list is the exchanges kept, newest first, of one tunnel or all ("").
func (r *recorder) list(tunnel string) []exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]exchange, 0, len(r.ring))
	for _, v := range slices.Backward(r.ring) {
		if tunnel == "" || v.Tunnel == tunnel {
			out = append(out, v)
		}
	}
	return out
}

func logsDir() string { return filepath.Join(stateHome(), "logs") }
func runDir() string  { return filepath.Join(stateHome(), "run") }

// logFiles are dir's .jsonl files, most recently written first: a file's
// time is never older than its newest line.
func logFiles(dir string) ([]os.FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var files []os.FileInfo
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, info)
	}
	slices.SortFunc(files, func(a, b os.FileInfo) int { return b.ModTime().Compare(a.ModTime()) })
	return files, nil
}

// readLog calls fn for each exchange in file, in the order written. A line
// that does not parse (cut by a crash) is skipped.
func readLog(file string, fn func(exchange) bool) error {
	f, err := os.Open(filepath.Clean(file))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		var ex exchange
		if json.Unmarshal(sc.Bytes(), &ex) != nil {
			continue
		}
		if !fn(ex) {
			return nil
		}
	}
	return sc.Err()
}

// recentExchanges is the newest n exchanges in dir, of one tunnel or all
// (""), newest first; n must be at least 1. It stops reading once the
// files left are all older than what it has.
func recentExchanges(dir, tunnel string, n int) ([]exchange, error) {
	files, err := logFiles(dir)
	if err != nil {
		return nil, err
	}
	var got []exchange
	for _, fi := range files {
		if len(got) >= n && fi.ModTime().Before(got[n-1].Time) {
			break
		}
		if tunnel != "" && !strings.HasPrefix(fi.Name(), tunnel+"-") {
			continue
		}
		// Lines go in as requests end, but Time is when they began: keep
		// the n newest by Time, holding at most 2n however big the file.
		err = readLog(filepath.Join(dir, fi.Name()), func(ex exchange) bool {
			if tunnel != "" && ex.Tunnel != tunnel {
				return true
			}
			got = append(got, ex)
			if len(got) >= 2*n {
				got = newest(got, n)
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		got = newest(got, n)
	}
	return got, nil
}

// newest is the n exchanges of es with the latest Time, newest first, in a
// slice of their own so the rest can be freed.
func newest(es []exchange, n int) []exchange {
	slices.SortFunc(es, func(a, b exchange) int { return b.Time.Compare(a.Time) })
	return slices.Clone(es[:min(len(es), n)])
}

func findExchange(dir, id string) (exchange, error) {
	files, err := logFiles(dir)
	if err != nil {
		return exchange{}, err
	}
	var found *exchange
	for _, fi := range files {
		err = readLog(filepath.Join(dir, fi.Name()), func(ex exchange) bool {
			if ex.ID == id {
				found = &ex
				return false
			}
			return true
		})
		if err != nil {
			return exchange{}, err
		}
		if found != nil {
			return *found, nil
		}
	}
	return exchange{}, fmt.Errorf("no request %s in %s", id, dir)
}

// processStatus is what one running devmux says about its tunnels, in
// run/<pid>.json; `devmux ls` reads it.
type processStatus struct {
	PID     int            `json:"pid"`
	Mode    string         `json:"mode"`
	Config  string         `json:"config"`
	Started time.Time      `json:"started"`
	Tunnels []tunnelStatus `json:"tunnels"`
}

func statusFile(pid int) string {
	return filepath.Join(runDir(), strconv.Itoa(pid)+".json")
}

func writeStatus(st processStatus) error {
	err := os.MkdirAll(runDir(), 0700)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	name := statusFile(st.PID)
	tmp := name + ".tmp"
	err = os.WriteFile(tmp, b, 0600)
	if err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// readStatuses is every live process's status. A file left by a process
// that died without cleaning up is removed.
func readStatuses() ([]processStatus, error) {
	entries, err := os.ReadDir(runDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []processStatus
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := filepath.Join(runDir(), e.Name())
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			continue
		}
		var st processStatus
		if json.Unmarshal(b, &st) != nil {
			continue
		}
		if !processAlive(st.PID) {
			_ = os.Remove(name)
			continue
		}
		out = append(out, st)
	}
	return out, nil
}
