package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/crgimenes/filo-term-go/kit"
	"github.com/crgimenes/filo-term-go/screen"
)

// view is one screen. It draws inside the frame and says which keys work
// there; the app owns the last two rows (legend and note).
type view interface {
	title() string
	hints() []kit.Hint
	draw(a *app, c *screen.Canvas, top, left, rows, cols int)
	key(a *app, k screen.Key)
}

type app struct {
	t     *screen.Terminal
	c     *screen.Canvas
	s     *session
	views []view
	quit  bool
	note  string
	tone  kit.Tone
}

const (
	minW = 40
	minH = 12
)

func (a *app) push(v view) { a.views = append(a.views, v) }

func (a *app) pop() {
	a.views = a.views[:len(a.views)-1]
	a.quit = len(a.views) == 0
}

func (a *app) say(tone kit.Tone, format string, args ...any) {
	a.tone = tone
	a.note = fmt.Sprintf(format, args...)
}

func cmdScreen(config string) int {
	confs, ok := loadOrWarn(config)
	if !ok {
		return 2
	}
	t, err := screen.Open()
	if errors.Is(err, screen.ErrNotTerminal) {
		warnf("the screen needs a terminal; devmux run serves the tunnels without one")
		return 2
	}
	if err != nil {
		warnf("%v", err)
		return 1
	}
	defer func() { _ = t.Close() }() // a panic must not leave the shell raw
	s := newSession("screen", configFile(config), confs, false)
	a := &app{t: t, c: screen.New(t.Size()), s: s}
	go s.watchConfig()
	a.push(&tunnelsView{})

	// kill or a closed window would otherwise leave the shell in raw mode
	// on the alternate screen, and the tunnels open.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGHUP, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		got := <-sig
		_ = t.Close()
		s.close()
		warnf("%v", got)
		os.Exit(1)
	}()

	a.run()
	a.say(kit.Wait, "closing tunnels")
	a.paint()
	s.close()
	_ = t.Close()
	return 0
}

func (a *app) run() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	events := a.t.Events()
	for !a.quit {
		a.paint()
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			if !ev.Resize {
				a.handle(ev.Key)
			}
		case <-a.s.wake:
		case <-tick.C:
			kit.Spin++
		}
	}
}

func (a *app) handle(k screen.Key) {
	if k == screen.Ctrl('c') {
		a.quit = true
		return
	}
	if len(a.views) == 0 {
		return
	}
	a.note = ""
	a.views[len(a.views)-1].key(a, k)
}

func (a *app) paint() {
	w, h := a.t.Size()
	a.c.Resize(w, h)
	a.c.Clear()
	if w < minW || h < minH {
		msg := fmt.Sprintf("devmux needs %dx%d, this is %dx%d", minW, minH, w, h)
		a.c.Print(h/2, max(0, (w-screen.Width(msg))/2), msg, screen.Pen{FG: kit.CWarn, BG: screen.Default})
		_ = a.t.Draw(a.c)
		return
	}
	warning := a.s.warning.Swap(nil)
	if warning != nil {
		a.say(kit.Warn, "%s", *warning)
	}
	a.drawOn(a.c, w, h)
	_ = a.t.Draw(a.c)
}

// drawOn paints the top view on c; apart from paint so tests draw without
// a terminal.
func (a *app) drawOn(c *screen.Canvas, w, h int) {
	if len(a.views) == 0 {
		kit.Note(c, h-1, 1, w-2, a.tone, a.note) // quitting
		return
	}
	v := a.views[len(a.views)-1]
	kit.Frame(c, 0, 0, h-2, w, v.title())
	v.draw(a, c, 1, 2, h-4, w-4)
	kit.Legend(c, h-2, 1, w-2, v.hints()...)
	kit.Note(c, h-1, 1, w-2, a.tone, a.note)
}

// age is how long ago, in the unit that reads best.
func age(since time.Time) string {
	d := time.Since(since)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func stateText(st tunnelStatus) (string, screen.Pen) {
	switch st.State {
	case stUp:
		return "up " + age(st.Since), screen.Pen{FG: kit.COK, BG: screen.Default}
	case stConnecting:
		return "connecting", kit.Soft
	case stRetry:
		return fmt.Sprintf("retry %d: %s", st.Retries, st.Error), screen.Pen{FG: kit.CErr, BG: screen.Default}
	}
	return "off", kit.Dim
}

type tunnelsView struct {
	tab kit.Table
}

func (v *tunnelsView) title() string { return "devmux · tunnels" }

func (v *tunnelsView) hints() []kit.Hint {
	return []kit.Hint{{Key: "space", What: "on/off"}, {Key: "enter", What: "routes"}, {Key: "r", What: "requests"}, {Key: "q", What: "quit"}}
}

func (v *tunnelsView) draw(a *app, c *screen.Canvas, top, left, rows, cols int) {
	ts := a.s.tunnels
	cells := make([][]string, len(ts))
	pens := make([]screen.Pen, len(ts))
	for i, t := range ts {
		st := t.status()
		text, pen := stateText(st)
		cells[i] = []string{st.Name, st.Host + ":" + st.RemotePort, routesText(t.routes(), st.Off), text}
		pens[i] = pen
	}
	tcols := fitCols([]kit.Col{{Header: "tunnel", Width: 16}, {Header: "remote", Width: 28}, {Header: "routes"}, {Header: "state", Width: 28}}, cells, 2, cols)
	v.tab.Draw(c, top, left, tcols, len(ts), func(i int) []string { return cells[i] }, rows-2)
	// the state column in its own colour, unless the row is under the cursor
	at := left
	for _, col := range tcols[:3] {
		at += col.Width + 1
	}
	if len(ts) > rows-2 {
		return // scrolled: the table alone knows which row is where
	}
	for i := range ts {
		if i != v.tab.Cursor {
			c.Print(top+2+i, at, kit.Cut(cells[i][3], tcols[3].Width), pens[i])
		}
	}
}

// fitCols narrows each column but fill to its widest cell (header
// included, Width as the ceiling) and gives fill what the line has left, so
// the table spans the screen.
func fitCols(cols []kit.Col, cells [][]string, fill, inner int) []kit.Col {
	out := slices.Clone(cols)
	used := len(out) - 1 // the gaps
	for j := range out {
		if j == fill {
			continue
		}
		w := screen.Width(out[j].Header)
		for _, row := range cells {
			w = max(w, screen.Width(row[j]))
		}
		out[j].Width = min(w, out[j].Width)
		used += out[j].Width
	}
	out[fill].Width = max(4, inner-used)
	return out
}

func routesText(routes []route, off []string) string {
	var parts []string
	for _, r := range routes {
		var p strings.Builder
		p.WriteString(r.Prefix + "→" + r.Port)
		for _, o := range off {
			if o == r.Prefix {
				p.WriteString(" (off)")
			}
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, " ")
}

func (v *tunnelsView) key(a *app, k screen.Key) {
	ts := a.s.tunnels
	if v.tab.Move(k, len(ts), 5) {
		return
	}
	if len(ts) == 0 {
		if k == 'q' || k == screen.KeyEsc {
			a.pop()
		}
		return
	}
	t := ts[v.tab.Cursor]
	switch k {
	case ' ':
		if t.running() {
			a.say(kit.Plain, "closing %s", t.conf.Name)
			go t.stop()
			return
		}
		t.start()
	case screen.KeyEnter:
		a.push(&routesView{t: t})
	case 'r':
		a.push(&requestsView{})
	case 'q', screen.KeyEsc:
		a.pop()
	}
}

// routesView lists one tunnel's routes, each one switchable, with whether
// something listens on its local port.
type routesView struct {
	t        *tunnel
	tab      kit.Table
	deleting string // the prefix asked about; the next key answers

	mu      sync.Mutex
	probed  time.Time
	probing bool
	open    map[string]bool
}

func (v *routesView) title() string { return "devmux · " + v.t.conf.Name + " · routes" }

func (v *routesView) hints() []kit.Hint {
	return []kit.Hint{{Key: "space", What: "on/off"}, {Key: "a", What: "add"}, {Key: "e", What: "edit"}, {Key: "d", What: "delete"}, {Key: "r", What: "requests"}, {Key: "esc", What: "back"}}
}

// probe dials each local port off the event loop, at most every 2 s.
func (v *routesView) probe(wake func()) {
	v.mu.Lock()
	if v.probing || time.Since(v.probed) < 2*time.Second {
		v.mu.Unlock()
		return
	}
	v.probing = true
	v.mu.Unlock()
	go func() {
		open := map[string]bool{}
		for _, r := range v.t.routes() {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", r.Port), 300*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				open[r.Port] = true
			}
		}
		v.mu.Lock()
		v.open, v.probed, v.probing = open, time.Now(), false
		v.mu.Unlock()
		wake()
	}()
}

func (v *routesView) draw(a *app, c *screen.Canvas, top, left, rows, cols int) {
	v.probe(a.s.notify)
	st := v.t.status()
	text, pen := stateText(st)
	n := c.Print(top, left, st.Host+":"+st.RemotePort+"  ", kit.Soft)
	c.Print(top, left+n, kit.Cut(text, cols-n), pen)

	v.mu.Lock()
	open, probed := v.open, !v.probed.IsZero()
	v.mu.Unlock()
	routes := v.t.routes()
	tcols := kit.FillCols([]kit.Col{{Header: "prefix", Width: 16}, {Header: "local", Width: 16}, {Header: "route", Width: 6}, {Header: "listening"}}, cols)
	v.tab.Draw(c, top+2, left, tcols, len(routes), func(i int) []string {
		r := routes[i]
		on := "on"
		if !v.t.routeOn(r.Prefix) {
			on = "off"
		}
		listening := "…"
		if probed {
			listening = "no"
			if open[r.Port] {
				listening = "yes"
			}
		}
		return []string{"/" + r.Prefix, "127.0.0.1:" + r.Port, on, listening}
	}, rows-4)
}

func (v *routesView) key(a *app, k screen.Key) {
	routes := v.t.routes()
	if v.deleting != "" {
		prefix := v.deleting
		v.deleting = ""
		if k != 'y' {
			a.say(kit.Plain, "kept /%s", prefix)
			return
		}
		rest := slices.DeleteFunc(routes, func(r route) bool { return r.Prefix == prefix })
		err := a.s.saveRoutes(v.t, rest, "", "")
		if err != nil {
			a.say(kit.Err, "%v", err)
			return
		}
		a.say(kit.OK, "deleted /%s", prefix)
		return
	}
	if v.tab.Move(k, len(routes), 5) {
		return
	}
	var cur *route
	if len(routes) > 0 {
		cur = &routes[min(v.tab.Cursor, len(routes)-1)]
	}
	switch k {
	case ' ':
		if cur != nil {
			v.t.toggleRoute(cur.Prefix)
		}
	case 'a':
		a.push(newRouteForm(v.t, nil))
	case 'e', screen.KeyEnter:
		if cur != nil {
			a.push(newRouteForm(v.t, cur))
		}
	case 'd', screen.KeyDel:
		if cur != nil {
			v.deleting = cur.Prefix
			a.say(kit.Warn, "delete /%s → %s from the config? y deletes, any other key keeps it", cur.Prefix, cur.Port)
		}
	case 'r':
		a.push(&requestsView{tunnel: v.t.conf.Name})
	case 'q', screen.KeyEsc:
		a.pop()
	}
}

// requestsView is the inspector: what arrived, newest first, live.
type requestsView struct {
	tunnel string
	tab    kit.Table
	at     string // the ID under the cursor, so new requests do not move it
	shown  []exchange
}

func (v *requestsView) title() string {
	if v.tunnel == "" {
		return "devmux · requests"
	}
	return "devmux · " + v.tunnel + " · requests"
}

func (v *requestsView) hints() []kit.Hint {
	return []kit.Hint{{Key: "enter", What: "detail"}, {Key: "esc", What: "back"}}
}

// refresh takes what arrived since and keeps the cursor on its request.
func (v *requestsView) refresh(a *app) {
	v.shown = a.s.rec.list(v.tunnel)
	// the request under the cursor may have left the ring
	v.tab.Cursor = max(0, min(v.tab.Cursor, len(v.shown)-1))
	for i, ex := range v.shown {
		if ex.ID == v.at {
			v.tab.Cursor = i
		}
	}
}

func (v *requestsView) draw(a *app, c *screen.Canvas, top, left, rows, cols int) {
	v.refresh(a)
	if len(v.shown) == 0 {
		c.Print(top, left, "no requests yet", kit.Dim)
		return
	}
	tcols := kit.FillCols([]kit.Col{{Header: "time", Width: 8}, {Header: "tunnel", Width: 10}, {Header: "method", Width: 7}, {Header: "status", Width: 6}, {Header: "ms", Width: 8}, {Header: "url"}}, cols)
	v.tab.Draw(c, top, left, tcols, len(v.shown), func(i int) []string {
		ex := v.shown[i]
		return []string{ex.Time.Format("15:04:05"), ex.Tunnel, printable(ex.Method), fmt.Sprint(ex.Status), fmt.Sprintf("%.1f", ex.MS), printable(ex.URL)}
	}, rows-2)
	v.at = v.shown[v.tab.Cursor].ID
}

func (v *requestsView) key(a *app, k screen.Key) {
	v.refresh(a)
	if v.tab.Move(k, len(v.shown), 10) {
		if len(v.shown) > 0 {
			v.at = v.shown[max(0, min(v.tab.Cursor, len(v.shown)-1))].ID
		}
		return
	}
	switch k {
	case screen.KeyEnter:
		if len(v.shown) > 0 {
			ex := v.shown[v.tab.Cursor]
			a.push(&detailView{ex: ex, lines: strings.Split(strings.TrimRight(formatExchange(ex, false), "\n"), "\n")})
		}
	case 'q', screen.KeyEsc:
		a.pop()
	}
}

// detailView is one exchange as text, wrapped to the width and scrolled.
type detailView struct {
	ex    exchange
	lines []string
	first int
	page  int
	total int
}

func (v *detailView) title() string { return "devmux · request " + v.ex.ID }

func (v *detailView) hints() []kit.Hint {
	return []kit.Hint{{Key: "↑↓ pgup pgdn", What: "scroll"}, {Key: "esc", What: "back"}}
}

func (v *detailView) draw(_ *app, c *screen.Canvas, top, left, rows, cols int) {
	var wrapped []string
	for _, l := range v.lines {
		wrapped = append(wrapped, wrap(l, cols)...)
	}
	v.page, v.total = rows, len(wrapped)
	v.first = max(0, min(v.first, len(wrapped)-rows))
	for i := 0; i < rows && v.first+i < len(wrapped); i++ {
		l := wrapped[v.first+i]
		pen := kit.Text
		if strings.HasPrefix(l, ">>") || strings.HasPrefix(l, "<<") {
			pen = kit.Soft
		}
		c.Print(top+i, left, l, pen)
	}
}

// wrap cuts s into pieces of at most width columns.
func wrap(s string, width int) []string {
	s = strings.ReplaceAll(s, "\t", "    ")
	if width < 1 || screen.Width(s) <= width {
		return []string{s}
	}
	var out []string
	var line strings.Builder
	w := 0
	for _, r := range s {
		rw := screen.RuneWidth(r)
		if w+rw > width {
			out = append(out, line.String())
			line.Reset()
			w = 0
		}
		line.WriteRune(r)
		w += rw
	}
	return append(out, line.String())
}

func (v *detailView) key(a *app, k screen.Key) {
	switch k {
	case screen.KeyUp, 'k':
		v.first--
	case screen.KeyDown, 'j':
		v.first++
	case screen.KeyPgUp:
		v.first -= v.page
	case screen.KeyPgDn, ' ':
		v.first += v.page
	case screen.KeyHome:
		v.first = 0
	case screen.KeyEnd:
		v.first = v.total
	case 'q', screen.KeyEsc:
		a.pop()
	}
	v.first = max(0, v.first)
}

// routeForm adds a route to a tunnel or edits one; Save writes the config
// file and hands the routes to the running tunnel.
type routeForm struct {
	t    *tunnel
	was  *route // nil adds
	form *kit.Form
}

const (
	fieldPrefix = iota
	fieldPort
)

func newRouteForm(t *tunnel, r *route) *routeForm {
	f := &routeForm{t: t}
	prefix, port := "", ""
	if r != nil {
		was := *r
		f.was = &was
		prefix, port = r.Prefix, r.Port
	}
	f.form = kit.NewForm([]kit.Field{
		{Kind: kit.TextField, Label: "prefix", Width: 32, Max: 200, Value: prefix},
		{Kind: kit.TextField, Label: "port", Width: 7, Max: 5, Value: port},
	}, "Save", "Cancel")
	return f
}

func (f *routeForm) title() string {
	if f.was == nil {
		return "devmux · " + f.t.conf.Name + " · new route"
	}
	return "devmux · " + f.t.conf.Name + " · route /" + f.was.Prefix
}

func (f *routeForm) hints() []kit.Hint {
	return []kit.Hint{{Key: "↑↓", What: "field"}, {Key: "ctrl-w", What: "save"}, {Key: "esc", What: "cancel"}}
}

func (f *routeForm) draw(_ *app, c *screen.Canvas, top, left, _, _ int) {
	c.Print(top, left, "/PREFIX/... goes to 127.0.0.1:PORT/..., the prefix stripped; the longest prefix wins.", kit.Dim)
	f.form.Draw(c, top+2, left, 6)
}

func (f *routeForm) key(a *app, k screen.Key) {
	switch f.form.Key(k) {
	case "save":
		f.save(a)
	case kit.Cancel: // ESC, or the Cancel button
		a.pop()
	}
}

func (f *routeForm) save(a *app) {
	prefix := strings.Trim(strings.TrimSpace(f.form.Value(fieldPrefix)), "/")
	port := strings.TrimSpace(f.form.Value(fieldPort))
	err := checkPrefix(prefix)
	if err != nil {
		f.form.Fail(fieldPrefix, err.Error())
		return
	}
	if checkPort(port) != nil {
		f.form.Fail(fieldPort, "a port is 1 to 65535")
		return
	}

	routes := f.t.routes()
	from := ""
	if f.was != nil {
		from = f.was.Prefix
	}
	for _, r := range routes {
		if r.Prefix == prefix && r.Prefix != from {
			f.form.Fail(fieldPrefix, "/"+prefix+" is already a route")
			return
		}
	}
	nr := route{Prefix: prefix, Port: port}
	i := slices.IndexFunc(routes, func(r route) bool { return f.was != nil && r.Prefix == from })
	if i < 0 {
		routes = append(routes, nr)
	} else {
		routes[i] = nr
	}

	err = a.s.saveRoutes(f.t, routes, from, prefix)
	if err != nil {
		f.form.Note = err.Error()
		return
	}
	a.pop()
	a.say(kit.OK, "saved /%s → %s", prefix, port)
}
