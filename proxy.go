package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

// maxLoggedBody caps what is kept of each body for the log; the proxied
// stream itself is never truncated.
const maxLoggedBody = 64 << 10

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
	body       bytes.Buffer
	truncated  bool
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

func (lw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lw.ResponseWriter.Write(b)
	lw.size += n
	keep := min(n, maxLoggedBody-lw.body.Len())
	lw.truncated = lw.truncated || keep < n
	lw.body.Write(b[:keep])
	return n, err
}

// Hijack is how ReverseProxy switches protocols (WebSocket); it then writes
// the 101 on the taken-over connection, past WriteHeader, so it is noted
// here.
func (lw *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := http.NewResponseController(lw.ResponseWriter).Hijack()
	if err == nil {
		lw.statusCode = http.StatusSwitchingProtocols
	}
	return c, brw, err
}

// Unwrap lets ReverseProxy reach Flush and Hijack through the wrapper;
// streaming responses and WebSocket upgrades fail without it.
func (lw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lw.ResponseWriter
}

// bodyTap keeps the first maxLoggedBody bytes of the request body as the
// proxy reads them, so nothing is held back from the backend. The
// transport may still be reading when the handler returns: mu.
type bodyTap struct {
	io.ReadCloser
	mu        sync.Mutex
	kept      bytes.Buffer
	truncated bool
	err       error
}

func (b *bodyTap) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	keep := min(n, maxLoggedBody-b.kept.Len())
	b.truncated = b.truncated || keep < n
	b.kept.Write(p[:keep])
	if err != nil && !errors.Is(err, io.EOF) {
		b.err = err
	}
	b.mu.Unlock()
	return n, err
}

func (b *bodyTap) result() (body []byte, truncated bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.kept.Bytes()), b.truncated, b.err
}

// newRouter builds one reverse proxy per route. A request goes to the route
// with the longest matching path prefix, with that prefix stripped; on says
// whether a route is switched on.
func newRouter(c tunnelConf, on func(prefix string) bool, rec *recorder) http.Handler {
	proxies := make(map[string]http.Handler, len(c.Routes))
	depth := 0 // segments in the deepest prefix: no longer candidate can match
	for _, rt := range c.Routes {
		depth = max(depth, strings.Count(rt.Prefix, "/")+1)
		target := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", rt.Port)}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorLog = log.New(io.Discard, "", 0)
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "devmux: "+err.Error(), http.StatusBadGateway)
		}
		proxies[rt.Prefix] = recording(c.Name, rt.Prefix, target.String(), proxy, rec)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seg := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", depth+1)
		for i := min(len(seg), depth); i > 0; i-- {
			prefix := strings.Join(seg[:i], "/")
			h, ok := proxies[prefix]
			if !ok {
				continue
			}
			if !on(prefix) {
				refuse(w, r, c.Name, prefix, http.StatusServiceUnavailable, "route is off", rec)
				return
			}
			h.ServeHTTP(w, r)
			return
		}
		refuse(w, r, c.Name, "", http.StatusNotFound, "no route", rec)
	})
}

func refuse(w http.ResponseWriter, r *http.Request, tunnel, prefix string, status int, why string, rec *recorder) {
	http.Error(w, "devmux: "+why, status)
	rec.add(exchange{
		Time:      time.Now(),
		Tunnel:    tunnel,
		Route:     prefix,
		Method:    r.Method,
		Host:      r.Host,
		URL:       r.URL.String(),
		ReqHeader: r.Header,
		Status:    status,
		Note:      why,
	})
}

// recording proxies to next and hands the whole exchange to rec. URL is
// what arrived, before the route's prefix is stripped.
func recording(tunnel, prefix, target string, next http.Handler, rec *recorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ex := exchange{
			Time:      time.Now(),
			Tunnel:    tunnel,
			Route:     prefix,
			Target:    target,
			Method:    r.Method,
			Host:      r.Host,
			URL:       r.URL.String(),
			ReqHeader: r.Header.Clone(),
		}
		tap := &bodyTap{ReadCloser: r.Body}
		r.Body = tap
		stripPrefix(r.URL, prefix)
		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// ReverseProxy panics with http.ErrAbortHandler when the response
		// breaks halfway; the request still reached the backend, so it is
		// recorded before the panic goes on.
		defer func() {
			p := recover()
			ex.MS = float64(time.Since(ex.Time).Microseconds()) / 1000
			ex.Status, ex.Size = lw.statusCode, lw.size
			ex.RespHeader = lw.Header().Clone()
			ex.RespBody, ex.RespTruncated = bytes.Clone(lw.body.Bytes()), lw.truncated
			var notes []string
			body, truncated, err := tap.result()
			ex.ReqBody, ex.ReqTruncated = body, truncated
			if err != nil {
				notes = append(notes, "reading the request body: "+err.Error())
			}
			if p != nil {
				notes = append(notes, "response cut short")
			}
			ex.Note = strings.Join(notes, "; ")
			rec.add(ex)
			if p != nil {
				panic(p)
			}
		}()
		next.ServeHTTP(lw, r)
	})
}

// stripPrefix takes "/"+prefix off the path. The escaped form is cut too, so
// a %2F the client sent reaches the backend as %2F, not as a separator.
func stripPrefix(u *url.URL, prefix string) {
	raw := u.RawPath
	u.Path = withSlash(strings.TrimPrefix(u.Path, "/"+prefix))
	u.RawPath = ""
	rest, ok := strings.CutPrefix(raw, "/"+prefix)
	if raw != "" && ok {
		u.RawPath = withSlash(rest) // url.URL drops it if it stops matching Path
	}
}

func withSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func formatBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return "[Empty body]"
	}

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		formValues, err := url.ParseQuery(string(body))
		if err == nil {
			var sb strings.Builder
			sb.WriteString("[Form data]")
			for _, key := range slices.Sorted(maps.Keys(formValues)) {
				fmt.Fprintf(&sb, "\n%s: %s", key, strings.Join(formValues[key], ", "))
			}
			return sb.String()
		}
	}

	if strings.Contains(contentType, "multipart/form-data") {
		return fmt.Sprintf("[Multipart form - Size: %d bytes]", len(body))
	}

	if strings.Contains(contentType, "json") {
		var out bytes.Buffer
		err := json.Indent(&out, body, "", "  ")
		if err == nil {
			return out.String()
		}
		return string(body)
	}

	if strings.Contains(contentType, "text") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "html") {
		return string(body)
	}

	return fmt.Sprintf("[Binary content - Content-Type: %s - Size: %d bytes]", contentType, len(body))
}

// formatExchange is the request and its response as text: what the TUI
// detail, `devmux request` and `devmux run` show. color is for a terminal.
func formatExchange(ex exchange, color bool) string {
	in, out, warn, reset := "", "", "", ""
	if color {
		in, out, warn, reset = colorGreen, colorYellow, colorRed, colorReset
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s>> %s %s%s%s\n", in, printable(ex.Method), printable(ex.Host), printable(ex.URL), reset)
	fmt.Fprintf(&sb, "%s>> Tunnel:%s %s  %sRoute:%s %s → %s  %sTime:%s %s  %sID:%s %s\n",
		in, reset, ex.Tunnel, in, reset, ex.Route, ex.Target,
		in, reset, ex.Time.Format("2006-01-02 15:04:05.000"), in, reset, ex.ID)
	writeHeaders(&sb, ">>", ex.ReqHeader)
	writeBody(&sb, ">>", ex.ReqBody, ex.ReqTruncated, ex.ReqHeader.Get("Content-Type"))

	fmt.Fprintf(&sb, "%s<< %d %s%s  %d bytes  %.1f ms\n", out, ex.Status, http.StatusText(ex.Status), reset, ex.Size, ex.MS)
	if ex.Note != "" {
		fmt.Fprintf(&sb, "%s!! %s%s\n", warn, printable(ex.Note), reset)
	}
	writeHeaders(&sb, "<<", ex.RespHeader)
	writeBody(&sb, "<<", ex.RespBody, ex.RespTruncated, ex.RespHeader.Get("Content-Type"))
	return sb.String()
}

func writeHeaders(sb *strings.Builder, prefix string, h http.Header) {
	for _, key := range slices.Sorted(maps.Keys(h)) {
		fmt.Fprintf(sb, "%s   %s: %s\n", prefix, printable(key), printable(strings.Join(h[key], ", ")))
	}
}

func writeBody(sb *strings.Builder, prefix string, body []byte, truncated bool, contentType string) {
	if len(body) == 0 {
		return
	}
	sb.WriteString(prefix + "\n")
	sb.WriteString(printable(formatBody(body, contentType)))
	if truncated {
		fmt.Fprintf(sb, "\n[... cut at %d bytes]", maxLoggedBody)
	}
	sb.WriteString("\n")
}

// printable shows the control characters in s (ESC, BEL, C1...) as escapes,
// keeping newlines and tabs: what an HTTP client sent must not drive the
// terminal that prints it (clear the screen, forge lines, OSC 52 clipboard).
func printable(s string) string {
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	var sb strings.Builder
	for _, r := range s {
		if isControl(r) {
			fmt.Fprintf(&sb, "\\x%02x", r)
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func isControl(r rune) bool {
	return r != '\n' && r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f))
}
