package main

import (
	"bytes"
	"encoding/json"
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

// Unwrap lets ReverseProxy reach Flush and Hijack through the wrapper;
// streaming responses and WebSocket upgrades fail without it.
func (lw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lw.ResponseWriter
}

// captureRequestBody reads up to maxLoggedBody for the log and puts what it
// read back in front of the rest, so the backend still receives the whole
// body.
func captureRequestBody(r *http.Request) (body []byte, truncated bool, err error) {
	head, err := io.ReadAll(io.LimitReader(r.Body, maxLoggedBody+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	if err != nil {
		return nil, false, err
	}
	if len(head) > maxLoggedBody {
		return head[:maxLoggedBody], true, nil
	}
	return head, false, nil
}

// newRouter builds one reverse proxy per route. A request goes to the route
// with the longest matching path prefix, with that prefix stripped; on says
// whether a route is switched on.
func newRouter(c tunnelConf, on func(prefix string) bool, rec *recorder) http.Handler {
	proxies := make(map[string]http.Handler, len(c.Routes))
	for _, rt := range c.Routes {
		target := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", rt.Port)}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorLog = log.New(io.Discard, "", 0)
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "devmux: "+err.Error(), http.StatusBadGateway)
		}
		proxies[rt.Prefix] = recording(c.Name, rt.Prefix, target.String(), proxy, rec)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seg := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		for i := len(seg); i > 0; i-- {
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
		body, truncated, err := captureRequestBody(r)
		ex.ReqBody, ex.ReqTruncated = body, truncated
		if err != nil {
			ex.Note = "reading the request body: " + err.Error()
		}

		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/"+prefix)
		if !strings.HasPrefix(r.URL.Path, "/") {
			r.URL.Path = "/" + r.URL.Path
		}
		r.URL.RawPath = ""

		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lw, r)

		ex.MS = float64(time.Since(ex.Time).Microseconds()) / 1000
		ex.Status, ex.Size = lw.statusCode, lw.size
		ex.RespHeader = lw.Header().Clone()
		ex.RespBody, ex.RespTruncated = lw.body.Bytes(), lw.truncated
		rec.add(ex)
	})
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
	fmt.Fprintf(&sb, "%s>> %s %s%s%s\n", in, ex.Method, ex.Host, ex.URL, reset)
	fmt.Fprintf(&sb, "%s>> Tunnel:%s %s  %sRoute:%s %s → %s  %sTime:%s %s  %sID:%s %s\n",
		in, reset, ex.Tunnel, in, reset, ex.Route, ex.Target,
		in, reset, ex.Time.Format("2006-01-02 15:04:05.000"), in, reset, ex.ID)
	writeHeaders(&sb, ">>", ex.ReqHeader)
	writeBody(&sb, ">>", ex.ReqBody, ex.ReqTruncated, ex.ReqHeader.Get("Content-Type"))

	fmt.Fprintf(&sb, "%s<< %d %s%s  %d bytes  %.1f ms\n", out, ex.Status, http.StatusText(ex.Status), reset, ex.Size, ex.MS)
	if ex.Note != "" {
		fmt.Fprintf(&sb, "%s!! %s%s\n", warn, ex.Note, reset)
	}
	writeHeaders(&sb, "<<", ex.RespHeader)
	writeBody(&sb, "<<", ex.RespBody, ex.RespTruncated, ex.RespHeader.Get("Content-Type"))
	return sb.String()
}

func writeHeaders(sb *strings.Builder, prefix string, h http.Header) {
	for _, key := range slices.Sorted(maps.Keys(h)) {
		fmt.Fprintf(sb, "%s   %s: %s\n", prefix, key, strings.Join(h[key], ", "))
	}
}

func writeBody(sb *strings.Builder, prefix string, body []byte, truncated bool, contentType string) {
	if len(body) == 0 {
		return
	}
	sb.WriteString(prefix + "\n")
	sb.WriteString(formatBody(body, contentType))
	if truncated {
		fmt.Fprintf(sb, "\n[... cut at %d bytes]", maxLoggedBody)
	}
	sb.WriteString("\n")
}
