// devmux.go – rota "/ip/*" → localhost:8001, "/dump/*" → 8080…
package main

import (
	"net/http"
	"net/http/httputil"
	"strings"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(segments) == 0 {
			http.NotFound(w, r)
			return
		}
		var target string
		switch segments[0] {
		case "ip":
			target = "http://127.0.0.1:8001"
		case "dump":
			target = "http://127.0.0.1:8080"
		case "bbs":
			target = "http://127.0.0.1:2200"
		default:
			http.NotFound(w, r)
			return
		}
		// strip first segment and proxy
		r.URL.Path = "/" + strings.Join(segments[1:], "/")
		rp := httputil.ReverseProxy{Director: func(req *http.Request) {
			req.URL.Scheme, req.URL.Host = "http", target[7:]
		}}
		rp.ServeHTTP(w, r)
	})
	http.ListenAndServe(":10000", mux)
}
