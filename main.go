// devmux - create a reverse tunnel to a remote server and proxy requests to local ports.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/crgimenes/filo"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

// maxLoggedBody caps what is kept of each body for the log; the proxied
// stream itself is never truncated.
const maxLoggedBody = 64 << 10

var (
	host       = ""
	remotePort = "10000"
	routes     = map[string]string{}
)

var ansiStripper = strings.NewReplacer(
	colorReset, "",
	colorRed, "",
	colorGreen, "",
	colorYellow, "",
	colorBlue, "",
	colorCyan, "",
)

func fileExists(name string) bool {
	_, err := os.Stat(name)
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	panic(err)
}

func configHome() string {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome != "" {
		return configHome
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("Failed to get home directory:", err)
	}
	return filepath.Join(home, ".config")
}

func getInitFiloPath() string {
	return filepath.Join(configHome(), "devmux", "init.filo")
}

func runFiloFile(name string) {
	if !fileExists(name) {
		return
	}

	f := filo.New()
	defer f.Close()

	// Seed the globals with the current defaults so the config file can read
	// and selectively override them.
	f.SetGlobal("Host", host)
	f.SetGlobal("RemotePort", remotePort)
	f.SetGlobal("Routes", routes)

	b, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		log.Fatal(err)
	}

	err = f.DoString(string(b))
	if err != nil {
		log.Fatal(err)
	}

	host = f.MustGetString("Host")
	remotePort = f.MustGetString("RemotePort")
	routes = f.MustGetMap("Routes")
}

// sshTarget resolves alias through ~/.ssh/config the way ssh does: a missing
// file or a missing Hostname means the alias is the host itself.
func sshTarget(alias string) (addr, user, keyPath string) {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}

	// #nosec G304 -- the user's own ~/.ssh/config.
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("failed to read SSH config: %v", err)
	}
	cfg, err := ssh_config.DecodeBytes(b)
	if err != nil {
		log.Fatalf("failed to decode SSH config: %v", err)
	}

	hostname, _ := cfg.Get(alias, "Hostname")
	if hostname == "" {
		hostname = alias
	}
	port, _ := cfg.Get(alias, "Port")
	if port == "" {
		port = "22"
	}
	user, _ = cfg.Get(alias, "User")
	if user == "" {
		user = os.Getenv("USER")
	}
	identity, _ := cfg.Get(alias, "IdentityFile")
	keyPath = os.ExpandEnv(identity)
	rest, ok := strings.CutPrefix(keyPath, "~")
	if ok {
		keyPath = home + rest
	}

	return net.JoinHostPort(hostname, port), user, keyPath
}

func dialSSH(user, addr, sshKeyPath string) *ssh.Client {
	auth, err := agentAuth(sshKeyPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	hostKeyCallback, err := knownhosts.New(os.ExpandEnv("$HOME/.ssh/known_hosts"))
	if err != nil {
		log.Fatal("could not create hostkeycallback function: ", err)
	}

	cfg := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: knownHostAlgorithms(hostKeyCallback, addr),
		Timeout:           10 * time.Second,
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		log.Fatalf("ssh dial: %v", err)
	}
	return c
}

// knownHostAlgorithms lists the key types known_hosts holds for addr. Without
// it the server may present a type that is not recorded (ecdsa when only
// ed25519 is known) and knownhosts reports a mismatch where ssh would not.
func knownHostAlgorithms(cb ssh.HostKeyCallback, addr string) []string {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(cb(addr, &net.TCPAddr{}, probe), &keyErr) {
		return nil
	}

	var algos []string
	for _, k := range keyErr.Want {
		switch k.Key.Type() {
		case ssh.KeyAlgoRSA:
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		default:
			algos = append(algos, k.Key.Type())
		}
	}
	return algos
}

func agentAuth(sshKeyPath string) (ssh.AuthMethod, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock != "" {
		// #nosec G704 -- sock is the ssh-agent socket from the user's own
		// environment, not a network address taken from any request.
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
		}
	}

	if sshKeyPath == "" {
		return nil, errors.New("no ssh-agent and no IdentityFile for this host")
	}
	// #nosec G304 -- sshKeyPath is the user's own SSH key from ssh_config.
	key, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", sshKeyPath, err)
	}
	return ssh.PublicKeys(signer), nil
}

func keepAlive(c *ssh.Client, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			log.Printf("keep-alive failed: %v", err)
			return
		}
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
	body       bytes.Buffer
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

func (lw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lw.ResponseWriter.Write(b)
	lw.size += n
	lw.body.Write(b[:min(n, maxLoggedBody-lw.body.Len())])
	return n, err
}

// Unwrap lets ReverseProxy reach Flush and Hijack through the wrapper;
// streaming responses and WebSocket upgrades fail without it.
func (lw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lw.ResponseWriter
}

func formatBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return "[Empty body]"
	}

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		formValues, err := url.ParseQuery(string(body))
		if err == nil {
			var sb strings.Builder
			sb.WriteString("[Form data]\n")
			for _, key := range slices.Sorted(maps.Keys(formValues)) {
				fmt.Fprintf(&sb, ">>   %s: %s\n", key, strings.Join(formValues[key], ", "))
			}
			return sb.String()
		}
	}

	if strings.Contains(contentType, "multipart/form-data") {
		return fmt.Sprintf("[Multipart form - Size: %d bytes]\nContent-Type: %s",
			len(body), contentType)
	}

	if strings.Contains(contentType, "text") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "html") {
		return string(body)
	}

	return fmt.Sprintf("[Binary content - Content-Type: %s - Size: %d bytes]",
		contentType,
		len(body))
}

// captureRequestBody reads up to maxLoggedBody for the log and puts it back in
// front of the rest, so the backend still receives the whole body.
func captureRequestBody(r *http.Request) ([]byte, error) {
	head, err := io.ReadAll(io.LimitReader(r.Body, maxLoggedBody))
	if err != nil {
		return nil, err
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	return head, nil
}

func writeHeaders(sb *strings.Builder, prefix string, h http.Header) {
	for _, key := range slices.Sorted(maps.Keys(h)) {
		fmt.Fprintf(sb, "%s   %s: %s\n", prefix, key, strings.Join(h[key], ", "))
	}
}

func captureRequestLog(r *http.Request, routeKey string, target string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "\n%s>> REQUEST RECEIVED%s\n", colorGreen, colorReset)
	fmt.Fprintf(&sb, "%s>> Route:%s %s → %s\n", colorGreen, colorReset, routeKey, target)
	fmt.Fprintf(&sb, "%s>> Method:%s %s\n", colorGreen, colorReset, r.Method)
	fmt.Fprintf(&sb, "%s>> URL:%s %s%s\n", colorGreen, colorReset, r.Host, r.URL.String())
	fmt.Fprintf(&sb, "%s>> Headers:%s\n", colorGreen, colorReset)
	writeHeaders(&sb, ">>", r.Header)

	body, err := captureRequestBody(r)
	if err != nil {
		fmt.Fprintf(&sb, ">>   [Error reading body: %v]\n", err)
		return sb.String()
	}
	if len(body) > 0 {
		fmt.Fprintf(&sb, "%s>> Body:%s\n", colorGreen, colorReset)
		fmt.Fprintf(&sb, ">>   %s\n", formatBody(body, r.Header.Get("Content-Type")))
	}

	return sb.String()
}

func captureResponseLog(w *loggingResponseWriter, duration time.Duration) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "\n%s<< RESPONSE SENT%s\n", colorYellow, colorReset)
	fmt.Fprintf(&sb, "%s<< Status:%s %d %s\n",
		colorYellow,
		colorReset,
		w.statusCode,
		http.StatusText(w.statusCode))
	fmt.Fprintf(&sb, "%s<< Size:%s %d bytes\n", colorYellow, colorReset, w.size)
	fmt.Fprintf(&sb, "%s<< Duration:%s %v\n", colorYellow, colorReset, duration)
	fmt.Fprintf(&sb, "%s<< Headers:%s\n", colorYellow, colorReset)
	writeHeaders(&sb, "<<", w.Header())

	if w.body.Len() > 0 {
		fmt.Fprintf(&sb, "%s<< Body:%s\n", colorYellow, colorReset)
		fmt.Fprintf(&sb, "<<   %s\n", formatBody(w.body.Bytes(), w.Header().Get("Content-Type")))
	}

	return sb.String()
}

func loggingHandler(routeKey string, target string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		requestLog := captureRequestLog(r, routeKey, target)
		fmt.Print(requestLog)

		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lw, r)

		responseLog := captureResponseLog(lw, time.Since(start))
		fmt.Print(responseLog)

		err := writeToLogFile(logFilePath(routeKey), ansiStripper.Replace(requestLog+responseLog))
		if err != nil {
			log.Printf("Failed to write log file: %v", err)
		}
	})
}

func logFilePath(routeKey string) string {
	logsDir := "logs"
	err := os.MkdirAll(logsDir, 0700)
	if err != nil {
		log.Printf("Failed to create logs directory: %v", err)
		logsDir = "."
	}

	timestamp := strings.ReplaceAll(time.Now().UTC().Format(time.RFC3339Nano), ":", "-")
	name := strings.ReplaceAll(routeKey, "/", "_")
	return filepath.Join(logsDir, name+"-"+timestamp+".log")
}

// writeToLogFile is 0600: the log holds request headers, cookies and tokens
// included.
func writeToLogFile(filePath string, content string) error {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	// #nosec G703 -- filePath comes from logFilePath: logs dir, a route key from
	// the config and a timestamp; nothing in it comes from the request.
	return os.WriteFile(filePath, []byte(content), 0600)
}

func routeNotFound(w http.ResponseWriter, r *http.Request) {
	errorMsg := fmt.Sprintf("\n%s!! ROUTE NOT FOUND%s: %s\n", colorRed, colorReset, r.URL.Path)
	fmt.Print(errorMsg)

	err := writeToLogFile(logFilePath("error"), ansiStripper.Replace(errorMsg))
	if err != nil {
		log.Printf("write error log: %v", err)
	}

	http.NotFound(w, r)
}

// newRouter builds one reverse proxy per route. A request goes to the route
// with the longest matching path prefix, with that prefix stripped.
func newRouter(routes map[string]string) (http.Handler, error) {
	proxies := make(map[string]http.Handler, len(routes))
	for key, port := range routes {
		_, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("route %q: invalid port %q", key, port)
		}
		key = strings.Trim(key, "/")
		target := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", port)}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorLog = log.Default()
		proxies[key] = loggingHandler(key, target.String(), proxy)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seg := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		for i := len(seg); i > 0; i-- {
			h, ok := proxies[strings.Join(seg[:i], "/")]
			if !ok {
				continue
			}
			r.URL.Path = "/" + strings.Join(seg[i:], "/")
			r.URL.RawPath = ""
			h.ServeHTTP(w, r)
			return
		}
		routeNotFound(w, r)
	}), nil
}

func usage() {
	fmt.Printf(`Usage: devmux

Open a reverse SSH tunnel to Host and route the HTTP requests that arrive on
its loopback RemotePort to local ports by path prefix.

Config: ./devmux_init.filo, else %s
  (set Host "my-vps")          ;; alias or host, resolved via ~/.ssh/config
  (set RemotePort "10000")     ;; default 10000
  (set Routes (list (tuple "api" "3000") (tuple "web" "8080")))

Requests and responses are printed to stdout and saved one per file in ./logs.

Example: with the config above, https://my-vps/api/users -> 127.0.0.1:3000/users
`, getInitFiloPath())
}

func main() {
	flag.Usage = usage
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Llongfile)

	initFile := getInitFiloPath()
	if fileExists("devmux_init.filo") {
		initFile = "devmux_init.filo"
	}
	runFiloFile(initFile)
	if host == "" {
		log.Fatalf("Host not set: create %s or ./devmux_init.filo (see devmux -h)", getInitFiloPath())
	}

	handler, err := newRouter(routes)
	if err != nil {
		log.Fatal(err)
	}

	addr, sshUser, sshKeyPath := sshTarget(host)
	sshClient := dialSSH(sshUser, addr, sshKeyPath)
	defer func() { _ = sshClient.Close() }()
	go keepAlive(sshClient, 30*time.Second)

	ln, err := sshClient.Listen("tcp", "127.0.0.1:"+remotePort)
	if err != nil {
		log.Fatalf("remote listen %s: %v", remotePort, err)
	}
	fmt.Printf("%s✓%s Remote port %s%s%s open on VPS (loopback)\n", colorGreen, colorReset, colorCyan, remotePort, colorReset)

	// ReadHeaderTimeout bounds a client that opens a connection and dribbles
	// headers forever (Slowloris). devmux listens on loopback, but the far end
	// of the tunnel is a port open on the VPS.
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		fmt.Printf("\n%sShutting down...%s\n", colorYellow, colorReset)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("%s→%s VPS reverse proxy port %s%s%s %s➜%s SSH %s➜%s devmux %s➜%s local ports\n",
		colorBlue, colorReset,
		colorCyan, remotePort, colorReset,
		colorGreen, colorReset,
		colorGreen, colorReset,
		colorGreen, colorReset)
	err = server.Serve(ln)
	if !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	<-drained
	fmt.Printf("%sShutdown complete. Goodbye!%s\n", colorGreen, colorReset)
}
