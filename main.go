// devmux - create a reverse tunnel to a remote server and proxy requests to local ports.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	luaEngine "github.com/yuin/gopher-lua"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"devmux/lua"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

var (
	user       = ""
	host       = ""
	remotePort = "10000"
	routes     = map[string]string{}
)

func fileExists(name string) bool {
	_, err := os.Stat(name)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		panic(err)
	}
	return true
}

func configHome() string {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("Failed to get home directory:", err)
		}
		configHome = filepath.Join(home, ".config")
	}
	return configHome
}

func getInitLuaPath() string {
	configHome := configHome()
	return filepath.Join(configHome, "devmux", "init.lua")
}

// createConfigDir creates the config directory if it does not exist.
func createConfigDir() {
	configHome := configHome()
	configDir := filepath.Join(configHome, "devmux")
	_, err := os.Stat(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(configDir, 0700)
			if err != nil {
				log.Fatal("Failed to create config directory:", err)
			}
			return
		}
		log.Fatal("Failed to check config directory:", err)
	}
}

func runLuaFile(name string) {
	//devmuxPath = "./" // TODO: get better default path

	if !fileExists(name) {
		//log.Fatalf("Config file %s not found", name)
		return
	}

	// Create a new Lua state.
	L := lua.New()
	defer L.Close()

	//L.SetGlobal("devmux_path", devmuxPath)
	L.SetGlobal("User", user) // TODO: get user from ~/.ssh/config
	L.SetGlobal("Host", "")
	L.SetGlobal("RemotePort", remotePort)
	L.SetGlobal("Routes", L.GetState().NewTable())

	// Read the Lua file.
	b, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		log.Fatal(err)
	}

	err = L.DoString(string(b))
	if err != nil {
		log.Fatal(err)
	}

	// Get the routes table from Lua.
	routesTable := L.GetGlobalTable("Routes")
	if routesTable == nil {
		log.Fatal("Failed to get routes table from Lua")
	}

	routes = make(map[string]string)
	routesTable.ForEach(func(k, v luaEngine.LValue) {
		if k.Type() == luaEngine.LTString && v.Type() == luaEngine.LTString {
			key := k.String()
			value := v.String()
			routes[key] = value
		}
	})

	user = L.MustGetString("User")
	host = L.MustGetString("Host")
	remotePort = L.MustGetString("RemotePort")

}

func dialSSH(user, host, keyFile string) *ssh.Client {
	auth, err := agentAuth()
	if err != nil {
		auth, err = keyAuth(keyFile)
		if err != nil {
			log.Fatalf("auth: %v", err)
		}
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: use a proper host key callback
		Timeout:         10 * time.Second,
	}
	c, err := ssh.Dial("tcp", host, cfg)
	if err != nil {
		log.Fatalf("ssh dial: %v", err)
	}
	return c
}

func agentAuth() (ssh.AuthMethod, error) {
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
		}
	}
	return nil, io.EOF
}

func keyAuth(file string) (ssh.AuthMethod, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	sign, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(sign), nil
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

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// loggingResponseWriter is a wrapper for http.ResponseWriter that captures the status code and size of the response
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
	body       *bytes.Buffer
}

// captures the status code
func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

// capture and count the size of the response body
func (lw *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := lw.ResponseWriter.Write(b)
	lw.size += size
	if lw.body != nil {
		lw.body.Write(b)
	}
	return size, err
}

func newLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	var buf *bytes.Buffer
	// Verificamos o Content-Type apenas no momento da escrita
	buf = &bytes.Buffer{}
	return &loggingResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // Default status code
		body:           buf,
	}
}

func formatBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return "[Empty body]"
	}

	if strings.Contains(contentType, "text") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "html") {
		return string(body)
	}

	return fmt.Sprintf("[Binary data, Content-Type: %s - Size: %v bytes]",
		contentType,
		len(body))
}

func captureRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return bodyBytes, nil
}

func logRequest(r *http.Request, routeKey string, target string) {
	fmt.Printf("\n%s>> REQUEST RECEIVED%s\n",
		colorGreen, colorReset)
	fmt.Printf("%s>> Route:%s %s → %s\n", colorGreen, colorReset, routeKey, target)
	fmt.Printf("%s>> Method:%s %s\n", colorGreen, colorReset, r.Method)
	fmt.Printf("%s>> URL:%s %s%s\n", colorGreen, colorReset, r.Host, r.URL.String())

	fmt.Printf("%s>> Headers:%s\n", colorGreen, colorReset)
	for key, values := range r.Header {
		fmt.Printf(">>   %s: %s\n", key, strings.Join(values, ", "))
	}

	bodyBytes, err := captureRequestBody(r)
	if err != nil {
		fmt.Printf(">>   [Error reading body: %v]\n", err)
		return
	}

	if len(bodyBytes) > 0 {
		contentType := r.Header.Get("Content-Type")
		fmt.Printf("%s>> Body:%s\n", colorGreen, colorReset)
		fmt.Printf(">>   %s\n", formatBody(bodyBytes, contentType))
	}
}

func logResponse(w *loggingResponseWriter, duration time.Duration) {
	fmt.Printf("\n%s<< RESPONSE%s\n",
		colorYellow, colorReset)
	fmt.Printf("%s<< Status:%s %d %s\n",
		colorYellow,
		colorReset,
		w.statusCode,
		http.StatusText(w.statusCode))
	fmt.Printf("%s<< Size:%s %d bytes\n", colorYellow, colorReset, w.size)
	fmt.Printf("%s<< Duration:%s %v\n", colorYellow, colorReset, duration)

	fmt.Printf("%s<< Headers:%s\n", colorYellow, colorReset)
	for key, values := range w.Header() {
		fmt.Printf("<<   %s: %s\n", key, strings.Join(values, ", "))
	}

	if w.body != nil && w.body.Len() > 0 {
		contentType := w.Header().Get("Content-Type")
		fmt.Printf("%s<< Body:%s\n", colorYellow, colorReset)
		fmt.Printf("<<   %s\n", formatBody(w.body.Bytes(), contentType))
	}
}

// loggingHandler is a middleware that intercepts requests and responses for logging
func loggingHandler(routeKey string, target string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		logRequest(r, routeKey, target)

		lw := newLoggingResponseWriter(w)

		next.ServeHTTP(lw, r)

		duration := time.Since(start)
		logResponse(lw, duration)
	})
}

func main() {
	log.SetFlags(log.LstdFlags | log.Llongfile)

	createConfigDir()
	initFile := getInitLuaPath()

	if fileExists("./devmux_init.lua") {
		initFile = "./devmux_init.lua"
	}

	key := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519")

	runLuaFile(initFile)

	sshClient := dialSSH(user, host, key)
	defer sshClient.Close()
	go keepAlive(sshClient, 30*time.Second)

	// 1. ask the server to listen on
	ln, err := sshClient.Listen("tcp", "127.0.0.1:"+remotePort)
	if err != nil {
		log.Fatalf("remote listen %s: %v", remotePort, err)
	}
	log.Printf("✓ Remote port %s open on VPS (loopback)", remotePort)

	// 2. listen on local port
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seg := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(seg) == 0 || seg[0] == "" {
			fmt.Printf("\n%s!! ROTA NÃO ENCONTRADA%s: %s\n", colorRed, colorReset, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		port, ok := routes[seg[0]]
		if !ok {
			fmt.Printf("\n%s!! ROTA NÃO ENCONTRADA%s: %s\n", colorRed, colorReset, seg[0])
			http.NotFound(w, r)
			return
		}

		routeKey := seg[0]
		// strip first segment
		r.URL.Path = "/" + strings.Join(seg[1:], "/")
		target := "http://127.0.0.1:" + port

		proxy := httputil.NewSingleHostReverseProxy(mustParseURL(target))
		proxy.ErrorLog = log.Default()

		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
		}

		// Use the middleware to log the request and response
		loggingHandler(routeKey, target, proxy).ServeHTTP(w, r)
	})

	server := http.Server{Handler: handler}

	// 3. CTRL-C close connection
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; ln.Close(); sshClient.Close() }()

	log.Printf("→ Ready: Caddy ➜ VPS:%s ➜ SSH ➜ devmux ➜ local ports", remotePort)
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
