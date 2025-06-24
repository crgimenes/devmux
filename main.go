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

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

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

	host = L.MustGetString("Host")
	remotePort = L.MustGetString("RemotePort")

}

func dialSSH(user, host, sshKeyPath string) *ssh.Client {
	auth, err := agentAuth(sshKeyPath)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

	hostKeyCallback, err := knownhosts.New(os.ExpandEnv("$HOME/.ssh/known_hosts"))
	if err != nil {
		log.Fatal("could not create hostkeycallback function: ", err)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}
	c, err := ssh.Dial("tcp", host, cfg)
	if err != nil {
		log.Fatalf("ssh dial: %v", err)
	}
	return c
}

func loadPrivateKey(keyPath string) (ssh.Signer, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(key)
}

func agentAuth(sshKeyPath string) (ssh.AuthMethod, error) {
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), nil
		}
	}

	signer, err := loadPrivateKey(sshKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
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
	// We check the Content-Type only at the time of writing
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

	// Process www-form-urlencoded forms
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		formValues, err := url.ParseQuery(string(body))
		if err == nil {
			var sb strings.Builder
			sb.WriteString("[Form data]\n")

			for key, values := range formValues {
				sb.WriteString(fmt.Sprintf(">>   %s: %s\n", key, strings.Join(values, ", ")))
			}
			return sb.String()
		}
		// If parsing fails, fall back to default behavior
	}

	// Process multipart/form-data (without showing binary data)
	if strings.Contains(contentType, "multipart/form-data") {
		return fmt.Sprintf("[Multipart form - Size: %v bytes]\nContent-Type: %s",
			len(body), contentType)
	}

	// Process other readable content types
	if strings.Contains(contentType, "text") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "html") {
		return string(body)
	}

	// Binary or unknown data
	return fmt.Sprintf("[Binary content - Content-Type: %s - Size: 0x%X bytes]",
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

// captureRequestLog formats request information and returns it as a string
func captureRequestLog(r *http.Request, routeKey string, target string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n%s>> REQUEST RECEIVED%s\n",
		colorGreen, colorReset))
	sb.WriteString(fmt.Sprintf("%s>> Route:%s %s → %s\n", colorGreen, colorReset, routeKey, target))
	sb.WriteString(fmt.Sprintf("%s>> Method:%s %s\n", colorGreen, colorReset, r.Method))
	sb.WriteString(fmt.Sprintf("%s>> URL:%s %s%s\n", colorGreen, colorReset, r.Host, r.URL.String()))

	sb.WriteString(fmt.Sprintf("%s>> Headers:%s\n", colorGreen, colorReset))
	for key, values := range r.Header {
		sb.WriteString(fmt.Sprintf(">>   %s: %s\n", key, strings.Join(values, ", ")))
	}

	bodyBytes, err := captureRequestBody(r)
	if err != nil {
		sb.WriteString(fmt.Sprintf(">>   [Error reading body: %v]\n", err))
	} else if len(bodyBytes) > 0 {
		contentType := r.Header.Get("Content-Type")
		sb.WriteString(fmt.Sprintf("%s>> Body:%s\n", colorGreen, colorReset))
		sb.WriteString(fmt.Sprintf(">>   %s\n", formatBody(bodyBytes, contentType)))
	}

	return sb.String()
}

// captureResponseLog formats response information and returns it as a string
func captureResponseLog(w *loggingResponseWriter, duration time.Duration) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n%s<< RESPONSE SENT%s\n",
		colorYellow, colorReset))
	sb.WriteString(fmt.Sprintf("%s<< Status:%s %d %s\n",
		colorYellow,
		colorReset,
		w.statusCode,
		http.StatusText(w.statusCode)))
	sb.WriteString(fmt.Sprintf("%s<< Size:%s %d bytes\n", colorYellow, colorReset, w.size))
	sb.WriteString(fmt.Sprintf("%s<< Duration:%s %v\n", colorYellow, colorReset, duration))

	sb.WriteString(fmt.Sprintf("%s<< Headers:%s\n", colorYellow, colorReset))
	for key, values := range w.Header() {
		sb.WriteString(fmt.Sprintf("<<   %s: %s\n", key, strings.Join(values, ", ")))
	}

	if w.body != nil && w.body.Len() > 0 {
		contentType := w.Header().Get("Content-Type")
		sb.WriteString(fmt.Sprintf("%s<< Body:%s\n", colorYellow, colorReset))
		sb.WriteString(fmt.Sprintf("<<   %s\n", formatBody(w.body.Bytes(), contentType)))
	}

	return sb.String()
}

// loggingHandler is a middleware that intercepts requests and responses for logging
func loggingHandler(routeKey string, target string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a buffer to capture log output
		var logBuffer bytes.Buffer

		// Log request to console and capture for file
		requestLog := captureRequestLog(r, routeKey, target)
		fmt.Print(requestLog)
		logBuffer.WriteString(stripAnsiCodes(requestLog))

		// Process the request
		lw := newLoggingResponseWriter(w)
		next.ServeHTTP(lw, r)

		// Calculate duration
		duration := time.Since(start)

		// Log response to console and capture for file
		responseLog := captureResponseLog(lw, duration)
		fmt.Print(responseLog)
		logBuffer.WriteString(stripAnsiCodes(responseLog))

		// Create log file with the combined log content
		logPath := logFilePath(routeKey)
		if err := writeToLogFile(logPath, logBuffer.String()); err != nil {
			log.Printf("Failed to write log file: %v", err)
		}
	})
}

// logFilePath generates a file path for the log file based on the route and current time
func logFilePath(routeKey string) string {
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	timestamp = strings.ReplaceAll(timestamp, ":", "-")

	// Create logs directory if it doesn't exist
	logsDir := "./logs"
	_, err := os.Stat(logsDir)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir(logsDir, 0700)
			if err != nil {
				log.Printf("Failed to create logs directory: %v", err)
				logsDir = "."
			}
		}
	}

	// Return the full path including directory
	return filepath.Join(logsDir, fmt.Sprintf("%s-%s.log", routeKey, timestamp))
}

// writeToLogFile writes the log content to a file
func writeToLogFile(filePath string, content string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Normalize line endings to just \n (Unix style)
	// First replace Windows style (\r\n) with Unix style (\n)
	normalizedContent := strings.ReplaceAll(content, "\r\n", "\n")
	// Then replace any remaining old Mac style line endings (\r) with Unix style (\n)
	normalizedContent = strings.ReplaceAll(normalizedContent, "\r", "\n")

	_, err = f.WriteString(normalizedContent)
	return err
}

// stripAnsiCodes removes ANSI color codes from a string
func stripAnsiCodes(s string) string {
	// ANSI escape code pattern
	r := strings.NewReplacer(
		colorReset, "",
		colorRed, "",
		colorGreen, "",
		colorYellow, "",
		colorBlue, "",
		colorPurple, "",
		colorCyan, "",
		colorWhite, "",
	)
	return r.Replace(s)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Llongfile)

	createConfigDir()
	initFile := getInitLuaPath()

	if fileExists("./devmux_init.lua") {
		initFile = "./devmux_init.lua"
	}

	//key := filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa")

	runLuaFile(initFile)

	///////////////////////////////
	// Read key, user, host, from init.lua or ~/.ssh/config

	sshPort := "22"

	configPath := os.ExpandEnv("$HOME/.ssh/config")
	f, err := os.Open(filepath.Clean(configPath))
	if err != nil {
		log.Fatalf("failed to open SSH config: %v", err.Error())
	}
	sshCfg, err := ssh_config.Decode(f)
	if err != nil {
		log.Fatalf("failed to decode SSH config: %v", err.Error())
	}
	f.Close()

	sshUser, _ := sshCfg.Get(host, "User")
	if sshUser == "" {
		sshUser = os.Getenv("USER")
	}
	hostname, _ := sshCfg.Get(host, "Hostname")
	if hostname == "" {
		log.Fatalf("no Hostname found for alias %s in SSH config", host)
	}
	if port, _ := sshCfg.Get(host, "Port"); port != "" {
		sshPort = port
	}
	sshKeyPath := ""
	if identity, _ := sshCfg.Get(host, "IdentityFile"); identity != "" {
		sshKeyPath = os.ExpandEnv(identity)
	}

	if sshPort != "" {
		hostname = fmt.Sprintf("%s:%s", hostname, sshPort)
	}

	sshClient := dialSSH(sshUser, hostname, sshKeyPath)
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
			// Create error message for route not found
			errorMsg := fmt.Sprintf("\n%s!! ROUTE NOT FOUND%s: %s\n", colorRed, colorReset, r.URL.Path)
			fmt.Print(errorMsg)

			// Log the error to a file (using "error" as the route key)
			errorLogPath := logFilePath("error")
			writeToLogFile(errorLogPath, stripAnsiCodes(errorMsg))

			http.NotFound(w, r)
			return
		}
		port, ok := routes[seg[0]]
		if !ok {
			// Create error message for route not found
			errorMsg := fmt.Sprintf("\n%s!! ROUTE NOT FOUND%s: %s\n", colorRed, colorReset, seg[0])
			fmt.Print(errorMsg)

			// Log the error to a file (using "error" as the route key)
			errorLogPath := logFilePath("error")
			writeToLogFile(errorLogPath, stripAnsiCodes(errorMsg))

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

	// Handle graceful shutdown on CTRL-C/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Printf("Received signal %v, shutting down...", s)

		// Close listener and SSH connections
		log.Println("Closing network connections...")
		ln.Close()

		log.Println("Closing SSH tunnel...")
		sshClient.Close()

		log.Println("Shutdown complete. Goodbye!")
		os.Exit(0)
	}()

	log.Printf("→ VPS reverse proxy port %s ➜ SSH ➜ devmux ➜ local ports", remotePort)
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		if err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}
}
