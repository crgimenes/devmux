// devmux - create a reverse tunnel to a remote server and proxy requests to local ports.
package main

import (
	"devmux/lua"
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
			http.NotFound(w, r)
			return
		}
		port, ok := routes[seg[0]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		// strip first segment
		r.URL.Path = "/" + strings.Join(seg[1:], "/")
		target := "http://127.0.0.1:" + port

		proxy := httputil.NewSingleHostReverseProxy(mustParseURL(target))
		proxy.ErrorLog = log.Default()
		proxy.ServeHTTP(w, r)
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
