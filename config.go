package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/crgimenes/filo"
)

type route struct {
	Prefix string `json:"prefix"`
	Port   string `json:"port"`
}

type tunnelConf struct {
	Name       string  `json:"name"`
	Host       string  `json:"host"`
	RemotePort string  `json:"remote_port"`
	Routes     []route `json:"routes"`
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

// stateHome holds what a running devmux leaves for the CLI to read: the
// request logs and one status file per process.
func stateHome() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir != "" {
		return filepath.Join(dir, "devmux")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("Failed to get home directory:", err)
	}
	return filepath.Join(home, ".local", "state", "devmux")
}

func defaultConfig() string {
	return filepath.Join(configHome(), "devmux", "init.filo")
}

// configFile is the file named, else ./devmux_init.filo, else the default.
func configFile(name string) string {
	if name != "" {
		return name
	}
	if fileExists("devmux_init.filo") {
		return "devmux_init.filo"
	}
	return defaultConfig()
}

func fileExists(name string) bool {
	_, err := os.Stat(name) // #nosec G703 -- a config path the user gave
	if err == nil {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	panic(err)
}

func loadConfig(name string) ([]tunnelConf, error) {
	file := configFile(name)
	b, err := os.ReadFile(filepath.Clean(file)) // #nosec G304 G703 -- the config file the user chose
	if err != nil {
		return nil, err
	}

	var tunnels []tunnelConf
	f := filo.New()
	defer f.Close()
	// The globals are the format before (tunnel ...): one tunnel, named
	// after its host.
	f.SetGlobal("Host", "")
	f.SetGlobal("RemotePort", "10000")
	f.SetGlobal("Routes", map[string]string{})
	err = f.RegisterBuiltin("tunnel", func(_ context.Context, args []filo.Value) (filo.Value, error) {
		t, err := parseTunnel(args)
		if err != nil {
			return filo.VBool(false), err
		}
		if slices.ContainsFunc(tunnels, func(o tunnelConf) bool { return o.Name == t.Name }) {
			return filo.VBool(false), fmt.Errorf("tunnel %q declared twice", t.Name)
		}
		tunnels = append(tunnels, t)
		return filo.VBool(true), nil
	})
	if err != nil {
		return nil, err
	}
	err = f.DoString(strings.TrimPrefix(string(b), "\uFEFF"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if len(tunnels) > 0 {
		return tunnels, nil
	}

	host, err := f.GetString("Host")
	if err != nil || host == "" {
		return nil, fmt.Errorf("%s: no (tunnel ...) declared", file)
	}
	t := tunnelConf{Name: host, Host: host}
	t.RemotePort, err = f.GetString("RemotePort")
	if err != nil {
		return nil, fmt.Errorf("%s: RemotePort: %w", file, err)
	}
	m, err := f.GetMap("Routes")
	if err != nil {
		return nil, fmt.Errorf("%s: Routes: %w", file, err)
	}
	for _, prefix := range slices.Sorted(maps.Keys(m)) {
		t.Routes = append(t.Routes, route{Prefix: prefix, Port: m[prefix]})
	}
	err = t.check()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return []tunnelConf{t}, nil
}

// parseTunnel reads (tunnel NAME HOST REMOTE-PORT (list (tuple PREFIX PORT) ...)).
func parseTunnel(args []filo.Value) (tunnelConf, error) {
	if len(args) != 4 {
		return tunnelConf{}, errors.New("tunnel: want (tunnel NAME HOST REMOTE-PORT ROUTES)")
	}
	var t tunnelConf
	var err error
	for i, dst := range []*string{&t.Name, &t.Host, &t.RemotePort} {
		*dst, err = valueText(args[i])
		if err != nil {
			return tunnelConf{}, fmt.Errorf("tunnel: argument %d: %w", i+1, err)
		}
	}
	list, err := args[3].AsList()
	if err != nil {
		return tunnelConf{}, fmt.Errorf("tunnel %s: routes: %w", t.Name, err)
	}
	for i, item := range list {
		pair, err := item.AsTuple()
		if err != nil || len(pair) != 2 {
			return tunnelConf{}, fmt.Errorf("tunnel %s: route %d is not (tuple PREFIX PORT)", t.Name, i+1)
		}
		var r route
		r.Prefix, err = valueText(pair[0])
		if err != nil {
			return tunnelConf{}, fmt.Errorf("tunnel %s: route %d: %w", t.Name, i+1, err)
		}
		r.Port, err = valueText(pair[1])
		if err != nil {
			return tunnelConf{}, fmt.Errorf("tunnel %s: route %d: %w", t.Name, i+1, err)
		}
		t.Routes = append(t.Routes, r)
	}
	return t, t.check()
}

// check normalizes the prefixes and refuses what would only fail later,
// on a request.
func (t *tunnelConf) check() error {
	if strings.TrimSpace(t.Name) == "" || strings.ContainsAny(t.Name, "/\\") {
		return fmt.Errorf("tunnel %q: name must be non-empty and have no slash", t.Name)
	}
	if t.Host == "" {
		return fmt.Errorf("tunnel %s: host is empty", t.Name)
	}
	err := checkPort(t.RemotePort)
	if err != nil {
		return fmt.Errorf("tunnel %s: remote port: %w", t.Name, err)
	}
	seen := map[string]bool{}
	for i := range t.Routes {
		r := &t.Routes[i]
		r.Prefix = strings.Trim(r.Prefix, "/")
		if r.Prefix == "" || seen[r.Prefix] {
			return fmt.Errorf("tunnel %s: route %q is empty or repeated", t.Name, r.Prefix)
		}
		seen[r.Prefix] = true
		err = checkPort(r.Port)
		if err != nil {
			return fmt.Errorf("tunnel %s: route %s: %w", t.Name, r.Prefix, err)
		}
	}
	return nil
}

func checkPort(p string) error {
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("invalid port %q", p)
	}
	return nil
}

// valueText takes a string, or a number written without quotes.
func valueText(v filo.Value) (string, error) {
	s, err := v.AsString()
	if err == nil {
		return s, nil
	}
	n, nerr := v.AsNumber()
	if nerr != nil {
		return "", err
	}
	return strconv.FormatFloat(n, 'f', -1, 64), nil
}
