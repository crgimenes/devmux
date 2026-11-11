package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
)

// runCommand returns the exit status: 0 done, 1 failed, 2 used wrong.
func runCommand(name string, args []string) int {
	fs := flag.NewFlagSet("devmux "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "")
	asJSON := fs.Bool("json", false, "")
	tunnelName := fs.String("tunnel", "", "")
	n := fs.Int("n", 20, "")
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		printUsage()
		return 0
	}
	if err != nil {
		warnf("%v (devmux -h)", err)
		return 2
	}
	if name == "" && fs.NArg() > 0 {
		// devmux -config F ls: the flags came before the command.
		rest := fs.Args()[1:]
		if *config != "" {
			rest = append([]string{"-config", *config}, rest...)
		}
		return runCommand(fs.Arg(0), rest)
	}

	switch name {
	case "":
		return cmdScreen(*config)
	case "run":
		return cmdRun(*config, fs.Args())
	case "ls":
		return cmdList(*config, *asJSON)
	case "requests":
		return cmdRequests(*tunnelName, *n, *asJSON)
	case "request":
		if fs.NArg() != 1 {
			warnf("request: want one ID (devmux requests lists them)")
			return 2
		}
		return cmdRequest(fs.Arg(0), *asJSON)
	case "help":
		printUsage()
		return 0
	}
	warnf("unknown command %q (devmux -h)", name)
	return 2
}

func loadOrWarn(config string) ([]tunnelConf, bool) {
	confs, err := loadConfig(config)
	if err != nil {
		warnf("%v (devmux -h shows the format)", err)
		return nil, false
	}
	return confs, true
}

// pickTunnels is the tunnels named, in config order; none named is all.
func pickTunnels(confs []tunnelConf, names []string) ([]tunnelConf, error) {
	if len(names) == 0 {
		return confs, nil
	}
	var out []tunnelConf
	for _, name := range names {
		i := slices.IndexFunc(confs, func(c tunnelConf) bool { return c.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("no tunnel %q in the config", name)
		}
		out = append(out, confs[i])
	}
	return out, nil
}

func cmdRun(config string, names []string) int {
	confs, ok := loadOrWarn(config)
	if !ok {
		return 2
	}
	confs, err := pickTunnels(confs, names)
	if err != nil {
		warnf("%v", err)
		return 2
	}

	s := newSession("run", configFile(config), confs, true)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)

	last := map[string]string{}
	for _, t := range s.tunnels {
		t.start()
	}
	for {
		select {
		case <-sig:
			fmt.Printf("%sclosing tunnels...%s\n", colorYellow, colorReset)
			s.close()
			return 0
		case <-s.wake:
			for _, t := range s.tunnels {
				st := t.status()
				line := stateLine(st)
				if last[st.Name] != line {
					last[st.Name] = line
					fmt.Println(line)
				}
			}
		}
	}
}

// stateLine is how devmux run reports a tunnel when its state changes.
func stateLine(st tunnelStatus) string {
	switch st.State {
	case stUp:
		return fmt.Sprintf("%s✓ %s%s up: %s:127.0.0.1:%s ➜ SSH ➜ local ports", colorGreen, st.Name, colorReset, st.Host, st.RemotePort)
	case stRetry:
		return fmt.Sprintf("%s✗ %s%s retry %d: %s", colorRed, st.Name, colorReset, st.Retries, st.Error)
	}
	return fmt.Sprintf("%s… %s%s %s", colorCyan, st.Name, colorReset, st.State)
}

type lsRow struct {
	tunnelConf
	State     string   `json:"state"`
	Error     string   `json:"error,omitempty"`
	PID       int      `json:"pid,omitempty"`
	Mode      string   `json:"mode,omitempty"`
	RoutesOff []string `json:"routes_off,omitempty"`
}

func cmdList(config string, asJSON bool) int {
	confs, ok := loadOrWarn(config)
	if !ok {
		return 2
	}
	statuses, err := readStatuses()
	if err != nil {
		warnf("%v", err)
		return 1
	}

	var rows []lsRow
	for _, c := range confs {
		row := lsRow{tunnelConf: c, State: stOff}
		for _, p := range statuses {
			for _, st := range p.Tunnels {
				if st.Name != c.Name || st.State == stOff {
					continue
				}
				row.State, row.Error, row.PID, row.Mode, row.RoutesOff = st.State, st.Error, p.PID, p.Mode, st.Off
			}
		}
		rows = append(rows, row)
	}

	if asJSON {
		return printJSON(rows)
	}
	for _, r := range rows {
		var routes []string
		for _, rt := range r.Routes {
			routes = append(routes, rt.Prefix+"="+rt.Port)
		}
		pidText := ""
		if r.PID != 0 {
			pidText = fmt.Sprintf("%d(%s)", r.PID, r.Mode)
		}
		fmt.Printf("%s;%s;%s;%s;%s;%s;%s\n",
			r.Name, r.Host, r.RemotePort, r.State, pidText, strings.Join(routes, ","), strings.Join(r.RoutesOff, ","))
	}
	return 0
}

func cmdRequests(tunnel string, n int, asJSON bool) int {
	got, err := recentExchanges(logsDir(), tunnel, n)
	if err != nil {
		warnf("%v", err)
		return 1
	}
	if asJSON {
		type brief struct {
			ID     string  `json:"id"`
			Time   string  `json:"time"`
			Tunnel string  `json:"tunnel"`
			Route  string  `json:"route,omitempty"`
			Method string  `json:"method"`
			URL    string  `json:"url"`
			Status int     `json:"status"`
			MS     float64 `json:"ms"`
			Note   string  `json:"note,omitempty"`
		}
		out := []brief{}
		for _, ex := range got {
			out = append(out, brief{ex.ID, ex.Time.Format("2006-01-02T15:04:05.000Z07:00"), ex.Tunnel, ex.Route, ex.Method, ex.URL, ex.Status, ex.MS, ex.Note})
		}
		return printJSON(out)
	}
	for _, ex := range got {
		fmt.Printf("%s;%s;%s;%s;%s;%d;%.1f\n",
			ex.ID, ex.Time.Format("2006-01-02 15:04:05"), ex.Tunnel, ex.Method, ex.URL, ex.Status, ex.MS)
	}
	return 0
}

func cmdRequest(id string, asJSON bool) int {
	ex, err := findExchange(logsDir(), id)
	if err != nil {
		warnf("%v", err)
		return 1
	}
	if asJSON {
		return printJSON(ex)
	}
	fmt.Print(formatExchange(ex, false))
	return 0
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	err := enc.Encode(v)
	if err != nil {
		warnf("%v", err)
		return 1
	}
	return 0
}
