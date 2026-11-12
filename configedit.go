package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// tunnelForm finds the top-level (tunnel "name" ...) in src: the byte range
// from its "(" to just after its ")". It knows strings and ; comments,
// enough to skip parentheses inside them.
func tunnelForm(src, name string) (start, end int, ok bool) {
	depth := 0
	start = -1
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case ';':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case '"':
			_, n := readString(src[i:])
			i += n - 1
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 && formName(src[start:i+1]) == name {
				return start, i + 1, true
			}
			depth = max(depth, 0)
		}
	}
	return 0, 0, false
}

// formName is NAME when form is (tunnel NAME ...), NAME a string or a bare
// number as parseTunnel takes it, else "".
func formName(form string) string {
	rest, ok := strings.CutPrefix(form, "(")
	if !ok {
		return ""
	}
	rest, ok = strings.CutPrefix(skipBlank(rest), "tunnel")
	if !ok || rest == "" || !strings.ContainsRune(" \t\r\n;", rune(rest[0])) {
		return ""
	}
	rest = skipBlank(rest)
	if strings.HasPrefix(rest, `"`) {
		s, _ := readString(rest)
		return s
	}
	end := strings.IndexAny(rest, " \t\r\n();\"")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// skipBlank skips whitespace and ; comments.
func skipBlank(s string) string {
	for {
		s = strings.TrimLeft(s, " \t\r\n")
		if !strings.HasPrefix(s, ";") {
			return s
		}
		nl := strings.IndexByte(s, '\n')
		if nl < 0 {
			return ""
		}
		s = s[nl+1:]
	}
}

// filoEscapes is Filo's string escapes (parser.go in filo), letter to byte.
var filoEscapes = map[byte]byte{'"': '"', 'n': '\n', 't': '\t', 'r': '\r', '\\': '\\', '0': 0, 'a': '\a', 'b': '\b', 'f': '\f', 'v': '\v'}

// readString reads the string literal at the start of s the way Filo does:
// its value and the bytes it spans, quotes included.
func readString(s string) (string, int) {
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				sb.WriteByte(filoEscapes[s[i]])
			}
		case '"':
			return sb.String(), i + 1
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String(), len(s)
}

func quote(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		esc := byte(0)
		for letter, b := range filoEscapes {
			if b == s[i] {
				esc = letter
			}
		}
		if esc != 0 {
			sb.WriteByte('\\')
			sb.WriteByte(esc)
			continue
		}
		sb.WriteByte(s[i])
	}
	sb.WriteByte('"')
	return sb.String()
}

func formatTunnel(c tunnelConf) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "(tunnel %s %s %s\n  (list", quote(c.Name), quote(c.Host), quote(c.RemotePort))
	w := 0
	for _, r := range c.Routes {
		w = max(w, len(quote(r.Prefix)))
	}
	for _, r := range c.Routes {
		q := quote(r.Prefix)
		fmt.Fprintf(&sb, "\n    (tuple %s%s %s)", q, strings.Repeat(" ", w-len(q)), quote(r.Port))
	}
	sb.WriteString("))")
	return sb.String()
}

// editRoutes changes the routes of tunnel name in file: edit gets the
// routes the file holds now, under a lock every devmux takes, so a change
// another process made since this one read the file is built on, not
// undone. Only that tunnel's (tunnel ...) form is rewritten; comments
// inside it are lost, the rest stays byte for byte. It returns the routes
// written.
func editRoutes(file, name string, edit func([]route) ([]route, error)) ([]route, error) {
	real, err := filepath.EvalSymlinks(file)
	if err != nil {
		return nil, err
	}
	unlock, err := lockFile(filepath.Join(filepath.Dir(real), "."+filepath.Base(real)+".devmux-lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	// An editor does not take the lock: if the file changes between the
	// read and the rename, start over from what it holds then.
	for range 5 {
		b, err := os.ReadFile(filepath.Clean(real)) // #nosec G304 G703 -- the config file devmux loaded
		if err != nil {
			return nil, err
		}
		confs, err := parseConfig(file, b)
		if err != nil {
			return nil, fmt.Errorf("the config does not load: %w", err)
		}
		i := slices.IndexFunc(confs, func(o tunnelConf) bool { return o.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("no tunnel %q in %s", name, file)
		}
		c := confs[i]
		c.Routes, err = edit(slices.Clone(c.Routes))
		if err != nil {
			return nil, err
		}
		err = c.check()
		if err != nil {
			return nil, err
		}
		out, err := editTunnel(file, string(b), c)
		if err != nil {
			return nil, err
		}
		again, err := replaceIfUnchanged(real, b, out)
		if !again {
			return c.Routes, err
		}
	}
	return nil, fmt.Errorf("%s keeps changing under devmux; try again", file)
}

// putRoute is the edit that sets r, in place of the route from ("" adds
// it). A prefix another route already has is refused.
func putRoute(from string, r route) func([]route) ([]route, error) {
	return func(rs []route) ([]route, error) {
		for _, o := range rs {
			if o.Prefix == r.Prefix && o.Prefix != from {
				return nil, fmt.Errorf("/%s is already a route, to port %s", r.Prefix, o.Port)
			}
		}
		if from == "" {
			return append(rs, r), nil
		}
		i := slices.IndexFunc(rs, func(o route) bool { return o.Prefix == from })
		if i < 0 {
			return nil, fmt.Errorf("/%s is no longer in the config", from)
		}
		rs[i] = r
		return rs, nil
	}
}

// dropRoute is the edit that removes the route prefix.
func dropRoute(prefix string) func([]route) ([]route, error) {
	return func(rs []route) ([]route, error) {
		i := slices.IndexFunc(rs, func(o route) bool { return o.Prefix == prefix })
		if i < 0 {
			return nil, fmt.Errorf("no route /%s", prefix)
		}
		return slices.Delete(rs, i, i+1), nil
	}
}

// editTunnel is src with c's form rewritten, checked to read back as c.
func editTunnel(file, src string, c tunnelConf) (string, error) {
	start, end, ok := tunnelForm(src, c.Name)
	if !ok {
		return "", fmt.Errorf("no (tunnel %q ...) in %s to save into; the old Host/Routes globals are edited by hand", c.Name, file)
	}
	out := src[:start] + formatTunnel(c) + src[end:]
	confs, err := parseConfig(file, []byte(out))
	if err != nil {
		return "", fmt.Errorf("the edited config does not load: %w", err)
	}
	i := slices.IndexFunc(confs, func(o tunnelConf) bool { return o.Name == c.Name })
	if i < 0 || !slices.Equal(confs[i].Routes, c.Routes) {
		return "", fmt.Errorf("the edited config does not read back as written")
	}
	return out, nil
}

// replaceIfUnchanged puts out in place of real, through a fresh temp file
// beside it (O_EXCL: no symlink or stale file is followed), unless real no
// longer holds was; then again is true and nothing was written.
func replaceIfUnchanged(real string, was []byte, out string) (again bool, err error) {
	info, err := os.Stat(real) // #nosec G703 -- the config file devmux loaded
	if err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(real), "."+filepath.Base(real)+".devmux-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // #nosec G703 -- our own temp file
	_, err = tmp.WriteString(out)
	err = errors.Join(err, tmp.Chmod(info.Mode().Perm()), tmp.Close())
	if err != nil {
		return false, err
	}
	now, err := os.ReadFile(filepath.Clean(real)) // #nosec G304 G703 -- the config file devmux loaded
	if err != nil {
		return false, err
	}
	if !bytes.Equal(now, was) {
		return true, nil
	}
	return false, os.Rename(tmp.Name(), real) // #nosec G703 -- the config file devmux loaded
}
