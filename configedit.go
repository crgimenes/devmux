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

// saveTunnel rewrites c's (tunnel ...) form in file and nothing else, then
// checks that the file still reads back to c before it replaces the old
// one. Comments inside the form are lost; the rest stays byte for byte.
// Another writer that got in between makes it start over from their text.
func saveTunnel(file string, c tunnelConf) error {
	real, err := filepath.EvalSymlinks(file)
	if err != nil {
		return err
	}
	for range 5 {
		b, err := os.ReadFile(filepath.Clean(real)) // #nosec G304 G703 -- the config file devmux loaded
		if err != nil {
			return err
		}
		out, err := editTunnel(file, string(b), c)
		if err != nil {
			return err
		}
		again, err := replaceIfUnchanged(real, b, out)
		if !again {
			return err
		}
	}
	return fmt.Errorf("%s keeps changing under devmux; try again", file)
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
