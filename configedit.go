package main

import (
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

// formName is NAME when form is (tunnel "NAME" ...), else "".
func formName(form string) string {
	rest, ok := strings.CutPrefix(form, "(")
	if !ok {
		return ""
	}
	rest = strings.TrimLeft(rest, " \t\r\n")
	rest, ok = strings.CutPrefix(rest, "tunnel")
	if !ok || rest == "" || !strings.ContainsRune(" \t\r\n", rune(rest[0])) {
		return ""
	}
	rest = strings.TrimLeft(rest, " \t\r\n")
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	s, _ := readString(rest)
	return s
}

// readString reads the string literal at the start of s: its value and the
// bytes it spans, quotes included.
func readString(s string) (string, int) {
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				sb.WriteByte(s[i])
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
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
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
func saveTunnel(file string, c tunnelConf) error {
	real, err := filepath.EvalSymlinks(file)
	if err != nil {
		return err
	}
	info, err := os.Stat(real) // #nosec G703 -- the config file devmux loaded
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Clean(real)) // #nosec G304 G703 -- the config file devmux loaded
	if err != nil {
		return err
	}
	src := string(b)
	start, end, ok := tunnelForm(src, c.Name)
	if !ok {
		return fmt.Errorf("no (tunnel %q ...) in %s to save into; the old Host/Routes globals are edited by hand", c.Name, file)
	}
	out := src[:start] + formatTunnel(c) + src[end:]

	confs, err := parseConfig(file, []byte(out))
	if err != nil {
		return fmt.Errorf("the edited config does not load: %w", err)
	}
	i := slices.IndexFunc(confs, func(o tunnelConf) bool { return o.Name == c.Name })
	if i < 0 || !slices.Equal(confs[i].Routes, c.Routes) {
		return fmt.Errorf("the edited config does not read back as written")
	}

	tmp := real + ".devmux-tmp"
	err = os.WriteFile(tmp, []byte(out), info.Mode().Perm()) // #nosec G703 -- next to the config file devmux loaded
	if err != nil {
		return err
	}
	err = os.Rename(tmp, real) // #nosec G703 -- the config file devmux loaded
	if err != nil {
		_ = os.Remove(tmp) // #nosec G703 -- our temp file beside it
	}
	return err
}
