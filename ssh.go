package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const sshTimeout = 10 * time.Second

// sshTarget resolves alias through ~/.ssh/config the way ssh does: a missing
// file or a missing Hostname means the alias is the host itself.
func sshTarget(alias string) (addr, user, keyPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", err
	}

	// #nosec G304 -- the user's own ~/.ssh/config.
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", "", "", fmt.Errorf("read SSH config: %w", err)
	}
	cfg, err := ssh_config.DecodeBytes(b)
	if err != nil {
		return "", "", "", fmt.Errorf("decode SSH config: %w", err)
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

	return net.JoinHostPort(hostname, port), user, keyPath, nil
}

func dialSSH(ctx context.Context, alias string) (*ssh.Client, error) {
	addr, user, keyPath, err := sshTarget(alias)
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	hostKeyCallback, err := knownhosts.New(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}

	auth, closeAgent, err := agentAuth(keyPath)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	defer closeAgent()

	cfg := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: knownHostAlgorithms(hostKeyCallback, addr),
		Timeout:           sshTimeout,
	}
	d := net.Dialer{Timeout: sshTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(sshTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
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
		if certAuthority(k) {
			// The key is a CA's, not the host's: the host shows a
			// certificate of any type, so the negotiation stays open.
			return nil
		}
		switch k.Key.Type() {
		case ssh.KeyAlgoRSA:
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		default:
			algos = append(algos, k.Key.Type())
		}
	}
	return algos
}

// agentAuth prefers ssh-agent; the returned func closes its socket once the
// handshake is over (a retrying tunnel would leak one per attempt).
func agentAuth(sshKeyPath string) (ssh.AuthMethod, func(), error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock != "" {
		// #nosec G704 -- sock is the ssh-agent socket from the user's own
		// environment, not a network address taken from any request.
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), func() { _ = conn.Close() }, nil
		}
	}

	if sshKeyPath == "" {
		return nil, nil, errors.New("no ssh-agent and no IdentityFile for this host")
	}
	// #nosec G304 -- sshKeyPath is the user's own SSH key from ssh_config.
	key, err := os.ReadFile(sshKeyPath)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", sshKeyPath, err)
	}
	return ssh.PublicKeys(signer), func() {}, nil
}

// certAuthority says whether k came from an @cert-authority line. KeyError
// does not say, but it gives the file and line.
func certAuthority(k knownhosts.KnownKey) bool {
	b, err := os.ReadFile(filepath.Clean(k.Filename)) // #nosec G304 -- the known_hosts devmux opened
	if err != nil {
		return false
	}
	lines := strings.Split(string(b), "\n")
	if k.Line < 1 || k.Line > len(lines) {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(lines[k.Line-1]), "@cert-authority")
}
