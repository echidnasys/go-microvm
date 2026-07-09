// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// maxConcurrentConns is the maximum number of concurrent SSH connections.
	maxConcurrentConns = 4

	// maxChannelsPerConn is the maximum number of channels per connection.
	maxChannelsPerConn = 10

	// handshakeTimeout is the deadline for the SSH handshake to complete.
	handshakeTimeout = 30 * time.Second
)

// Config holds the configuration for the embedded SSH server.
type Config struct {
	// Port is the TCP port to listen on. Use 0 to let the OS assign a
	// free port.
	Port int

	// AuthorizedKeys is the list of public keys permitted to connect.
	AuthorizedKeys []ssh.PublicKey

	// Env is the base environment passed to every spawned command.
	Env []string

	// DefaultUID is the numeric user ID for spawned processes.
	DefaultUID uint32

	// DefaultGID is the numeric group ID for spawned processes.
	DefaultGID uint32

	// DefaultUser is the username reported to the shell.
	DefaultUser string

	// DefaultHome is the home directory for spawned processes.
	DefaultHome string

	// DefaultShell is the login shell binary (e.g. "/bin/sh").
	DefaultShell string

	// DefaultWorkDir is the working directory for spawned commands. If
	// empty or the directory does not exist, DefaultHome is used instead.
	DefaultWorkDir string

	// AgentForwarding enables SSH agent forwarding support. When true,
	// the server accepts auth-agent-req@openssh.com requests and creates
	// per-session agent sockets.
	AgentForwarding bool

	// AllowTCPForwarding enables client-initiated "direct-tcpip" channels
	// (ssh -L / -D). When true, the server dials the requested host:port
	// from inside the guest and pipes the channel. Tools like VS Code
	// Remote-SSH require this to reach their in-guest server over a
	// dynamic SOCKS forward. Default false: non-session channels are
	// rejected, preserving the shell/exec-only posture.
	AllowTCPForwarding bool

	// HostKey is an optional pre-generated host key signer. When non-nil,
	// the server uses this key instead of generating an ephemeral one.
	// This enables host key pinning by the client.
	HostKey ssh.Signer

	// Logger is the structured logger. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Server is an embedded SSH server designed to run inside a guest VM.
type Server struct {
	cfg        Config
	sshCfg     *ssh.ServerConfig
	listener   net.Listener
	wg         sync.WaitGroup
	quit       chan struct{}
	logger     *slog.Logger
	agentFwdMu sync.Mutex
	agentFwd   map[*ssh.ServerConn]bool
}

// New creates a new Server with an ephemeral ECDSA P-256 host key. It
// configures public-key authentication against the supplied authorized
// keys and allows at most one authentication attempt per connection.
func New(cfg Config) (*Server, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	sshCfg := &ssh.ServerConfig{
		MaxAuthTries: 1,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			for _, ak := range cfg.AuthorizedKeys {
				if ak.Type() == key.Type() &&
					subtle.ConstantTimeCompare(ak.Marshal(), key.Marshal()) == 1 {
					logger.Info("public key accepted",
						"user", conn.User(),
						"remote", conn.RemoteAddr(),
					)
					return &ssh.Permissions{}, nil
				}
			}
			logger.Warn("public key rejected",
				"user", conn.User(),
				"remote", conn.RemoteAddr(),
			)
			return nil, fmt.Errorf("unknown public key for %s", conn.User())
		},
	}

	if cfg.HostKey != nil {
		// Use the injected host key (enables client-side pinning).
		sshCfg.AddHostKey(cfg.HostKey)
	} else {
		// Generate an ephemeral ECDSA P-256 host key.
		hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate host key: %w", err)
		}

		signer, err := ssh.NewSignerFromKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("create host key signer: %w", err)
		}

		sshCfg.AddHostKey(signer)
	}

	return &Server{
		cfg:      cfg,
		sshCfg:   sshCfg,
		quit:     make(chan struct{}),
		logger:   logger,
		agentFwd: make(map[*ssh.ServerConn]bool),
	}, nil
}

// Port returns the actual port the server is listening on. This is
// especially useful when the server was started with port 0.
func (s *Server) Port() int {
	if s.listener == nil {
		return s.cfg.Port
	}
	return s.listener.Addr().(*net.TCPAddr).Port
}

// ListenAndServe opens a TCP listener on the configured port and serves
// SSH connections until Close is called.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", s.cfg.Port, err)
	}

	s.logger.Info("SSH server listening", "addr", ln.Addr().String())
	return s.Serve(ln)
}

// Serve accepts connections on the provided listener. It limits
// concurrent connections to maxConcurrentConns via a semaphore.
func (s *Server) Serve(ln net.Listener) error {
	s.listener = ln
	sem := make(chan struct{}, maxConcurrentConns)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil
			default:
				s.logger.Error("accept failed", "error", err)
				continue
			}
		}

		sem <- struct{}{}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-sem }()
			s.handleConnection(conn)
		}()
	}
}

// Close gracefully shuts down the server by closing the listener and
// waiting for active connections to finish.
func (s *Server) Close() {
	close(s.quit)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
}

// handleConnection performs the SSH handshake and dispatches session
// channels. It enforces a handshake deadline and limits the number of
// channels per connection.
func (s *Server) handleConnection(netConn net.Conn) {
	defer func() { _ = netConn.Close() }()

	// Enforce a handshake deadline.
	if err := netConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.logger.Error("set handshake deadline", "error", err)
		return
	}

	srvConn, chans, reqs, err := ssh.NewServerConn(netConn, s.sshCfg)
	if err != nil {
		s.logger.Debug("SSH handshake failed",
			"remote", netConn.RemoteAddr(),
			"error", err,
		)
		return
	}
	defer func() { _ = srvConn.Close() }()
	defer s.setAgentForwarding(srvConn, false)

	// Clear the deadline after a successful handshake.
	if err := netConn.SetDeadline(time.Time{}); err != nil {
		s.logger.Error("clear deadline", "error", err)
		return
	}

	s.logger.Info("SSH connection established",
		"user", srvConn.User(),
		"remote", srvConn.RemoteAddr(),
	)

	// Handle global requests (agent forwarding, keepalive, etc.).
	go s.handleGlobalRequests(reqs, srvConn)

	channelCount := 0
	for newCh := range chans {
		chanType := newCh.ChannelType()
		if chanType == "direct-tcpip" && s.cfg.AllowTCPForwarding {
			channelCount++
			if channelCount > maxChannelsPerConn {
				s.logger.Warn("too many channels, rejecting", "count", channelCount)
				_ = newCh.Reject(ssh.ResourceShortage, "too many channels")
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleDirectTCPIP(newCh)
			}()
			continue
		}
		if chanType != "session" {
			s.logger.Warn("rejecting non-session channel",
				"type", chanType,
			)
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		channelCount++
		if channelCount > maxChannelsPerConn {
			s.logger.Warn("too many channels, rejecting",
				"count", channelCount,
			)
			_ = newCh.Reject(ssh.ResourceShortage, "too many channels")
			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			s.logger.Error("accept channel", "error", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSession(ch, requests, srvConn)
		}()
	}
}

// directTCPIPExtra is the RFC 4254 §7.2 "direct-tcpip" channel-open payload.
type directTCPIPExtra struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// handleDirectTCPIP services a client-initiated "direct-tcpip" channel by
// dialing the requested destination from inside the guest and piping bytes
// bidirectionally. Only reachable when AllowTCPForwarding is set. The dial
// target is whatever the guest itself can reach (loopback services plus any
// gateway-proxied egress); this grants the SSH client no route the guest
// shell does not already have.
func (s *Server) handleDirectTCPIP(newCh ssh.NewChannel) {
	var req directTCPIPExtra
	if err := ssh.Unmarshal(newCh.ExtraData(), &req); err != nil {
		s.logger.Warn("bad direct-tcpip payload", "error", err)
		_ = newCh.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
		return
	}
	dest := net.JoinHostPort(req.DestAddr, fmt.Sprintf("%d", req.DestPort))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", dest)
	if err != nil {
		s.logger.Warn("direct-tcpip dial failed", "dest", dest, "error", err)
		_ = newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("dial %s: %v", dest, err))
		return
	}
	defer func() { _ = conn.Close() }()

	ch, reqs, err := newCh.Accept()
	if err != nil {
		s.logger.Error("accept direct-tcpip channel", "error", err)
		return
	}
	defer func() { _ = ch.Close() }()
	go ssh.DiscardRequests(reqs)

	s.logger.Debug("direct-tcpip forwarding", "dest", dest)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ch, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, ch); done <- struct{}{} }()
	<-done
	// Unblock the peer copy: closing both ends (deferred) makes the second
	// io.Copy return so its goroutine exits and the WaitGroup can drain.
}

// handleGlobalRequests processes connection-level SSH requests.
// It rejects all global requests; session-specific requests like
// agent forwarding are handled in handleSession.
func (s *Server) handleGlobalRequests(reqs <-chan *ssh.Request, _ *ssh.ServerConn) {
	for req := range reqs {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// setAgentForwarding records or clears the agent-forwarding state for
// the given connection.
func (s *Server) setAgentForwarding(conn *ssh.ServerConn, enabled bool) {
	s.agentFwdMu.Lock()
	defer s.agentFwdMu.Unlock()
	if enabled {
		s.agentFwd[conn] = true
	} else {
		delete(s.agentFwd, conn)
	}
}

// isAgentForwarding reports whether agent forwarding has been enabled
// for the given connection.
func (s *Server) isAgentForwarding(conn *ssh.ServerConn) bool {
	s.agentFwdMu.Lock()
	defer s.agentFwdMu.Unlock()
	return s.agentFwd[conn]
}
