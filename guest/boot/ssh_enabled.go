// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !nosshd

package boot

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/stacklok/go-microvm/guest/sshd"
)

// bringUpSSH performs the SSH-specific portion of the boot sequence:
// parses authorized_keys, loads an injected host key if present, and
// starts the embedded SSH server listener. Returns a shutdown closure
// that stops the server.
//
// When [WithoutSSH] has set cfg.disableSSH, this function is a no-op
// returning a no-op shutdown — the caller can still build with -tags=sshd
// and run with SSH off at runtime.
//
// Compiled into the binary by default. Pass -tags=nosshd at build time
// to link the [ssh_disabled.go] stub instead, which keeps
// golang.org/x/crypto/ssh out of the dependency graph.
func bringUpSSH(logger *slog.Logger, cfg *config, envVars []string) (func(), error) {
	if cfg.disableSSH {
		logger.Info("SSH bring-up disabled via WithoutSSH")
		return func() {}, nil
	}

	authorizedKeys, err := ParseAuthorizedKeys(cfg.sshKeysPath)
	if err != nil {
		return nil, fmt.Errorf("parsing authorized keys: %w", err)
	}

	// Load injected host key (if present). The key is deleted from disk
	// after loading into memory so it cannot be read by the sandbox user.
	// If the file does not exist, hostKeySigner remains nil and the SSH
	// server will generate an ephemeral key.
	var hostKeySigner ssh.Signer
	if hostKeyPEM, readErr := os.ReadFile(cfg.sshHostKeyPath); readErr == nil {
		signer, parseErr := ssh.ParsePrivateKey(hostKeyPEM)
		if parseErr != nil {
			logger.Warn("failed to parse injected host key, falling back to ephemeral",
				"path", cfg.sshHostKeyPath, "error", parseErr)
		} else {
			hostKeySigner = signer
			logger.Info("loaded injected SSH host key", "path", cfg.sshHostKeyPath)
		}
		_ = os.Remove(cfg.sshHostKeyPath)
	}

	sshdCfg := sshd.Config{
		Port:            cfg.sshPort,
		AuthorizedKeys:  authorizedKeys,
		Env:             envVars,
		DefaultUID:      cfg.userUID,
		DefaultGID:      cfg.userGID,
		DefaultUser:     cfg.userName,
		DefaultHome:     cfg.userHome,
		DefaultShell:    cfg.userShell,
		DefaultWorkDir:  cfg.workspaceMountPoint,
		AgentForwarding: cfg.sshAgentForwarding,
		HostKey:         hostKeySigner,
		Logger:          logger,
	}
	srv, err := sshd.New(sshdCfg)
	if err != nil {
		return nil, fmt.Errorf("creating SSH server: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.sshPort))
	if err != nil {
		return nil, fmt.Errorf("listening on port %d: %w", cfg.sshPort, err)
	}

	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Error("SSH server error", "error", err)
		}
	}()

	logger.Info("SSH server listening", "port", cfg.sshPort)
	return func() { srv.Close() }, nil
}

// ParseAuthorizedKeys reads an authorized_keys file and returns the parsed
// public keys. Returns an error if no valid keys are found.
//
// Not available in -tags=nosshd builds (which exclude this file from
// the dependency graph).
func ParseAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var keys []ssh.PublicKey
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue // skip unparseable lines
		}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in %s", path)
	}
	return keys, nil
}
