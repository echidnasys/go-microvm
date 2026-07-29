// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/stacklok/go-microvm/timesync"
)

// startSettimeTestServer starts an sshd whose settime hook records the epoch
// it receives instead of touching the system clock.
func startSettimeTestServer(t *testing.T, settimeErr error) (addr string, signer ssh.Signer, got *atomic.Int64) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err = ssh.NewSignerFromKey(key)
	require.NoError(t, err)

	srv, err := New(Config{
		Port:           0,
		AuthorizedKeys: []ssh.PublicKey{signer.PublicKey()},
		Env:            []string{"PATH=/usr/bin:/bin"},
		DefaultUID:     uint32(os.Getuid()),
		DefaultGID:     uint32(os.Getgid()),
		DefaultUser:    "testuser",
		DefaultHome:    os.TempDir(),
		DefaultShell:   "/bin/sh",
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	got = &atomic.Int64{}
	srv.settime = func(epoch int64) error {
		got.Store(epoch)
		return settimeErr
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr = ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })

	return addr, signer, got
}

func settimeDial(t *testing.T, addr string, signer ssh.Signer) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		//nolint:gosec // Test code; host key verification not needed.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSettimeCommandHandledInProcess(t *testing.T) {
	t.Parallel()

	addr, signer, got := startSettimeTestServer(t, nil)
	client := settimeDial(t, addr, signer)

	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = session.Run(fmt.Sprintf("%s 1753700000", timesync.SetTimeCommand))
	require.NoError(t, err, "settime exec should exit 0")
	assert.Equal(t, int64(1753700000), got.Load())
}

func TestSettimeCommandRejectsBadArgs(t *testing.T) {
	t.Parallel()

	addr, signer, got := startSettimeTestServer(t, nil)

	for _, cmd := range []string{
		timesync.SetTimeCommand,                    // missing epoch
		timesync.SetTimeCommand + " notanumber",    // non-numeric
		timesync.SetTimeCommand + " 123 extra-arg", // trailing garbage
		timesync.SetTimeCommand + " -5",            // negative epoch
	} {
		session, err := settimeDial(t, addr, signer).NewSession()
		require.NoError(t, err)
		err = session.Run(cmd)
		var exitErr *ssh.ExitError
		require.ErrorAs(t, err, &exitErr, "cmd %q must fail without reaching a shell", cmd)
		assert.Equal(t, 1, exitErr.ExitStatus(), "cmd %q", cmd)
		assert.Equal(t, int64(0), got.Load(), "settime must not be called for %q", cmd)
		_ = session.Close()
	}
}

func TestSettimeCommandReportsFailure(t *testing.T) {
	t.Parallel()

	addr, signer, _ := startSettimeTestServer(t, fmt.Errorf("EPERM"))
	session, err := settimeDial(t, addr, signer).NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = session.Run(timesync.SetTimeCommand + " 1753700000")
	var exitErr *ssh.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitStatus())
}
