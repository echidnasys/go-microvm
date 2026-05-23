// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !nosshd

package boot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestParseAuthorizedKeys(t *testing.T) {
	t.Parallel()

	t.Run("valid key", func(t *testing.T) {
		t.Parallel()
		_, pubKeyStr := generateTestKey(t)

		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.WriteFile(path, []byte(pubKeyStr+"\n"), 0o600))

		keys, err := ParseAuthorizedKeys(path)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := ParseAuthorizedKeys("/nonexistent/authorized_keys")
		assert.Error(t, err)
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.WriteFile(path, []byte(""), 0o600))

		_, err := ParseAuthorizedKeys(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid keys")
	})

	t.Run("invalid key skipped", func(t *testing.T) {
		t.Parallel()
		_, pubKeyStr := generateTestKey(t)

		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		content := "not-a-valid-key\n" + pubKeyStr + "\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		keys, err := ParseAuthorizedKeys(path)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})

	t.Run("comments skipped", func(t *testing.T) {
		t.Parallel()
		_, pubKeyStr := generateTestKey(t)

		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		content := "# comment\n" + pubKeyStr + "\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		keys, err := ParseAuthorizedKeys(path)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})
}

func TestBringUpSSH_DisabledIsNoOp(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	cfg.disableSSH = true

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	shutdown, err := bringUpSSH(logger, cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	shutdown() // must not panic
}

// generateTestKey creates an ECDSA key pair and returns the signer and
// the authorized_keys-formatted public key string.
func generateTestKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	pubKeyStr := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	return signer, pubKeyStr
}
