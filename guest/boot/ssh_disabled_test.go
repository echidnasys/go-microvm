// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux && nosshd

package boot

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBringUpSSH_DisabledStub_NoOpWhenAcknowledged(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	cfg.disableSSH = true

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	shutdown, err := bringUpSSH(logger, cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	shutdown() // must not panic
}

func TestBringUpSSH_DisabledStub_ErrorsWhenNotAcknowledged(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	// disableSSH left false — caller did NOT call WithoutSSH().

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	shutdown, err := bringUpSSH(logger, cfg, nil)
	require.Error(t, err)
	assert.Nil(t, shutdown)
	assert.True(t, errors.Is(err, ErrSSHNotBuilt),
		"expected ErrSSHNotBuilt, got %v", err)
}
