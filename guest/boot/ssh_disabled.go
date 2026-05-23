// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux && nosshd

package boot

import (
	"errors"
	"log/slog"
)

// ErrSSHNotBuilt is returned by [Run] when the binary was compiled with
// -tags=nosshd and the caller did not opt out of SSH bring-up via
// [WithoutSSH]. Catching it explicitly is useful for consumers that want
// to detect the "SSH stripped at build time but no acknowledgement"
// misconfiguration as a distinct case from a runtime SSH failure.
var ErrSSHNotBuilt = errors.New(
	"guest/boot: SSH support stripped at build time (-tags=nosshd); call WithoutSSH() to acknowledge",
)

// bringUpSSH is the no-SSH stub. Compiled into binaries built with the
// nosshd build tag — see ssh_enabled.go for the default implementation.
//
// When the caller acknowledged the SSH-off path via [WithoutSSH], this is
// a no-op that returns a no-op shutdown. When the caller did NOT call
// [WithoutSSH], it returns [ErrSSHNotBuilt] to fail loud rather than
// silently boot without SSH.
func bringUpSSH(logger *slog.Logger, cfg *config, _ []string) (func(), error) {
	if !cfg.disableSSH {
		return nil, ErrSSHNotBuilt
	}
	logger.Info("SSH bring-up skipped (built with -tags=nosshd)")
	return func() {}, nil
}
