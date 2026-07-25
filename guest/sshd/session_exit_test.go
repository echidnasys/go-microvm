// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"os/exec"
	"testing"
)

// A signal-killed command must map to the shell convention 128+signum:
// ExitCode() returns -1 for signal deaths, and sending that as the SSH
// exit-status uint32 shows clients a meaningless 4294967295 (live finding:
// an OOM-killed agent surfaced as "Process exited with status 4294967295").
func TestExitCode_SignaledProcess(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         int
	}{
		{"sigterm", "kill -TERM $$", 143},
		{"sigkill", "kill -KILL $$", 137},
		{"plain exit", "exit 7", 7},
		{"success", "exit 0", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := exec.Command("/bin/sh", "-c", tc.script).Run()
			if got := exitCode(err); got != tc.want {
				t.Errorf("exitCode(%q) = %d, want %d", tc.script, got, tc.want)
			}
		})
	}
}
