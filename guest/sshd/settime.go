// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/stacklok/go-microvm/timesync"
)

// handleSettime intercepts the reserved timesync.SetTimeCommand exec command
// and steps the system clock in-process. It returns true when the command was
// a settime request (well-formed or not), in which case the session is
// finished and no shell must be spawned. Guest images ship no doas/sudo and
// session shells run privilege-dropped, so this in-process path (the server
// runs as root) is what lets the host correct guest clock skew.
func (s *Server) handleSettime(ch ssh.Channel, command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 || fields[0] != timesync.SetTimeCommand {
		return false
	}

	fail := func(msg string) {
		_, _ = fmt.Fprintln(ch.Stderr(), msg)
		sendExitStatus(ch, 1)
	}

	if len(fields) != 2 {
		fail(fmt.Sprintf("usage: %s <epoch-seconds>", timesync.SetTimeCommand))
		return true
	}
	epoch, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || epoch < 0 {
		fail(fmt.Sprintf("invalid epoch %q", fields[1]))
		return true
	}

	if err := s.settime(epoch); err != nil {
		s.logger.Error("settime failed", "epoch", epoch, "error", err)
		fail(fmt.Sprintf("settime: %v", err))
		return true
	}
	s.logger.Info("system clock stepped", "epoch", epoch)
	sendExitStatus(ch, 0)
	return true
}

// setSystemClock steps the wall clock via clock_settime(CLOCK_REALTIME) —
// the one time-setting syscall the guest seccomp policy permits
// (settimeofday and clock_adjtime are blocked).
func setSystemClock(epochSeconds int64) error {
	ts := unix.Timespec{Sec: epochSeconds}
	if err := unix.ClockSettime(unix.CLOCK_REALTIME, &ts); err != nil {
		return fmt.Errorf("clock_settime: %w", err)
	}
	return nil
}
