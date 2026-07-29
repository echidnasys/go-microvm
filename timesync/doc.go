// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package timesync keeps a microVM guest's wall clock aligned with the host.
//
// libkrun guests have no RTC and no host-driven time source: the guest clock
// stops while the host sleeps and nothing corrects it afterward, so skew
// grows with every sleep cycle. In-guest NTP is not an option — default-deny
// egress drops UDP/123 and the guest seccomp policy blocks the adjtime
// syscalls NTP daemons need. This package closes the gap from the host side:
// a Syncer periodically reads the guest clock over an existing command
// channel (typically SSH) and steps it back to host time when it drifts.
package timesync
