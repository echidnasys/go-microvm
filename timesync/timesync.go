// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package timesync

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultInterval is how often the guest clock is checked. Timers that
	// come due while the host sleeps fire immediately on wake, so this
	// interval also bounds how quickly post-sleep skew is corrected.
	DefaultInterval = 60 * time.Second

	// DefaultThreshold is the smallest absolute skew that triggers a step.
	// Guest time is read at whole-second granularity, so anything below
	// 2s is indistinguishable from measurement noise.
	DefaultThreshold = 2 * time.Second
)

// GuestRunner executes commands in the guest. *ssh.Client satisfies it.
type GuestRunner interface {
	Run(ctx context.Context, cmd string) (string, error)
	RunSudo(ctx context.Context, cmd string) (string, error)
}

// Result reports the outcome of a single sync check.
type Result struct {
	// Skew is guest time minus host time; negative means the guest clock
	// is behind (the usual case after the host sleeps).
	Skew time.Duration
	// Stepped is true when the guest clock was set to host time.
	Stepped bool
}

// Syncer periodically measures guest wall-clock skew against the host and
// steps the guest clock when it drifts beyond a threshold. Stepping uses
// date(1), which busybox implements via clock_settime — the one time-setting
// syscall the guest seccomp policy permits (settimeofday and clock_adjtime
// are blocked, so slewing daemons like chrony cannot run in the guest).
type Syncer struct {
	runner    GuestRunner
	interval  time.Duration
	threshold time.Duration

	// now returns host wall-clock time. Overridable in tests.
	now func() time.Time
}

// Option configures a Syncer.
type Option func(*Syncer)

// WithInterval sets how often Run checks the guest clock.
func WithInterval(d time.Duration) Option {
	return func(s *Syncer) { s.interval = d }
}

// WithThreshold sets the minimum absolute skew that triggers a step.
func WithThreshold(d time.Duration) Option {
	return func(s *Syncer) { s.threshold = d }
}

// New creates a Syncer that corrects the guest reachable via runner.
func New(runner GuestRunner, opts ...Option) *Syncer {
	s := &Syncer{
		runner:    runner,
		interval:  DefaultInterval,
		threshold: DefaultThreshold,
		now:       time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// SyncOnce measures the guest clock and steps it to host time if the skew
// exceeds the threshold.
func (s *Syncer) SyncOnce(ctx context.Context) (Result, error) {
	out, err := s.runner.Run(ctx, "date -u +%s")
	if err != nil {
		return Result{}, fmt.Errorf("read guest time: %w", err)
	}
	guestEpoch, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return Result{}, fmt.Errorf("parse guest time %q: %w", strings.TrimSpace(out), err)
	}

	res := Result{Skew: time.Duration(guestEpoch-s.now().Unix()) * time.Second}
	if res.Skew.Abs() < s.threshold {
		return res, nil
	}

	if _, err := s.runner.RunSudo(ctx, fmt.Sprintf("date -u -s @%d", s.now().Unix())); err != nil {
		return res, fmt.Errorf("step guest clock: %w", err)
	}
	res.Stepped = true
	return res, nil
}

// Run syncs immediately, then on every interval tick until ctx is done,
// returning ctx.Err(). Individual sync failures are logged and retried on
// the next tick — a transient SSH failure must not end clock keeping.
func (s *Syncer) Run(ctx context.Context) error {
	s.syncAndLog(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.syncAndLog(ctx)
		}
	}
}

func (s *Syncer) syncAndLog(ctx context.Context) {
	res, err := s.SyncOnce(ctx)
	switch {
	case err != nil:
		slog.Warn("guest time sync failed", "error", err)
	case res.Stepped:
		slog.Info("stepped guest clock", "skew", res.Skew)
	}
}
